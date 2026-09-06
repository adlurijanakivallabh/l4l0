"""The autonomous think→act→observe loop.

Synthesized from real source read across all five reference agents (per the
project's reference-first mandate), not any single one:

- **Repeating-tool-call handling that SKIPS re-execution**, not just an
  advisory nudge — adapted from a reference orchestrator's actual chain-
  execution loop, which detects an identical repeated call, returns a
  corrective response WITHOUT re-running the tool, and hard-aborts the whole
  chain past a higher threshold.
- **A "no tool call" turn gets a corrective nudge and one retry**, rather than
  immediately stopping — adapted from the same reference's "reflector"
  mechanism (which asks the model for guidance instead of silently giving up
  when it responds with prose instead of an action), simplified here to an
  in-loop corrective message rather than a separate sub-agent call.
- **Graduated budget wrap-up directives**, role-differentiated (root vs
  sub-agent), injected into the prompt as thresholds cross — adapted from a
  different reference's actual budget-hook source (see orchestrator/budget.py
  for the full citation and the fail-open gap deliberately avoided there).
- **Optional cooperative cancellation + per-step event callbacks** — adapted
  from a third reference's actual agent-executor source (an abort-signal
  wired into the session, and an event-subscription model separating "drive
  the loop" from "consume progress") so a future GUI can stream live progress
  and a stop button can cleanly interrupt a running loop.
- **Canonical-evidence discipline** (a tool result is real captured text, a
  model's own narrative is not evidence) — independently confirmed by two
  different references' real source under different names (a typed-evidence-
  family philosophy; a literal "canonical exact quotes... noncanonical
  operational feedback" prompt contract) — enforced in prompts/ and
  confirmation/review.py, but the loop is what makes every tool result
  traceable to a real observation in the first place.
- **A reserved final turn beyond max_steps**, dedicated purely to letting the
  model transmit a summary rather than losing everything when the step
  ceiling hits mid-investigation — adapted from a reference's per-task-kind
  turn-budget design, whose own turn_budget field "counts task-work turns;
  the runtime reserves one additional transport turn." This was read (Phase
  5) but not actually adopted at the time; added retroactively after an
  audit flagged the gap between what was read and what was built.

Phase 2, pentagi pass: :mod:`lalo.orchestrator.journal` was built and
independently tested to satisfy the original plan's own Phase 2 acceptance
criterion ("kill-mid-run -> resume replays to the exact next action with no
duplicated side effect"), but nothing ever actually wired it into the live
loop — an agent process killed mid-scan had no path to resume at all, despite
that module's own unit tests passing. Fixed here: ``run`` accepts an optional
``journal``/``agent_key``; on entry it replays every already-completed step
for that key straight into ``transcript`` (and reconstructs ``budget.spent``
to match) without calling the model or dispatching a single tool, then
continues live from the first step that was never journaled. Each new live
dispatch is wrapped in ``journal.run_once`` so a subsequent crash can resume
past it too. Scoped deliberately to ONE agent's own steps, not the whole
spawn tree: a spawned child that was still mid-execution when the crash
happened is not resumed granularly and simply restarts from scratch on the
next ``spawn_agent`` call — matching a different reference's own actual
resume granularity (its coarser task/subtask units are reset to "Created"
and restarted from the top on reload, not resumed mid-unit either), and
avoiding the much larger scope of threading a live journal down through
every spawned descendant for a proportionally small additional benefit.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from ..core.errors import AllProvidersFailedError
from ..core.logging import get_logger
from ..core.model_router import CompletionRequest, CompletionResponse, ModelRouter
from ..core.usage import record_usage
from ..observability import Tracer
from ..orchestrator.budget import (
    Budget,
    BudgetBand,
    BudgetExceededError,
    SubagentReserveExceededError,
)
from ..orchestrator.journal import DurableJournal
from .tools import ToolRegistry, parse_tool_call, str_arg

_log = get_logger("lalo.agent")

_PROTOCOL = (
    "Act ONE STEP AT A TIME. Emit EXACTLY ONE JSON object and then STOP — you will "
    "be given that tool's result before you act again. Do NOT plan or emit multiple "
    "steps at once, and do NOT call finish until you have seen real tool results.\n"
    '  {"tool": "<name>", "args": {...}}\n'
    "When the objective is genuinely met, and only then: "
    '{"tool": "finish", "args": {"summary": "..."}}\n'
    "Emit only the single JSON object, nothing else."
)

_NO_TOOL_CALL_NUDGE = (
    "Your reply did not contain a tool call. Every turn must be exactly one JSON "
    'object: {"tool": "<name>", "args": {...}}. If you believe the objective is '
    'already met, say so via {"tool": "finish", "args": {"summary": "..."}}.'
)

_FINAL_TURN_DIRECTIVE = (
    "FINAL TURN: your step budget is exhausted and no further tool calls will run "
    'after this one. Respond with {"tool": "finish", "args": {"summary": "..."}} '
    "summarizing what you found, what you confirmed, and what remains open — a "
    "partial result now is far more useful than nothing."
)

# Role-differentiated wrap-up directives, worded distinctly for a root agent
# (compiling a final report) vs a sub-agent (reporting back to its parent) —
# adapted in spirit, not text, from a reference's own root-vs-subagent framing.
_ROOT_DIRECTIVES: dict[BudgetBand, str] = {
    BudgetBand.NOTICE: "Budget notice: begin wrapping up — avoid starting large new "
    "lines of investigation so you can finish comfortably before the limit.",
    BudgetBand.URGENT: "Budget urgent: stop opening new lines of investigation. Close "
    "out only what is essential and move toward calling finish.",
    BudgetBand.CRITICAL: "Budget critical: STOP other work and finish immediately — "
    "secure your findings and call finish now. Anything unfinished is discarded.",
}
_SUBAGENT_DIRECTIVES: dict[BudgetBand, str] = {
    BudgetBand.NOTICE: "Budget notice: begin wrapping up this subtask — if you are "
    "close to a confirmed result, drive it to a reportable conclusion.",
    BudgetBand.URGENT: "Budget urgent: report any confirmed result now and avoid "
    "starting anything new; prepare to call finish.",
    BudgetBand.CRITICAL: "Budget critical: report your result right now and call "
    "finish — you may be cut off before your parent receives anything else.",
}


@dataclass
class AgentConfig:
    role: str = "reasoning"
    max_steps: int = 25
    max_observation_chars: int = 4000
    is_root: bool = True
    # A tool call identical to the previous one this many times in a row is
    # skipped (not re-executed) with a corrective nudge instead.
    repeat_soft_threshold: int = 3
    # ...and beyond this many identical repeats in a row, the chain aborts.
    repeat_abort_threshold: int = 6
    # A turn with no parseable tool call gets this many corrective retries
    # before the loop gives up.
    max_no_tool_call_retries: int = 2

    def __post_init__(self) -> None:
        # A reference agent's own turn-budget constructor validates a minimum
        # boundary for exactly this reason ("must reserve at least one task
        # turn and one result turn") — here, repeat_count is seeded at 1 for a
        # brand-new signature, so repeat_soft_threshold < 2 would treat a
        # tool's genuinely first-ever call as already repeated and never
        # dispatch it at all.
        if self.max_steps < 1:
            raise ValueError("max_steps must be >= 1")
        if self.repeat_soft_threshold < 2:
            raise ValueError("repeat_soft_threshold must be >= 2")
        if self.repeat_abort_threshold <= self.repeat_soft_threshold:
            raise ValueError("repeat_abort_threshold must be > repeat_soft_threshold")
        if self.max_no_tool_call_retries < 0:
            raise ValueError("max_no_tool_call_retries must be >= 0")


@dataclass
class AgentResult:
    stop_reason: str
    steps: int
    transcript: list[dict[str, object]] = field(default_factory=list)
    summary: str = ""


def _call_signature(name: str, args: dict[str, object]) -> str:
    return name + "|" + json.dumps(args, sort_keys=True, default=str)


def _truncate_observation(text: str, max_chars: int) -> str:
    """Cap ``text`` at ``max_chars``, keeping head AND tail with a clear marker.

    Phase 6, cai pass: informed by a reference agent's own worker-output
    truncation (read in full — ``_truncate_worker_output``), adopted here at
    the one place every tool observation, spawned-child summaries included,
    already funnels through. A naive ``text[:max_chars]`` head-only slice (the
    prior behavior) does two things wrong at once: it discards exactly the
    part of a long observation most likely to carry the actual conclusion (a
    child agent's closing verdict, a scan tool's final result line tends to
    come last, not first), and it gives the model no signal that anything was
    cut at all — a truncated observation and a genuinely short one were
    indistinguishable.
    """
    if len(text) <= max_chars:
        return text
    half = max_chars // 2
    if half <= 0:
        return f"[...truncated {len(text)} chars...]"
    dropped = len(text) - 2 * half
    return f"{text[:half]}\n\n[...truncated {dropped} chars...]\n\n{text[-half:]}"


class AgentLoop:
    def __init__(
        self,
        router: ModelRouter,
        registry: ToolRegistry,
        *,
        system_prompt: str,
        config: AgentConfig | None = None,
        tracer: Tracer | None = None,
        budget: Budget | None = None,
        on_event: Callable[[str, dict[str, object]], None] | None = None,
        should_stop: Callable[[], bool] | None = None,
        usage_path: Path | None = None,
        agent_id: str | None = None,
    ) -> None:
        self.router = router
        self.registry = registry
        self.system_prompt = system_prompt
        self.config = config or AgentConfig()
        # A fresh Tracer per loop instance, never the process-wide default —
        # that singleton's spans/counters only ever accumulate with no reset,
        # so every AgentLoop that didn't pass its own tracer would otherwise
        # silently share (and contaminate) one process-lifetime timeline.
        self.tracer = tracer or Tracer()
        self.budget = budget
        self.on_event = on_event
        self.should_stop = should_stop
        # None (the default) means "don't record" -- every existing caller
        # that doesn't opt in stays hermetic (no write to the real lifetime
        # usage log). See _complete()'s own note for why this was dead code
        # before this fix despite being fully built and tested in isolation.
        self.usage_path = usage_path
        # This loop's own identity (the root agent, or a spawned child) for
        # UsageStats.by_agent - None is a legitimate value here too, meaning
        # "record lifetime/by_provider totals but attribute nothing to a
        # specific agent."
        self.agent_id = agent_id

    def _emit(self, event: str, payload: dict[str, object]) -> None:
        if self.on_event is not None:
            self.on_event(event, payload)

    def _complete(self, prompt: str) -> CompletionResponse | None:
        """Call the router; classify a total provider failure instead of
        letting it crash the run uncaught. Mirrors a reference agent
        executor's own result shape (a `retryable` classification returned to
        an OUTER orchestrator) rather than retrying internally — ModelRouter
        has already exhausted its own failover chain by the time
        AllProvidersFailedError reaches here, so there is nothing left to
        retry at this layer; a future orchestrator decides what to do next.

        Phase 2, strix pass (closes Phase 2): :func:`~lalo.core.usage.
        record_usage` was built and unit-tested in the Phase 0 cai pass to
        close a real gap ("an autonomous run's actual dollar cost is
        invisible") but, like the durable journal earlier in this phase,
        nothing ever actually called it from the live loop -- every real
        completion's token usage was silently discarded. Recording happens
        HERE (not per-role, not per-agent) since this is the one place every
        real completion response, root or child, already passes through.
        ``usage_path`` defaults to ``None`` (recording off) so every existing
        caller that doesn't opt in stays hermetic; :class:`~lalo.scan.
        ScanRunner` opts in for a real run. Never allowed to affect the
        agent's own control flow: a usage-recording failure (a disk error, a
        future cost-limit raise) is logged and swallowed, not propagated --
        this is a best-effort side observation, not a correctness path.
        """
        try:
            response = self.router.complete(
                self.config.role, CompletionRequest(prompt=prompt, system=self.system_prompt)
            )
        except AllProvidersFailedError:
            return None
        if self.usage_path is not None:
            try:
                record_usage(response, path=self.usage_path, agent_id=self.agent_id)
            except Exception:
                _log.exception("usage recording failed; continuing without it")
        return response

    def _render_prompt(
        self, mission: str, transcript: list[dict[str, object]], directive: str | None
    ) -> str:
        parts = [
            f"MISSION:\n{mission}",
            f"\nAVAILABLE TOOLS:\n{self.registry.describe()}",
            f"\n{_PROTOCOL}",
        ]
        if directive:
            parts.append(f"\n[{directive}]")
        if transcript:
            parts.append("\nHISTORY (most recent last):")
            for entry in transcript[-12:]:
                parts.append(f"  called {entry['tool']}({entry['args']}) -> {entry['observation']}")
        parts.append("\nWhat is your next action? Reply with one JSON tool call.")
        return "\n".join(parts)

    def _budget_directive(self) -> str | None:
        if self.budget is None:
            return None
        band = self.budget.band(is_root=self.config.is_root)
        if band in (BudgetBand.OK, BudgetBand.EXHAUSTED):
            return None
        table = _ROOT_DIRECTIVES if self.config.is_root else _SUBAGENT_DIRECTIVES
        return table[band]

    def _check_budget_ceiling(self) -> str | None:
        """Return a stop_reason if the hard ceiling was just reached, else None."""
        if self.budget is None:
            return None
        try:
            if self.config.is_root:
                self.budget.check_root()
            else:
                self.budget.check_subagent()
        except BudgetExceededError:
            return "budget_exhausted"
        except SubagentReserveExceededError:
            return "subagent_reserve_exhausted"
        return None

    def run(
        self,
        mission: str,
        *,
        journal: DurableJournal | None = None,
        agent_key: str = "root",
    ) -> AgentResult:
        transcript: list[dict[str, object]] = []
        last_signature: str | None = None
        repeat_count = 0
        no_tool_call_retries = 0

        start_step = 0
        if journal is not None:
            # Replay already-completed steps for this key with no model call
            # and no re-dispatch -- this is the actual resume, not just a log.
            while journal.has(f"{agent_key}:{start_step}"):
                entry = journal.get(f"{agent_key}:{start_step}")
                transcript.append(
                    {
                        "tool": entry["tool"],
                        "args": entry["args"],
                        "observation": entry["observation"],
                    }
                )
                if self.budget is not None:
                    self.budget.spend(1)
                start_step += 1
            if start_step:
                self._emit("resumed", {"replayed_steps": start_step})

        for step in range(start_step, self.config.max_steps):
            if self.should_stop is not None and self.should_stop():
                return AgentResult("cancelled", step, transcript)

            stop_reason = self._check_budget_ceiling()
            if stop_reason is not None:
                self._emit("budget_exhausted", {"step": step})
                return AgentResult(stop_reason, step, transcript)

            with self.tracer.span("agent_step", step=step):
                directive = self._budget_directive()
                prompt = self._render_prompt(mission, transcript, directive)
                response = self._complete(prompt)
                if response is None:
                    self._emit("provider_failed", {"step": step})
                    return AgentResult("provider_failed", step, transcript)
                call = parse_tool_call(response.text)

                if call is None:
                    no_tool_call_retries += 1
                    if no_tool_call_retries > self.config.max_no_tool_call_retries:
                        _log.info("agent produced no tool call after retries; stopping")
                        return AgentResult(
                            "no_tool_call", step + 1, transcript, summary=response.text
                        )
                    transcript.append(
                        {"tool": "_nudge", "args": {}, "observation": _NO_TOOL_CALL_NUDGE}
                    )
                    continue
                no_tool_call_retries = 0

                if call.name == "finish":
                    self._emit("finished", {"step": step})
                    return AgentResult(
                        "finished", step + 1, transcript, summary=str_arg(call.args, "summary")
                    )

                signature = _call_signature(call.name, call.args)
                if signature == last_signature:
                    repeat_count += 1
                else:
                    repeat_count = 1
                    last_signature = signature

                if repeat_count >= self.config.repeat_abort_threshold:
                    self._emit("repeating_tool_call_aborted", {"tool": call.name})
                    return AgentResult("repeating_tool_call_aborted", step + 1, transcript)

                if repeat_count >= self.config.repeat_soft_threshold:
                    # Skip re-execution — do not repeat a side effect the model
                    # is stuck looping on; nudge it toward a different approach.
                    observation = (
                        f"tool call '{call.name}' repeated {repeat_count} times with "
                        "identical arguments; try a different approach or target"
                    )
                    ok = False
                else:
                    self._emit("tool_call", {"tool": call.name, "args": call.args})
                    tool_name, tool_args = call.name, call.args

                    def _dispatch_once(
                        _name: str = tool_name, _args: dict[str, object] = tool_args
                    ) -> dict[str, object]:
                        result = self.registry.dispatch(_name, _args)
                        return {
                            "tool": _name,
                            "args": _args,
                            "observation": _truncate_observation(
                                result.observation, self.config.max_observation_chars
                            ),
                            "ok": result.ok,
                        }

                    if journal is not None:
                        entry = journal.run_once(f"{agent_key}:{step}", _dispatch_once)
                    else:
                        entry = _dispatch_once()
                    observation = str(entry["observation"])
                    ok = bool(entry["ok"])
                    self._emit("tool_result", {"tool": call.name, "ok": ok})

                transcript.append(
                    {"tool": call.name, "args": call.args, "observation": observation}
                )
                self.tracer.counter("tool_calls")
                if self.budget is not None:
                    self.budget.spend(1)

        return self._final_turn(mission, transcript)

    def _final_turn(self, mission: str, transcript: list[dict[str, object]]) -> AgentResult:
        """One guaranteed extra turn beyond max_steps, reserved purely for the
        model to transmit a summary — it may not call any other tool here. A
        non-compliant response (no tool call, or anything but finish) just
        falls back to the plain max_steps outcome rather than looping further."""
        prompt = self._render_prompt(mission, transcript, _FINAL_TURN_DIRECTIVE)
        response = self._complete(prompt)
        if response is None:
            return AgentResult("max_steps", self.config.max_steps, transcript)
        call = parse_tool_call(response.text)
        if call is not None and call.name == "finish":
            summary = str_arg(call.args, "summary")
            self._emit("finished", {"step": self.config.max_steps, "reserved_turn": True})
            return AgentResult(
                "max_steps_reserved_turn", self.config.max_steps, transcript, summary=summary
            )
        return AgentResult("max_steps", self.config.max_steps, transcript)
