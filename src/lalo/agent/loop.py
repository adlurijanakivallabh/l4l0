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
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass, field

from ..core.logging import get_logger
from ..core.model_router import CompletionRequest, ModelRouter
from ..observability import Tracer, get_tracer
from ..orchestrator.budget import (
    Budget,
    BudgetBand,
    BudgetExceededError,
    SubagentReserveExceededError,
)
from .tools import ToolRegistry, parse_tool_call

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


@dataclass
class AgentResult:
    stop_reason: str
    steps: int
    transcript: list[dict[str, object]] = field(default_factory=list)
    summary: str = ""


def _call_signature(name: str, args: dict[str, object]) -> str:
    return name + "|" + json.dumps(args, sort_keys=True, default=str)


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
    ) -> None:
        self.router = router
        self.registry = registry
        self.system_prompt = system_prompt
        self.config = config or AgentConfig()
        self.tracer = tracer or get_tracer()
        self.budget = budget
        self.on_event = on_event
        self.should_stop = should_stop

    def _emit(self, event: str, payload: dict[str, object]) -> None:
        if self.on_event is not None:
            self.on_event(event, payload)

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

    def run(self, mission: str) -> AgentResult:
        transcript: list[dict[str, object]] = []
        last_signature: str | None = None
        repeat_count = 0
        no_tool_call_retries = 0

        for step in range(self.config.max_steps):
            if self.should_stop is not None and self.should_stop():
                return AgentResult("cancelled", step, transcript)

            stop_reason = self._check_budget_ceiling()
            if stop_reason is not None:
                self._emit("budget_exhausted", {"step": step})
                return AgentResult(stop_reason, step, transcript)

            with self.tracer.span("agent_step", step=step):
                directive = self._budget_directive()
                prompt = self._render_prompt(mission, transcript, directive)
                response = self.router.complete(
                    self.config.role, CompletionRequest(prompt=prompt, system=self.system_prompt)
                )
                call = parse_tool_call(response.text)

                if call is None:
                    no_tool_call_retries += 1
                    if no_tool_call_retries > self.config.max_no_tool_call_retries:
                        _log.info("agent produced no tool call after retries; stopping")
                        return AgentResult("no_tool_call", step, transcript, summary=response.text)
                    transcript.append(
                        {"tool": "_nudge", "args": {}, "observation": _NO_TOOL_CALL_NUDGE}
                    )
                    continue
                no_tool_call_retries = 0

                if call.name == "finish":
                    self._emit("finished", {"step": step})
                    return AgentResult(
                        "finished", step, transcript, summary=str(call.args.get("summary", ""))
                    )

                signature = _call_signature(call.name, call.args)
                if signature == last_signature:
                    repeat_count += 1
                else:
                    repeat_count = 1
                    last_signature = signature

                if repeat_count >= self.config.repeat_abort_threshold:
                    self._emit("repeating_tool_call_aborted", {"tool": call.name})
                    return AgentResult("repeating_tool_call_aborted", step, transcript)

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
                    result = self.registry.dispatch(call.name, call.args)
                    observation = result.observation[: self.config.max_observation_chars]
                    ok = result.ok
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
        response = self.router.complete(
            self.config.role, CompletionRequest(prompt=prompt, system=self.system_prompt)
        )
        call = parse_tool_call(response.text)
        if call is not None and call.name == "finish":
            summary = str(call.args.get("summary", ""))
            self._emit("finished", {"step": self.config.max_steps, "reserved_turn": True})
            return AgentResult(
                "max_steps_reserved_turn", self.config.max_steps, transcript, summary=summary
            )
        return AgentResult("max_steps", self.config.max_steps, transcript)
