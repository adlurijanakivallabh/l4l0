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

Phase 2, a studied reference agent's own pass: :mod:`lalo.orchestrator.journal` was built and
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
past it too. Originally scoped deliberately to ONE agent's own steps, not the
whole spawn tree: a spawned child that was still mid-execution when the crash
happened was not resumed granularly and simply restarted from scratch on the
next ``spawn_agent`` call — matching a different reference's own actual
resume granularity (its coarser task/subtask units are reset to "Created"
and restarted from the top on reload, not resumed mid-unit either), and
avoiding what looked at the time like the much larger scope of threading a
live journal down through every spawned descendant for a proportionally
small additional benefit.

That scope turned out to be small after all, though not in the way "durably
resumable child steps" first suggests: :mod:`lalo.scan` now also wires every
spawned child's own ``child_loop.run()`` call with ``journal=``/
``agent_key=child_id`` (sharing this same journal instance), which durably
records a completed child's own steps in the shared journal file alongside
the root's, under its own namespace. But since ``_run_child`` runs a whole
spawn — dispatch, run to completion, graph merge — synchronously inside ONE
of the root's own ``journal.run_once`` calls, a child that was still
genuinely mid-execution when the crash happened is never resumed granularly
either: the root's own not-yet-completed spawn step simply re-runs in full
on resume, which spawns a brand-new child under a fresh id and redoes that
task from scratch, discarding whatever the abandoned child had already done.
The real, load-bearing benefit is narrower and still genuine: a child that
DID run to completion before an unrelated LATER crash needs no resume at
all (its result is already part of the root's own replayed history), and
the reseeding fix below is what stops a fresh id minted after resume from
colliding with that completed child's own already-journaled one. Nothing
above needed to change for the per-child journaling itself — ``agent_key``
was already an opaque per-caller namespace, never special-cased for "root"
— only the one call site in ``scan.py`` that constructs each child's
``AgentLoop`` did. The
one thing that DID need new work belongs to the coordinator that mints
child ids, not this loop: a resumed process's id counter starts fresh with
no memory of ids a crashed attempt's replayed-not-respawned steps already
used, so it must be reseeded past the journal's own already-recorded
``agent-N:...`` keys before any live dispatch can spawn again — otherwise a
genuinely new child could be minted a stale, already-used id and its own
resume-replay would splice an unrelated prior child's history into a
brand-new task.

A live-scan comparison against a reference agent surfaced a real,
previously dead-on-arrival wire: the GUI's own ``POST /steer`` endpoint
(``gui/app.py``) already appended every operator steering message to the
run's ``EventLog`` — its own module docstring even said "a human OR AGENT
may later read" it — but nothing anywhere ever actually read one back into
a running loop. An operator typing "focus on the API endpoints" mid-scan
had zero effect on the agent, only a cosmetic line in the GUI's own
console. ``get_steering`` (optional, ``None`` by default) closes that:
:meth:`_render_prompt` renders every steering message received so far as
its own labeled section, read alongside the mission, on every turn for as
long as the run continues — a persistence choice deliberate versus a
show-once-then-drop design, since "focus on API areas" is meant to shift
priority for the REST of the mission, not just the very next step. This
never expands what the agent can do or touches the confirmation-authority
boundary — it only ever influences what the agent chooses to prioritize
within its own ordinary think-act-observe loop, the same read-only design
the steering endpoint itself already established.

A follow-up audit of that same live comparison found what looked like a gap
in :mod:`lalo.core.redaction`'s own stated design ("every subsystem that
renders text... routes through" the shared redactor): true for logging and
for a submitted finding's own fields, but not for this loop — a tool
observation went straight from ``registry.dispatch`` into ``transcript``,
with no call to ``redact()`` anywhere on that path. A fix was shipped
routing ``_dispatch_once``'s observation through ``redact()`` before
``_truncate_observation`` — and then reverted, here, after a real live
autonomous run against a live target proved it was wrong, not merely
incomplete.

**Reverted, with the evidence that forced it:** ``identity/tool.py``'s
``login_as`` registers a freshly captured session value with the shared
redactor specifically so it never leaks into a LOG line — its own comment
says so explicitly: "the agent's own captured credential to actively reuse
in subsequent ``http`` calls, not a third-party secret to withhold from
it." Routing tool observations through the SAME shared redactor's
``redact()`` before they reach the transcript broke exactly that: the
session value ``login_as`` deliberately returns for reuse got replaced with
the redaction placeholder before the agent ever saw it again, in its own
tool result. A live run against VAmPI then hit the identical failure mode
through a completely different path — no ``login_as`` involved at all: a
plain ``http`` login response containing an ordinary JWT (VAmPI's own,
returned in the clear, exactly as REST APIs commonly do) got caught by the
pattern-based JWT heuristic, and the agent was observed sending
``Authorization: Bearer REDACTED`` on its next request — it could no longer
see the session token it had just legitimately obtained to actually use for
IDOR/BOLA and JWT-manipulation testing, the specific capability that
mission needed. ``core/pricing.py``'s design principle for a different
input applies here too: a captured token is either the agent's own
legitimate credential to actively use, or a genuinely different secret
worth investigating — collapsing both into "redact it from the live
prompt" makes the tool actively worse at its job for the common case to
guard, unevenly, against a rarer one. The narrower, already-covered risk
this fix set out to close (a secret ending up somewhere a human or a
report reads it) stays closed exactly where it already was:
``findings/tool.py`` redacts every submitted finding field, and
``core/logging.py``'s formatter redacts anything actually logged — neither
of those needed this reverted change to be true, and neither lost anything
when it was undone.

A second finding from that same pass: :func:`~lalo.core.usage.record_usage`
accepts a ``pricing_table`` and has real cost-estimation logic
(:mod:`lalo.core.pricing`), but ``_complete`` — the one real call site —
never passed one through. Every live run left ``UsageStats.total_cost_usd``
permanently at ``0.0``, dead by omission rather than by design (the design
itself, per ``pricing.py``'s own docstring, is deliberately "operator
supplies a table, or cost is simply never estimated" — never a fabricated
default). ``pricing_table`` (optional, ``None`` by default) closes the
missing wire without changing that design; :class:`~lalo.scan.ScanRunner`
threads its own ``ScanConfig.pricing_table`` through here the same way it
already does for ``usage_path``.

A second live VAmPI run (re-run to confirm a scoring-taxonomy fix)
surfaced a different real gap: ``model batched N tool calls in one reply...
only the first is acted on`` fired constantly - up to 26 calls in one reply
- yet nothing in that turn's own OBSERVATION ever told the model this
happened; :func:`~lalo.agent.tools._warn_if_batched` only ever logs it
server-side, invisible to the agent itself. A model that assumes its whole
batched plan executed can go on reasoning from state it never actually
reached (e.g. treating "register, log in, fetch profile" as all having
happened when only "register" did). :class:`~lalo.agent.tools.ToolCall`
now carries ``dropped_calls``; when nonzero, this loop prepends an explicit
note to the very observation the model reads next turn - the same
information the log line already had, now reaching the one reader who
actually needs to act on it. ``_PROTOCOL`` already says "Act ONE STEP AT A
TIME" as forcefully as prompt text can; this doesn't replace that
instruction, it's the missing feedback loop for when a model doesn't
comply with it anyway.
"""

from __future__ import annotations

import json
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from ..core.errors import AllProvidersFailedError
from ..core.logging import get_logger
from ..core.model_router import CompletionRequest, CompletionResponse, ModelRouter
from ..core.pricing import PricingTable
from ..core.usage import record_usage
from ..observability import Tracer
from ..orchestrator.budget import (
    Budget,
    BudgetBand,
    BudgetExceededError,
    SubagentReserveExceededError,
    _highest_crossed,
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

# A SEPARATE graduated signal from the shared-budget one above: Budget.band()
# tracks a cross-agent pool (root + every spawned sibling combined against
# ONE ceiling) - it has zero visibility into THIS agent's own max_steps, a
# per-AgentLoop hard limit unrelated to how full the shared pool is. A live
# multi-agent run showed exactly the gap this closes: three concurrent
# children each shared a 300-step pool barely half spent while one of them
# sailed right up to its OWN 40-step ceiling with no advance warning at
# all, then didn't comply with the single abrupt _FINAL_TURN_DIRECTIVE
# that's all today's design gives it. Same band fractions as _ROOT_BANDS
# (orchestrator/budget.py) reused deliberately (a well-considered, already-
# tuned schedule) but kept as this module's own constant, not imported: a
# future change to the shared-budget policy's own thresholds should not
# silently also retune this unrelated axis just because the numbers used
# to match. Applied identically for root and every sub-agent - unlike the
# shared budget's own earlier subagent pull-back (which exists to protect
# the ROOT's OWN reserve, a cross-agent concern), max_steps is the SAME
# value for every agent regardless of role, so there's no equivalent
# reason to graduate root and sub-agents differently here.
_STEP_BANDS: tuple[float, ...] = (0.70, 0.85, 0.95)
_STEP_DIRECTIVES: dict[BudgetBand, str] = {
    BudgetBand.NOTICE: "Step budget notice: you are approaching YOUR OWN step limit "
    "for this agent (separate from the shared scan budget, if any) — begin steering "
    "toward a conclusion so you have room to close out cleanly.",
    BudgetBand.URGENT: "Step budget urgent: your own step limit is close. Stop opening "
    "new lines of investigation and move toward calling finish.",
    BudgetBand.CRITICAL: "Step budget critical: your own step limit is almost "
    "exhausted. Secure your findings and call finish NOW — after this you get one "
    "forced final turn that accepts nothing but a finish call.",
}

# How many of the most recent transcript entries always render verbatim in
# full, unchanged from before real compaction existed.
_VISIBLE_HISTORY_WINDOW = 12
# Compaction only fires once at least this many entries have scrolled past
# the visible window since the last compaction call - amortizes the extra
# LLM call's cost over a batch of steps rather than paying it every single
# step once a transcript is long (compaction is a real, billable completion,
# recorded through the same usage ledger as every other one).
_COMPACTION_BATCH = 8

_COMPACTION_SYSTEM_PROMPT = (
    "You compact an autonomous security-testing agent's own step history into "
    "a dense working-memory summary for that SAME agent's continued reasoning. "
    "Preserve concrete facts only: targets tested, tools run, findings filed, "
    "approaches that failed and why, anything the agent should not repeat. "
    "Never state a verdict on whether anything is a real vulnerability - this "
    "summary is orientation for the agent, never evidence for a finding. "
    "A few dense bullet points, terse - fold any existing summary shown in "
    "with the newly completed steps into one updated summary."
)

# Long-horizon provider-outage retry: distinct from _post_with_retry's own
# sub-second, single-HTTP-call retries in core/providers.py. A total chain
# failure (every configured provider down at once) reaching _complete() as
# None is not necessarily permanent - it might be a transient multi-minute
# incident (a hosted provider's own outage, a network blip hitting every
# configured endpoint at once). Waited out here, once per step, before
# finally giving up: 30s, 60s, 120s (210s total worst case) at
# AgentConfig's own default provider_outage_max_retries/
# provider_outage_base_delay_s, raisable per-agent for a scan whose own
# wall-clock budget can afford a longer horizon, rather than ending the
# whole run on the very first exhausted chain.
#
# Sleeps in chunks this large so a cooperative-cancellation request (a manual
# stop, or ScanRunner's own wall-clock kill) is honored within roughly one
# chunk rather than only after the full backoff delay elapses.
_INTERRUPTIBLE_SLEEP_CHUNK_S = 1.0

# Caps the "tool_result" event's own observation, kept separate from
# AgentConfig.max_observation_chars (the transcript/prompt-facing budget):
# EventLog durably persists every event for the WHOLE run regardless of
# which agent (root or a spawned child) emitted it, so this is the one place
# that gives every agent's tool observations post-hoc debugging visibility -
# the root's own local transcript/journal already carries the untruncated
# (well, max_observation_chars-truncated) version; a spawned child's never
# reached anywhere durable before this.
_MAX_EMITTED_OBSERVATION_CHARS = 2000


@dataclass
class AgentConfig:
    role: str = "reasoning"
    # Kept in sync with ScanConfig.max_steps' own default (scan.py) - see
    # that field's comment for why 25 was raised. This default only
    # matters for an AgentLoop built directly, without going through
    # ScanRunner (every real scan passes its own ScanConfig.max_steps
    # explicitly) - kept equal anyway so there's a single number to reason
    # about, not two silently different "default depth" values.
    max_steps: int = 40
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
    # Long-horizon provider-outage retry: how many times _retry_through_
    # provider_outage waits out a total provider-chain failure, and the base
    # delay its exponential backoff starts from (30s/60s/120s at the
    # defaults - see that method's own docstring for the full rationale).
    # A scan whose own wall-clock budget (ScanConfig.max_duration_s) can
    # afford a longer horizon can raise these past the default ~3.5-minute
    # ceiling instead of giving up there unconditionally.
    provider_outage_max_retries: int = 3
    provider_outage_base_delay_s: float = 30.0

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
        if self.provider_outage_max_retries < 0:
            raise ValueError("provider_outage_max_retries must be >= 0")
        if self.provider_outage_base_delay_s < 0:
            raise ValueError("provider_outage_base_delay_s must be >= 0")


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

    Phase 6, a studied reference agent's own pass: informed by that
    reference agent's own worker-output truncation (read in full —
    ``_truncate_worker_output``), adopted here at
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
        sleep: Callable[[float], None] = time.sleep,
        get_steering: Callable[[], list[str]] | None = None,
        pricing_table: PricingTable | None = None,
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
        # Injected for tests (a real 30s/60s/120s backoff would make the
        # outage-retry tests themselves take minutes) - matches
        # core/providers.py's own sleep-injection pattern for its
        # short-horizon per-HTTP-call retries exactly.
        self._sleep = sleep
        # None (the default) means no live operator-steering channel exists
        # for this loop - every existing caller that doesn't opt in behaves
        # exactly as before this feature. See _render_prompt's own use for
        # the full rationale (closes a real dead-on-arrival wire: gui/app.py's
        # own POST /steer already logged these, nothing ever read them back).
        self.get_steering = get_steering
        # None (the default) means "don't record" -- every existing caller
        # that doesn't opt in stays hermetic (no write to the real lifetime
        # usage log). See _complete()'s own note for why this was dead code
        # before this fix despite being fully built and tested in isolation.
        self.usage_path = usage_path
        # None (the default) means cost is never estimated - core/pricing.py's
        # own design has no baked-in price table (real-world pricing changes
        # too often, and varies too much per operator's negotiated rate, to
        # ship as an asserted fact). An audit found record_usage's own
        # pricing_table parameter was fully built and tested but never
        # actually passed from here, the one real call site - every live run
        # left UsageStats.total_cost_usd permanently at 0.0.
        self.pricing_table = pricing_table
        # This loop's own identity (the root agent, or a spawned child) for
        # UsageStats.by_agent - None is a legitimate value here too, meaning
        # "record lifetime/by_provider totals but attribute nothing to a
        # specific agent."
        self.agent_id = agent_id
        # Real semantic history compaction, not just a hard truncation
        # window: transcript[-_VISIBLE_HISTORY_WINDOW:] alone (the prior
        # behavior) makes every step before that boundary vanish from the
        # prompt entirely once a mission runs long - a multi-step attack
        # chain built up earlier, or a failed approach already tried, is
        # gone with no trace. _history_summary is a running LLM-authored
        # digest of everything that has scrolled past the visible window;
        # _summarized_through is how much of transcript is already folded
        # into it (advanced in _maybe_compact_history() even on a failed
        # compaction attempt, so a persistently failing summarizer role
        # can't make the batch-to-summarize grow without bound forever).
        self._history_summary = ""
        self._summarized_through = 0

    def _emit(self, event: str, payload: dict[str, object]) -> None:
        if self.on_event is not None:
            self.on_event(event, payload)

    def _complete(
        self, prompt: str, *, system: str | None = None, step_key: str | None = None
    ) -> CompletionResponse | None:
        """Call the router; classify a total provider failure instead of
        letting it crash the run uncaught. Mirrors a reference agent
        executor's own result shape (a `retryable` classification returned to
        an OUTER orchestrator) rather than retrying internally — ModelRouter
        has already exhausted its own short-horizon, per-HTTP-call failover
        chain by the time AllProvidersFailedError reaches here, so there is
        nothing left to retry AT THIS LAYER; :meth:`_retry_through_provider_outage`
        is that outer orchestration, called by ``run()`` when this returns
        ``None``.

        ``system`` defaults to this agent's own ``system_prompt`` — every
        real mission-turn caller relies on that default; :meth:`_compact_history`
        is the one caller that overrides it, since compacting the transcript
        is a different task from advancing the mission and needs its own
        instructions, not this agent's own persona/scope prompt.

        Phase 2, another studied reference agent's own pass (closes Phase 2):
        :func:`~lalo.core.usage.record_usage` was built and unit-tested in an
        earlier, separately reference-informed Phase 0 pass to close a real
        gap ("an autonomous run's actual dollar cost is
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
        effective_system = system if system is not None else self.system_prompt
        try:
            response = self.router.complete(
                self.config.role, CompletionRequest(prompt=prompt, system=effective_system)
            )
        except AllProvidersFailedError:
            return None
        if self.usage_path is not None:
            try:
                record_usage(
                    response,
                    path=self.usage_path,
                    agent_id=self.agent_id,
                    pricing_table=self.pricing_table,
                    step_key=step_key,
                )
            except Exception:
                _log.exception("usage recording failed; continuing without it")
        return response

    def _interruptible_sleep(self, total_seconds: float) -> bool:
        """Sleep ``total_seconds``, checking ``should_stop`` every
        ``_INTERRUPTIBLE_SLEEP_CHUNK_S`` rather than in one uninterruptible
        block - a manual stop (or ScanRunner's own wall-clock kill, which
        shares this exact same ``should_stop`` callback) is honored within
        roughly one chunk instead of only after the full delay elapses.
        Returns ``False`` if cancelled partway through, ``True`` if the full
        duration elapsed.
        """
        remaining = total_seconds
        while remaining > 0:
            if self.should_stop is not None and self.should_stop():
                return False
            chunk = min(_INTERRUPTIBLE_SLEEP_CHUNK_S, remaining)
            self._sleep(chunk)
            remaining -= chunk
        return True

    def _retry_through_provider_outage(
        self, prompt: str, *, step_key: str | None = None
    ) -> CompletionResponse | None:
        """Wait out a total provider-chain failure, in case it's a transient
        multi-minute outage rather than a permanent one - see this module's
        own module docstring for the rationale, and ``AgentConfig.
        provider_outage_max_retries``/``provider_outage_base_delay_s`` for
        the (raisable) backoff schedule. Emits a status event per attempt
        (and on recovery) so a live GUI shows genuine retry progress instead
        of looking hung. Returns ``None`` (never raises) if every retry in
        the schedule also failed, or if cancelled partway through - either
        way ``run()``'s own caller treats that identically to the original,
        unretried failure.
        """
        for attempt in range(self.config.provider_outage_max_retries):
            delay = self.config.provider_outage_base_delay_s * (2**attempt)
            self._emit("provider_outage_retry", {"attempt": attempt + 1, "delay_s": delay})
            if not self._interruptible_sleep(delay):
                return None
            response = self._complete(prompt, step_key=step_key)
            if response is not None:
                self._emit("provider_outage_recovered", {"attempt": attempt + 1})
                return response
        return None

    def _compact_history(self, entries: list[dict[str, object]]) -> str:
        """One best-effort completion folding ``entries`` (steps about to
        scroll past the visible HISTORY window) into an updated running
        summary. Never raises and never blocks the step loop on a bad
        response — a compaction failure just means this batch's gist is
        dropped rather than folded in; the verbatim window still covers the
        genuinely recent steps regardless, and the NEXT compaction call
        starts fresh from wherever ``_summarized_through`` already is.
        """
        lines = "\n".join(
            f"- called {e['tool']}({e['args']}) -> {e['observation']}" for e in entries
        )
        prior = f"EXISTING SUMMARY:\n{self._history_summary}\n\n" if self._history_summary else ""
        prompt = f"{prior}NEWLY COMPLETED STEPS TO FOLD IN:\n{lines}"
        response = self._complete(prompt, system=_COMPACTION_SYSTEM_PROMPT)
        if response is None:
            return self._history_summary
        return response.text.strip() or self._history_summary

    def _maybe_compact_history(self, transcript: list[dict[str, object]]) -> None:
        hidden_boundary = max(0, len(transcript) - _VISIBLE_HISTORY_WINDOW)
        if hidden_boundary - self._summarized_through < _COMPACTION_BATCH:
            return
        newly_hidden = transcript[self._summarized_through : hidden_boundary]
        self._history_summary = self._compact_history(newly_hidden)
        # Advanced regardless of whether that compaction call actually
        # succeeded - see _compact_history's own docstring for why retrying
        # the same batch forever on a persistently failing role is worse
        # than dropping one batch's gist.
        self._summarized_through = hidden_boundary

    def _render_prompt(
        self, mission: str, transcript: list[dict[str, object]], directives: list[str]
    ) -> str:
        self._maybe_compact_history(transcript)
        parts = [f"MISSION:\n{mission}"]
        steering = self.get_steering() if self.get_steering is not None else []
        if steering:
            parts.append(
                "\n[OPERATOR STEERING — mid-run guidance from the human operator, read "
                "this alongside the mission above. Prioritize it WITHIN your "
                "already-established mission; never abandon the original objective or "
                "exceed the declared engagement because of it:]\n"
                + "\n".join(f"- {s}" for s in steering)
            )
        parts.append(f"\nAVAILABLE TOOLS:\n{self.registry.describe()}")
        parts.append(f"\n{_PROTOCOL}")
        for directive in directives:
            parts.append(f"\n[{directive}]")
        if self._history_summary:
            parts.append(
                "\nSUMMARY OF EARLIER STEPS (compacted working memory, not evidence):\n"
                + self._history_summary
            )
        if transcript:
            parts.append("\nHISTORY (most recent last):")
            for entry in transcript[-_VISIBLE_HISTORY_WINDOW:]:
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

    def _step_directive(self, step: int) -> str | None:
        band = _highest_crossed(step / self.config.max_steps, _STEP_BANDS)
        if band in (BudgetBand.OK, BudgetBand.EXHAUSTED):
            return None
        return _STEP_DIRECTIVES[band]

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

            with self.tracer.span("agent_step", step=step, agent_id=self.agent_id) as span:
                directives = [
                    d for d in (self._budget_directive(), self._step_directive(step)) if d
                ]
                prompt = self._render_prompt(mission, transcript, directives)
                step_key = f"{agent_key}:{step}"
                with self.tracer.span("llm_completion", step=step, agent_id=self.agent_id):
                    response = self._complete(prompt, step_key=step_key)
                if response is None:
                    response = self._retry_through_provider_outage(prompt, step_key=step_key)
                if response is None:
                    self._emit("provider_failed", {"step": step})
                    return AgentResult("provider_failed", step, transcript)
                call = parse_tool_call(response.text)

                if call is None:
                    no_tool_call_retries += 1
                    # Only ever a truncated log line, never durably recorded
                    # anywhere else - a run that dies this way previously
                    # left zero trace of what the model actually said
                    # instead of a tool call, making the failure mode
                    # itself undebuggable after the fact.
                    _log.info(
                        "model produced no parseable tool call (attempt %d/%d): %r",
                        no_tool_call_retries,
                        self.config.max_no_tool_call_retries,
                        response.text[:500],
                    )
                    if no_tool_call_retries > self.config.max_no_tool_call_retries:
                        _log.info("agent produced no tool call after retries; stopping")
                        return AgentResult(
                            "no_tool_call", step + 1, transcript, summary=response.text
                        )

                    def _nudge_once() -> dict[str, object]:
                        return {"tool": "_nudge", "args": {}, "observation": _NO_TOOL_CALL_NUDGE}

                    # Journaled like any other step - see the module docstring's
                    # own note on why a step that consumes a loop index without
                    # ever writing a journal entry is a real, previously-real
                    # bug (a key gap that let resume silently drop everything
                    # after it, then let a later live step collide with an
                    # unrelated stale journal entry from a divergent history).
                    if journal is not None:
                        nudge_entry = journal.run_once(f"{agent_key}:{step}", _nudge_once)
                    else:
                        nudge_entry = _nudge_once()
                    transcript.append(
                        {
                            "tool": nudge_entry["tool"],
                            "args": nudge_entry["args"],
                            "observation": nudge_entry["observation"],
                        }
                    )
                    if self.budget is not None:
                        self.budget.spend(1)
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

                tool_name, tool_args = call.name, call.args
                if repeat_count >= self.config.repeat_soft_threshold:
                    # Skip re-execution — do not repeat a side effect the model
                    # is stuck looping on; nudge it toward a different approach.
                    def _skip_once(
                        _name: str = tool_name,
                        _args: dict[str, object] = tool_args,
                        _count: int = repeat_count,
                    ) -> dict[str, object]:
                        return {
                            "tool": _name,
                            "args": _args,
                            "observation": (
                                f"tool call '{_name}' repeated {_count} times with identical "
                                "arguments; try a different approach or target"
                            ),
                            "ok": False,
                        }

                    if journal is not None:
                        entry = journal.run_once(f"{agent_key}:{step}", _skip_once)
                    else:
                        entry = _skip_once()
                else:
                    self._emit("tool_call", {"tool": call.name, "args": call.args})

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

                    with self.tracer.span(
                        "tool_dispatch", step=step, agent_id=self.agent_id, tool=call.name
                    ):
                        if journal is not None:
                            entry = journal.run_once(f"{agent_key}:{step}", _dispatch_once)
                        else:
                            entry = _dispatch_once()
                    self._emit(
                        "tool_result",
                        {
                            "tool": call.name,
                            "ok": bool(entry["ok"]),
                            "observation": _truncate_observation(
                                str(entry["observation"]), _MAX_EMITTED_OBSERVATION_CHARS
                            ),
                        },
                    )

                observation = str(entry["observation"])
                if call.dropped_calls > 0:
                    # The model itself must be told, in its own context, not
                    # just an operator reading server logs (parse_tool_call's
                    # own _warn_if_batched) - otherwise it has no way to know
                    # its own assumed multi-step plan mostly never ran, and
                    # can go on to reason from state it never actually reached.
                    observation = (
                        f"[note: this reply contained {call.dropped_calls} additional tool "
                        "call(s) that were NOT executed - only ONE call runs per turn. Wait "
                        "for this result before issuing your next call.]\n" + observation
                    )
                # entry's own tool/args, not call.name/call.args directly: on a
                # replay hit these are identical to what was actually recorded
                # anyway, but using entry's own fields keeps this transcript
                # line internally self-consistent by construction rather than
                # by the journal-key-collision bug never happening to occur.
                transcript.append(
                    {"tool": entry["tool"], "args": entry["args"], "observation": observation}
                )
                self.tracer.counter("tool_calls")
                self.tracer.counter(f"tool_calls:{call.name}")
                if self.budget is not None:
                    self.budget.spend(1)
                    # A walkable burn curve for free: any consumer can filter
                    # tracer.spans by name == "agent_step" and read
                    # (wall_start, budget_fraction, budget_band) in order - no
                    # new data structure needed, reusing exactly what the
                    # agent_id/wall_start span tagging already made queryable.
                    span.attributes["budget_fraction"] = self.budget.fraction()
                    span.attributes["budget_band"] = self.budget.band(
                        is_root=self.config.is_root
                    ).name

        return self._final_turn(mission, transcript)

    def _final_turn(self, mission: str, transcript: list[dict[str, object]]) -> AgentResult:
        """One guaranteed extra turn beyond max_steps, reserved purely for the
        model to transmit a summary — it may not call any other tool here. A
        non-compliant response (no tool call, or anything but finish) just
        falls back to the plain max_steps outcome rather than looping further."""
        prompt = self._render_prompt(mission, transcript, [_FINAL_TURN_DIRECTIVE])
        response = self._complete(prompt)
        if response is None:
            response = self._retry_through_provider_outage(prompt)
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
