"""The end-to-end integration pass: wires every phase 0-18 mechanism into one
operator-runnable scan.

Every phase from Phase 0 (provider config) through Phase 18 (eval) built and
tested its own mechanism in isolation; nothing before this module ever
assembled provider/config resolution + the runtime container + the full tool
registry + prompts + :class:`~lalo.agent.loop.AgentLoop` + the reachability
graph into one thing an operator can actually point at a target and run — the
gap :func:`~lalo.gui.app.main`'s own docstring names explicitly. This module
is that assembly, not a new phase of its own: nothing here makes a fresh
architectural decision a numbered phase didn't already make, except the two
genuinely new pieces spelled out below.

**Multi-agent graph merge** (new): Phase 6/7 built isolated per-agent graph
snapshots and an authoritative-finding-ids merge rule, but no phase actually
wrote the glue that copies a child's finding NODES (not just their ids) back
onto its parent's graph — :func:`~lalo.agent.spawn.merge_finding_nodes`
closes that, used here at every spawn boundary, recursively (a grandchild's
findings land on its parent, which are then a normal part of what that
parent's own ``finding_ids`` reports up to ITS parent in turn).

**Two flat-toolset gaps closed**: Phase 8 (identity: login/JWT tamper) and
Phase 9 (recon: OpenAPI/GraphQL/JS-mining) were built as plain Python library
code with no agent-callable tool wrapper — unreachable by any agent, only by
tests. See :mod:`lalo.identity.tool` and :mod:`lalo.recon.tool`.
``query_graph``/``note``, named in CLAUDE.md's own flat-toolset description
but never built in any phase, are closed the same way — see
:mod:`lalo.graph.tool`. (Correction: an earlier version of this docstring, and
this commit's own original message, claimed these three files were built "per
the operator's explicit sign-off... asked via AskUserQuestion before writing
code." That claim was false — no such question was ever put to the operator.
The operator was informed of this after the fact, reviewed the actual
resulting code directly, and retroactively approved keeping it; that approval
is real, the originally-claimed prior one was not. Recorded here rather than
silently rewritten, matching this project's own citation-accuracy discipline.)
Two more gaps this docstring originally described as out of scope are also
now closed, both built afterward in direct response to today's own live
end-to-end run against a local target, not as part of this module's
original pass: a concrete :class:`~lalo.recon.runner.ReconRunner` (nmap, via
:mod:`lalo.recon.scan`, wired into the ``recon`` tool's own ``scan_ports``
action), and a real, scope-checked browser-automation tool
(:mod:`lalo.browser`, ``build_browser_tool``) — CLAUDE.md's last named,
previously never-built flat-toolset entry. One :class:`~lalo.browser.session.BrowserSession`
is shared across the whole scan (root and every spawned descendant), never
one per agent: :mod:`lalo.agent.spawn`'s own synchronous spawn model means
only one agent is ever calling tools at any moment, so there is no
concurrent access to isolate a browser session against, and starting a real
Chromium instance per agent would be pure waste for that reason.

**Login preflight** (added after a live comparison run showed a broken login
only ever surfacing deep into a mission, after budget was already spent on
unauthenticated groundwork): ``ScanConfig.login_preflight_pairs`` lets an
operator name which ``(identity_id, scheme_name)`` pairs to authenticate once
during preflight, before the container/OAST/browser or the main agent loop
start - see :meth:`ScanRunner._preflight_logins`. Advisory by default (a
failure is logged as a status event, matching ``fail_on_unreachable_targets``'
own stance), with ``fail_on_broken_login`` to hard-stop instead. Empty by
default and never auto-populated from ``identities``/``login_schemes``: those
two maps are independent (an identity isn't tied to one scheme), so pairing
them for preflight is the operator's call, not a cartesian-product guess this
module should make.

**Trace persistence** (an audit finding, not a request): every agent step
already ran inside a :meth:`~lalo.observability.tracing.Tracer.span`, and a
single shared :class:`~lalo.observability.tracing.Tracer` was already passed
to the root and every spawned child - but nothing ever read `.spans`/
`.counters` back out. The data was collected, logged once at debug level,
and discarded the moment the process exited. Closed by writing every span/
counter to ``trace.json`` in the run directory at run end (alongside
``events.jsonl``/``graph.json``) and folding a small aggregated summary
(span count/total duration per name, raw counters) into the
``scan_completed`` status event, both via :func:`_write_trace_file`/
:func:`_trace_summary`. Deliberately NOT changed: :class:`AgentLoop`'s own
default of a fresh ``Tracer()`` per instance when no explicit one is passed
- that default is only ever exercised by ad-hoc/test construction, since
this module already explicitly shares one ``Tracer`` across the whole spawn
tree; switching that default to the process-wide singleton would make two
unrelated scans running in the same long-lived process (the GUI server
serves more than one) silently share trace state, a worse regression than
the gap it would claim to close.

**Cost/usage report visibility** (the same audit pass): ``core/pricing.py``
and ``core/usage.py``'s ``record_usage`` were fully built with real cost-
estimation logic, but ``ScanConfig`` had no field to actually supply a
price table, and ``report/writer.py``/``html.py``/``pdf.py`` had zero
references to usage or cost anywhere - token/cost totals only ever reached
the operator as a transient GUI toast, never the delivered report.
``ScanConfig.pricing_table`` (optional, ``None`` by default - see the
field's own docstring for why no default table is baked in) closes the
first half; a :class:`~lalo.report.collect.ReportUsage` built from THIS
run's own usage delta (never the ``usage_path`` ledger's cumulative total,
which can span many scans) and threaded into :func:`~lalo.report.writer.
write_report` closes the second.

**Redaction is now opt-in, not opt-out** (an explicit, informed operator
request, not a project-wide "secrets don't matter" stance): ``core/
redaction.py``'s ``redact()`` used to run unconditionally for every log
line and every submitted finding field. ``ScanConfig.redact_findings``
(default ``False``) is set once, first thing in :meth:`run`, via
``set_redaction_enabled`` - captured credentials now appear verbatim in
the delivered report and logs unless an operator explicitly opts back
into the old, conservative behavior. This does not touch CLAUDE.md's own
confirmation-authority boundary, which was already maximally open before
this change (nothing has ever gated or removed a finding); it only
changes whether a literal secret STRING inside otherwise-complete
evidence gets masked in the delivered artifact.

**Review timing** (a deliberate, simple choice, not a hidden requirement):
CLAUDE.md's two non-blocking confidence layers run over every finding once
the primary agent (and every spawned descendant) has finished, not
interleaved mid-run — this keeps the review role's own provider chain
strictly separate from the root mission's turn-taking, at the cost of a
finding's adjusted score only being visible once the whole scan concludes
rather than the moment it lands. A future incremental-review pass could
change this without touching anything else here.
"""

from __future__ import annotations

import json
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from .agent.loop import AgentConfig, AgentLoop, AgentResult
from .agent.spawn import (
    AgentCoordinator,
    build_parallel_spawn_tool,
    build_spawn_tools,
    isolate_for_child,
    merge_finding_nodes,
)
from .agent.tools import Tool, ToolRegistry
from .browser.session import BrowserSession
from .browser.tool import build_browser_tool
from .core.atomic_io import append_owner_only_line, atomic_write_verified
from .core.config import load_settings
from .core.errors import (
    AllProvidersFailedError,
    ConfigError,
    ContainerError,
    LoginFailedError,
    ResumeConfigMismatchError,
    TargetUnreachableError,
)
from .core.model_router import ModelRouter
from .core.pricing import PricingTable
from .core.providers import build_router, verify_router
from .core.redaction import set_redaction_enabled
from .core.usage import load_usage
from .execution.firer import HttpFirer, probe_reachability
from .execution.scope import ScopeGuard
from .execution.target import Engagement
from .execution.tool import (
    build_access_control_matrix_tool,
    build_diff_responses_tool,
    build_fire_concurrent_tool,
    build_http_tool,
    build_raw_tcp_tool,
)
from .findings.confidence import compute_confidence
from .findings.review import run_adversarial_review
from .findings.tool import build_record_finding_tool
from .graph.model import NodeKind, ReachabilityGraph
from .graph.tool import build_note_tool, build_query_graph_tool
from .identity.credentials import Identity, IdentityStore
from .identity.login import LoginScheme, SessionRegistry, login
from .identity.tool import build_jwt_tool, build_login_tool, build_session_check_tool
from .integrations.mcp_client import MCPServerConfig, build_mcp_tool
from .oast.server import OASTServer
from .oast.tool import build_oast_tools
from .observability.tracing import Tracer, wall_clock_union
from .orchestrator.budget import Budget, RunStatus
from .orchestrator.journal import DurableJournal
from .prompts import render_prompt
from .recon.tool import build_recon_tool
from .report.collect import ReportUsage
from .report.manifest import write_report_manifest
from .report.writer import write_report
from .runtime.container import RuntimeConfig, RuntimeContainer, docker_available
from .runtime.tool import build_run_command_tool
from .skills.loader import load_skills
from .skills.tool import build_recall_tool

if TYPE_CHECKING:
    from .gui.events import EventCategory, EventLog

_TERMINAL_SUCCESS = frozenset({"finished", "max_steps_reserved_turn"})
_TERMINAL_BUDGET = frozenset({"budget_exhausted", "subagent_reserve_exhausted"})


@dataclass
class ScanConfig:
    """Everything one scan run needs beyond provider credentials (env-resolved)."""

    mission: str
    target_specs: list[str]
    run_dir: Path
    exclude_target_specs: list[str] = field(default_factory=list)
    # Constraints beyond target scope (e.g. "no destructive testing outside
    # business hours", "do not touch the payments service") -- kept distinct
    # from the free-form `mission` so it's always injected into the agent
    # prompt as its own guaranteed block, never dependent on whether the
    # mission text happens to repeat it. Empty by default (nothing extra).
    rules_of_engagement: str = ""
    egress_lock: bool = False
    max_steps: int = 25
    spawn_max_depth: int = 3
    budget_ceiling: int = 300
    identities: dict[str, Identity] = field(default_factory=dict)
    login_schemes: dict[str, LoginScheme] = field(default_factory=dict)
    # (identity_id, scheme_name) pairs to authenticate once during preflight,
    # before the main agent loop starts, rather than only ever discovering a
    # broken login whenever the agent itself gets around to calling
    # `login_as` mid-mission - by then it may have already burned real
    # budget on unauthenticated groundwork. Empty by default: identities and
    # login_schemes are two independent maps (an identity isn't tied to one
    # scheme), so pairing them is the operator's call, not a guess this
    # module should make via a cartesian product.
    login_preflight_pairs: list[tuple[str, str]] = field(default_factory=list)
    # False (the default) mirrors fail_on_unreachable_targets' own advisory-
    # only stance: a failed preflight login is always logged as a status
    # event, and set True only to hard-stop the scan on it instead.
    fail_on_broken_login: bool = False
    # Keyed by connection name, matching `identities`' own convention -- a
    # dict key structurally rules out two connections silently colliding on
    # the same agent-facing `mcp_<name>` tool name, unlike a plain list
    # (see integrations/mcp_client.py's own module docstring for why a
    # reference agent's equivalent raises UserError on this at runtime
    # instead; a dict makes the collision unrepresentable instead of caught).
    mcp_connections: dict[str, MCPServerConfig] = field(default_factory=dict)
    container_config: RuntimeConfig | None = None
    # None (the default) keeps a caller hermetic -- matching container_config's
    # own opt-in shape. Pass DEFAULT_USAGE_PATH (or any path) to actually
    # record real lifetime token/cost usage for this scan's completions; the
    # GUI's own real scan-launch path opts in.
    usage_path: Path | None = None
    # None (the default) means cost is never estimated - core/pricing.py's
    # own design deliberately ships with no baked-in price table (real-world
    # token pricing changes too often, and varies too much per operator's
    # own negotiated rate, to assert as a fact on the operator's behalf).
    # Meaningless without usage_path also being set - cost is derived from
    # the SAME per-completion token counts usage recording already captures,
    # never computed independently.
    pricing_table: PricingTable | None = None
    # False (the default) preserves probe_reachability's own advisory-only
    # design -- an in-engagement network/infra or raw-TCP target may simply
    # not speak HTTP, so "unreachable" is never assumed to mean
    # misconfigured. An operator who knows their targets are HTTP-reachable
    # can opt into a hard stop instead of a logged warning. An operational
    # preference, not a locked scope/safety field -- deliberately excluded
    # from _ResumeManifest, same reasoning as max_steps/budget_ceiling.
    fail_on_unreachable_targets: bool = False
    # None (the default) preserves today's unbounded behavior - nothing
    # anywhere else enforces a real-time ceiling on a scan; only the step
    # count (max_steps) and step budget (budget_ceiling) can ever stop one,
    # and a mission spending most of its steps on slow network waits could
    # otherwise run for a very long time while technically still "within
    # budget". Set to opt into a hard wall-clock kill via the SAME
    # cooperative should_stop() every AgentLoop already checks between
    # steps - reuses the existing cancel plumbing rather than adding a new
    # one. Deliberately excluded from _ResumeManifest and NOT persisted
    # across a resume: the clock restarts fresh on each real process
    # lifetime rather than tracking cumulative wall-clock time across
    # crashes, the same simplification already accepted for max_steps/
    # budget_ceiling being resume-adjustable operational knobs, not locked
    # scope/safety fields.
    max_duration_s: float | None = None
    # False (the default) keeps the review role's LLM cost at one call per
    # finding. True doubles it - a second, differently-lensed review
    # (findings/review.py's own production-viability-skeptic
    # review_second_opinion.txt) runs per finding, feeding a small,
    # always-positive corroboration bonus into the confidence score on
    # agreement, never a penalty on disagreement. An operational cost/
    # thoroughness tradeoff, not a locked scope/safety field.
    enable_second_opinion_review: bool = False
    # False (the default) means secrets are NOT redacted - an explicit,
    # informed operator choice (see core/redaction.py's own
    # set_redaction_enabled docstring for the full reasoning): captured
    # credentials appear verbatim in the delivered report and in logs.
    # Unlike egress_lock/fail_on_unreachable_targets above, this default is
    # the PERMISSIVE one on purpose - an operator who wants the older,
    # conservative report-hygiene behavior back sets this True.
    redact_findings: bool = False


@dataclass
class ScanOutcome:
    status: RunStatus
    result: AgentResult
    report_paths: dict[str, Path]


@dataclass(frozen=True)
class _ResumeManifest:
    """The subset of :class:`ScanConfig` that must stay IDENTICAL across a
    crash/resume for the resumed run to be resuming the same authorized
    engagement, not a silently different one — see
    :class:`~lalo.core.errors.ResumeConfigMismatchError`.

    Deliberately narrower than "every ScanConfig field", after reading a
    reference agent's own real ``--resume`` implementation in full (not just
    its comparison-doc summary): that CLI hard-rejects combining ``--resume``
    with a new target list (targets are permanently locked to the persisted
    run), but explicitly treats several OTHER fields as operator-adjustable
    on resume, inheriting the persisted value only when the operator doesn't
    re-specify one (``if args.instruction is None: args.instruction =
    state.get("instruction")``). The same reference's own budget/turn
    governance separately confirms *why* this distinction matters here:
    ``BudgetExceededError``/reaching the scan budget limit cleanly stops the
    scan (not a crash) specifically so the operator can resume it -- and the
    single most obvious reason to resume a budget-stopped scan is to raise
    the ceiling that stopped it. An earlier version of this manifest included
    ``max_steps``/``spawn_max_depth``/``budget_ceiling``, which would have
    made exactly that normal, expected resume flow impossible (any budget
    increase would be rejected as a "different config"). Only fields that
    actually define WHAT is authorized (mission, targets, exclusions, rules
    of engagement) or toggle a safety control (egress_lock) are locked;
    operational tuning knobs are free to change across a resume.
    """

    mission: str
    target_specs: list[str]
    egress_lock: bool
    # Both defaulted (unlike the fields above) so a manifest written before
    # these fields existed still resumes -- an old run predates the concept
    # of an exclusion list or a distinct rules-of-engagement field, which is
    # honestly "none"/"" for that run, not a reason to refuse resume.
    exclude_target_specs: list[str] = field(default_factory=list)
    rules_of_engagement: str = ""

    @classmethod
    def from_config(cls, config: ScanConfig) -> _ResumeManifest:
        return cls(
            mission=config.mission,
            target_specs=list(config.target_specs),
            exclude_target_specs=list(config.exclude_target_specs),
            rules_of_engagement=config.rules_of_engagement,
            egress_lock=config.egress_lock,
        )


def _manifest_path(run_dir: Path) -> Path:
    return run_dir / "resume_manifest.json"


def read_resume_manifest(run_dir: Path) -> dict[str, object] | None:
    """The locked engagement fields (mission/targets/exclusions/rules of
    engagement/egress_lock) a prior run of ``run_dir`` persisted - for a
    caller (the GUI's own resume affordance) that wants to relaunch it
    without retyping them, so a resume can never accidentally diverge from
    what was originally authorized. ``None`` if ``run_dir`` was never
    actually started (no manifest was ever written).
    """
    path = _manifest_path(run_dir)
    if not path.exists():
        return None
    data = json.loads(path.read_bytes())
    return data if isinstance(data, dict) else None


def _journal_path(run_dir: Path) -> Path:
    return run_dir / "journal.jsonl"


def _max_spawned_agent_number(journal: DurableJournal) -> int:
    """The highest N already used by an ``agent-N`` child anywhere in
    ``journal`` -- used to reseed :class:`AgentCoordinator`'s child-id
    counter on resume (see :meth:`AgentCoordinator.seed_counter`), since a
    fresh process has no memory of ids a crashed attempt's replayed-not-
    respawned steps already used.
    """
    numbers: list[int] = []
    for key in journal.completed_keys():
        prefix, _, _ = key.partition(":")
        suffix = prefix.removeprefix("agent-")
        if suffix != prefix and suffix.isdigit():
            numbers.append(int(suffix))
    return max(numbers, default=0)


def _events_path(run_dir: Path) -> Path:
    return run_dir / "events.jsonl"


def _trace_path(run_dir: Path) -> Path:
    return run_dir / "trace.json"


def _trace_summary(tracer: Tracer) -> dict[str, object]:
    """Aggregate ``tracer``'s spans by name (count + total duration) plus its
    raw counters - an audit found this data was previously collected, logged
    at debug level, and then discarded: nothing anywhere ever read a
    :class:`~lalo.observability.tracing.Tracer`'s ``.spans``/``.counters``
    back out. Small and JSON-serializable on purpose, for both the durable
    ``trace.json`` file below and the ``scan_completed`` status event.
    """
    by_name: dict[str, dict[str, float]] = {}
    for s in tracer.spans:
        agg = by_name.setdefault(s.name, {"count": 0.0, "total_duration_ms": 0.0})
        agg["count"] += 1
        agg["total_duration_ms"] += s.duration_ms or 0.0
    return {
        "spans": by_name,
        "counters": dict(tracer.counters),
        # Distinct from summing every span's own duration above: concurrent
        # spawn_agents work overlaps in real time, so a plain sum overcounts
        # wall-clock elapsed by however much it overlapped.
        "wall_clock_seconds": wall_clock_union(tracer.spans),
    }


def _write_trace_file(run_dir: Path, tracer: Tracer) -> None:
    """Persist every raw span/counter to ``trace.json``, alongside
    ``events.jsonl`` - the durable, after-the-fact answer to "what took
    long and how often did each tool run" that a plain in-memory Tracer
    could never give once the process exits.

    Routed through :func:`atomic_write_verified` like every other whole-file
    run-directory artifact (the graph, every report format, the usage log) -
    a span's own ``attributes`` can carry the same confidential
    engagement/target data those do, so this needs the identical owner-only
    (``0600``) guarantee, not a plain ``Path.write_text`` at the OS default
    mode.
    """
    payload = {
        "spans": [
            {
                "name": s.name,
                "start": s.start,
                "end": s.end,
                "duration_ms": s.duration_ms,
                "attributes": s.attributes,
            }
            for s in tracer.spans
        ],
        "counters": dict(tracer.counters),
    }
    atomic_write_verified(_trace_path(run_dir), json.dumps(payload, indent=2).encode("utf-8"))


def load_run_events(run_dir: Path) -> EventLog:
    """Replay a run's durably-persisted narration into a fresh, in-memory
    :class:`~lalo.gui.events.EventLog` — for a run-history viewer to render a
    completed/crashed run's events exactly as the live GUI would have,
    independent of whether that scan's own live ``EventLog`` (process-
    lifetime, not run-scoped) still holds them or the GUI process that ran it
    is even still alive.

    Missing file or a torn final line from a crash mid-write are never fatal
    - the former is a run recorded before this feature existed (or one with
    no ``event_log`` attached at all), the latter mirrors
    :class:`~lalo.orchestrator.journal.DurableJournal`'s own established
    crash-tolerant reload behavior.
    """
    from .gui.events import EventLog

    replay = EventLog()
    path = _events_path(run_dir)
    if not path.exists():
        return replay
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except (json.JSONDecodeError, ValueError):
            continue
        if not isinstance(record, dict):
            continue
        category = record.get("category")
        payload = record.get("payload")
        if not isinstance(category, str) or not isinstance(payload, dict):
            continue
        replay.append(category, payload)  # type: ignore[arg-type]
    return replay


def _load_or_write_manifest(config: ScanConfig) -> None:
    """Enforce config-identity across a resume, then ensure a manifest exists
    for THIS run either way (a first run writes one so a later crash has
    something to check against; a resumed run that matches leaves it alone).
    """
    current = _ResumeManifest.from_config(config)
    path = _manifest_path(config.run_dir)
    if path.exists():
        persisted = _ResumeManifest(**json.loads(path.read_bytes()))
        if persisted != current:
            raise ResumeConfigMismatchError(
                f"run_dir {config.run_dir} holds a scan started with different "
                "config (mission/targets/budget/steps) -- refusing to resume "
                "under different parameters than what was originally authorized"
            )
        return
    atomic_write_verified(path, json.dumps(asdict(current), sort_keys=True).encode("utf-8"))


def _terminal_status(stop_reason: str) -> RunStatus:
    if stop_reason in _TERMINAL_SUCCESS:
        return RunStatus.COMPLETED
    if stop_reason in _TERMINAL_BUDGET:
        return RunStatus.BUDGET_EXHAUSTED
    # cancelled / provider_failed / no_tool_call / repeating_tool_call_aborted /
    # a bare max_steps (the model didn't even use its reserved final turn) are
    # all "a stop happened, but nothing here ever confirmed a clean finish" -
    # RunStatus.COMPLETED must never be claimed on their behalf.
    return RunStatus.UNVERIFIED_STOP


def _diff_by_agent(
    before: dict[str, dict[str, float]], after: dict[str, dict[str, float]]
) -> dict[str, dict[str, float]]:
    """Diff two ``UsageStats.by_agent`` maps key-for-key, the same way the
    flat lifetime totals just above are already diffed - the data was
    already computed and thrown away; this just stops throwing it away. An
    agent present in only one of the two snapshots (a child spawned during
    this run has no "before" entry at all) reads as a plain 0 baseline on
    the missing side, not a KeyError.
    """
    result: dict[str, dict[str, float]] = {}
    for agent_id in set(before) | set(after):
        b, a = before.get(agent_id, {}), after.get(agent_id, {})
        result[agent_id] = {
            field: a.get(field, 0) - b.get(field, 0)
            for field in ("requests", "input_tokens", "output_tokens", "cost_usd")
        }
    return result


_SHELL_CHUNK_FLUSH_THRESHOLD_CHARS = 750


class _ShellChunkCoalescer:
    """Wraps an ``on_shell_event`` sink to collapse high-frequency shell
    "chunk" events (one per output line) into far fewer, larger ones before
    they ever reach :meth:`ScanRunner._emit` -- a single verbose command
    (feroxbuster, ``nmap -v``, gobuster) can otherwise emit thousands of
    one-line chunk events, which would evict a run's own earlier
    findings/narration from the shared, bounded ``EventLog`` and serialize
    concurrent agents behind a synchronous per-line disk append.

    "start" and "end" events (exactly one each per command) always pass
    through immediately, unbuffered, in original order. "chunk" events are
    buffered per ``(command_id, stream)`` -- stdout and stderr are never
    merged, since the frontend renders them with different styling (see
    ``applyShellEvent`` in gui/static/app.js) -- and flushed as one combined
    event once the buffered text reaches ``threshold`` characters, or when a
    "start"/"end" for that command_id arrives (any pending chunks for that
    command, both streams, are flushed first, then the start/end passes
    through).

    Not thread-safe by design and doesn't need to be: one instance is built
    fresh per agent (inside ``_build_registry``, itself called once per
    agent), and a single agent's own ``run_command`` tool calls are already
    sequential from that agent's own perspective.
    """

    def __init__(
        self,
        emit: Callable[[dict[str, object]], None],
        *,
        threshold: int = _SHELL_CHUNK_FLUSH_THRESHOLD_CHARS,
    ) -> None:
        self._emit = emit
        self._threshold = threshold
        self._buffers: dict[tuple[object, str], str] = {}

    def __call__(self, payload: dict[str, object]) -> None:
        event = payload.get("event")
        command_id = payload.get("command_id")
        if event == "chunk":
            key = (command_id, str(payload.get("stream")))
            text = self._buffers.get(key, "") + str(payload.get("text", ""))
            if len(text) >= self._threshold:
                del self._buffers[key]
                self._emit_chunk(command_id, key[1], text)
            else:
                self._buffers[key] = text
            return
        if event in ("start", "end"):
            self._flush_command(command_id)
        self._emit(payload)

    def _flush_command(self, command_id: object) -> None:
        for stream in ("stdout", "stderr"):
            key = (command_id, stream)
            text = self._buffers.pop(key, None)
            if text:
                self._emit_chunk(command_id, stream, text)

    def _emit_chunk(self, command_id: object, stream: str, text: str) -> None:
        self._emit({"event": "chunk", "command_id": command_id, "stream": stream, "text": text})


class ScanRunner:
    """Runs one scan to completion. Call :meth:`run` from a background thread
    (it blocks for the whole scan) and :meth:`cancel` from any other thread to
    request early termination.

    Phase 2, shannon pass (closes Phase 2): that reference's own ``stop``
    command implements a deliberately elaborate cancel-then-terminate-then-
    verify workflow lifecycle, with its own docstring naming the property
    worth adopting -- "Shannon does not silently believe a scan stopped."
    :meth:`cancel` here used to be purely cooperative (set a flag, checked
    only at the next agent-loop step boundary) -- correct for the model call
    itself, but a scan blocked on a long-running tool call (a multi-minute
    nmap sweep, say) would keep running for however long that ONE call takes
    to finish naturally, regardless of how urgently an operator needs it
    stopped (e.g. having just realized a target is more sensitive than
    intended). ``cancel`` now ALSO force-stops the running container the
    instant it's called, from whatever thread called it -- interrupting a
    blocking ``exec()`` immediately (a forcibly-removed container makes the
    in-flight ``docker exec`` fail fast with a real, ordinary tool-observation
    failure, not a hang or a crash) rather than waiting for a timeout. The
    cooperative flag stays too, since the container may not exist yet (a
    cancel requested before ``run()`` even starts still needs to stop the
    agent loop's very first step) and because a graceful in-between-steps
    stop is still the common, non-urgent case.
    """

    def __init__(
        self,
        config: ScanConfig,
        *,
        env: Mapping[str, str] | None = None,
        event_log: EventLog | None = None,
    ) -> None:
        self.config = config
        self._env = env
        self.event_log = event_log
        self._cancelled = False
        self._container: RuntimeContainer | None = None
        # Multi-lane concurrent sub-agents (spawn_agents) run several
        # children's own AgentLoops on real OS threads at once - _emit_lock
        # serializes every _emit() call (the durable file append plus
        # event_log.append(), both hit by every one of those children's own
        # tool_call/tool_result/status events), and _graph_lock serializes
        # every touch of a SHARED ReachabilityGraph (a child's own isolated
        # copy is never touched concurrently by anything else - only the
        # isolate_for_child() snapshot and the eventual merge_finding_nodes()
        # call back onto a shared parent graph ever need this).
        self._emit_lock = threading.Lock()
        self._graph_lock = threading.Lock()
        # Set to time.monotonic() at the top of run() - None beforehand so
        # _should_stop() (which every AgentLoop, root and every spawned
        # child, already polls between steps) can't mistake "hasn't started
        # yet" for "the deadline already passed".
        self._start_time: float | None = None
        self._wall_clock_exceeded = False

    def cancel(self) -> None:
        self._cancelled = True
        container = self._container
        if container is not None:
            container.stop()

    def _should_stop(self) -> bool:
        if self._cancelled:
            return True
        max_duration = self.config.max_duration_s
        if (
            max_duration is not None
            and self._start_time is not None
            and time.monotonic() - self._start_time >= max_duration
        ):
            # A plain bool write, not a read-modify-write - concurrently
            # spawned children (spawn_agents) may all observe and set this
            # at once; redundant writes of the same value are harmless,
            # unlike the counter/dict races elsewhere in this phase.
            self._wall_clock_exceeded = True
            return True
        return False

    def _pending_steering(self) -> list[str]:
        """Every operator steering message received so far this run, in
        order - closes a real, previously dead-on-arrival wire: POST /steer
        already appended a "steering" event to the GUI's own EventLog
        (gui/app.py's own module docstring even says "a human OR AGENT may
        later read" it), but nothing anywhere ever actually read it back
        into a running AgentLoop - an operator typing "focus on the API
        endpoints" mid-scan had ZERO effect on the agent, only a cosmetic
        line in the GUI thread.

        Deliberately NON-consuming (returns the full history every call,
        never advances a cursor): multi-lane concurrent sub-agents
        (spawn_agents) mean several AgentLoops - the root and any number of
        children - may call this independently or concurrently, and a
        single shared "already consumed" cursor would mean only whichever
        one happened to read first ever saw a given message. Each caller
        (AgentLoop._render_prompt) instead just re-renders the current full
        list every time, which is cheap (a bounded, in-memory filter) and
        gives every agent in the spawn tree the same persistent view.

        Read-only in the same sense the /steer endpoint's own design
        already establishes: this only ever influences what the agent
        chooses to prioritize within its own normal think-act-observe
        loop - it has no path to record_finding or any other tool, and
        cannot expand the operator-declared engagement.
        """
        if self.event_log is None:
            return []
        _cursor, events = self.event_log.snapshot()
        return [
            str(e.payload["text"])
            for e in events
            if e.category == "steering" and "text" in e.payload
        ]

    def _preflight_logins(self, firer: HttpFirer) -> list[tuple[str, str, str]]:
        """Authenticate every configured ``(identity_id, scheme_name)`` pair
        once, before the main agent loop starts, catching a broken login
        immediately rather than only whenever the agent itself gets around
        to calling ``login_as`` mid-mission - potentially after already
        burning real budget on unauthenticated groundwork.

        Returns ``(identity_id, scheme_name, reason)`` for every pair that
        failed; always advisory (logged via a status event) regardless of
        ``fail_on_broken_login`` - the caller decides whether a failure is
        fatal. A resulting session is discarded, not registered: this is a
        credential-shape check, not a substitute for the agent's own
        `login_as` call, which is what actually registers a usable session
        on the graph (see identity/login.py's own SessionRegistry
        docstring for why that invariant matters).
        """
        failures: list[tuple[str, str, str]] = []
        for identity_id, scheme_name in self.config.login_preflight_pairs:
            identity = self.config.identities.get(identity_id)
            scheme = self.config.login_schemes.get(scheme_name)
            if identity is None or scheme is None:
                reason = (
                    f"unknown identity {identity_id!r}"
                    if identity is None
                    else f"unknown scheme {scheme_name!r}"
                )
                failures.append((identity_id, scheme_name, reason))
                self._emit(
                    "status",
                    {
                        "event": "login_preflight_failed",
                        "identity_id": identity_id,
                        "scheme": scheme_name,
                        "reason": reason,
                    },
                )
                continue
            try:
                login(firer, identity, scheme)
            except LoginFailedError as exc:
                failures.append((identity_id, scheme_name, str(exc)))
                self._emit(
                    "status",
                    {
                        "event": "login_preflight_failed",
                        "identity_id": identity_id,
                        "scheme": scheme_name,
                        "reason": str(exc),
                    },
                )
        return failures

    def _emit(self, category: EventCategory, payload: dict[str, object]) -> None:
        # Durably persisted regardless of whether a live EventLog is attached
        # (EventLog itself is process-lifetime, not run-scoped - it outlives
        # any single scan - so this is the only durable, per-run record of a
        # scan's own narration once the process exits or a later scan starts).
        # Same sensitivity class as journal.jsonl (tool_call args can carry a
        # session token, a login password) - same append_owner_only_line
        # primitive, same 0600 permission model. Locked: concurrently
        # spawned children (spawn_agents) each call this from their own
        # thread on every one of their own tool_call/tool_result/status
        # events.
        with self._emit_lock:
            append_owner_only_line(
                _events_path(self.config.run_dir),
                json.dumps({"category": category, "payload": payload}, sort_keys=True, default=str),
            )
            if self.event_log is not None:
                self.event_log.append(category, payload)

    def _on_agent_event(self, agent_id: str, event: str, payload: dict[str, object]) -> None:
        if event in ("tool_call", "tool_result"):
            self._emit("log", {"agent_id": agent_id, "event": event, **payload})
        else:
            self._emit("status", {"agent_id": agent_id, "event": event, **payload})

    def _on_root_event(
        self,
        agent_id: str,
        event: str,
        payload: dict[str, object],
        graph: ReachabilityGraph,
        graph_path: Path,
    ) -> None:
        """Like :meth:`_on_agent_event`, but for the root agent only: also
        persists the graph after every completed step.

        Replaying the journal on resume restores the root's own transcript,
        but does nothing to restore what those original tool calls did to the
        graph (record_finding/note/recon facts, or a completed spawn_agent
        call's merged child findings) -- dispatch is deliberately never
        re-run during replay. Without this, a crash mid-scan would resume the
        CONVERSATION but silently lose every finding/fact the graph held at
        crash time, since the only other graph.save() call in this class runs
        once, at the very end of a fully completed scan. A save after every
        root-level step keeps the two artifacts (journal, graph) at the same
        durability granularity, mirroring this journal's own "every
        individual side-effecting step, not a periodic snapshot" principle.
        """
        self._on_agent_event(agent_id, event, payload)
        if event == "tool_result":
            graph.save(graph_path)

    def run(self) -> ScanOutcome:
        # Set before anything else in this run can possibly log or record a
        # finding - the redaction toggle is process-wide (see
        # core/redaction.py's own set_redaction_enabled docstring), so it
        # must be in effect from the very first line this run could emit,
        # not applied partway through.
        set_redaction_enabled(self.config.redact_findings)
        # Started here, not in __init__: a session's wall-clock budget
        # should measure from when the scan actually begins running, not
        # from whenever the ScanRunner object happened to be constructed.
        self._start_time = time.monotonic()
        # Cheap, local, no-resource-started-yet check: refuse to (re)start
        # against a run_dir that already belongs to a different config before
        # a single provider/container/OAST resource is touched.
        self.config.run_dir.mkdir(parents=True, exist_ok=True)
        _load_or_write_manifest(self.config)

        settings = load_settings(self._env)
        if not settings.resolved:
            raise ConfigError(
                "no LLM provider credentials configured - set one of: "
                + ", ".join(sorted(settings.missing_credential_hints().values()))
            )
        router = build_router(settings)

        if not docker_available():
            raise ContainerError(
                "docker is not reachable - the disposable runtime container "
                "cannot start, and L4L0 never runs the free shell without it"
            )

        # Preflight, cheap-to-expensive, before any container/OAST/browser
        # resource starts -- informed by a reference agent's own real
        # preflight validator (see core/providers.py's verify_router and
        # execution/firer.py's probe_reachability docstrings for the full
        # citations). docker_available() above is the cheapest check (no
        # network at all) and stays first; these two make real network calls
        # (an LLM completion, a target probe), so they run after it, still
        # before the actually-expensive container/OAST/browser startup. A
        # totally-broken provider chain is a hard precondition failure (this
        # would fail on the very first completion call regardless, just
        # wastefully late); target reachability stays advisory-only and never
        # blocks the scan.
        provider_health = verify_router(router)
        if provider_health and not any(healthy for healthy, _ in provider_health.values()):
            raise AllProvidersFailedError(
                "every configured provider failed preflight verification",
                failures=[(name, reason) for name, (_, reason) in provider_health.items()],
            )

        engagement = Engagement.from_specs(
            self.config.target_specs, exclude_specs=self.config.exclude_target_specs
        )
        scope = ScopeGuard(engagement, egress_lock=self.config.egress_lock)
        preflight_firer = HttpFirer(scope)
        try:
            reachability = probe_reachability(engagement, preflight_firer)
            login_failures = self._preflight_logins(preflight_firer)
        finally:
            preflight_firer.close()
        unreachable: list[tuple[str, str]] = []
        for host, (reachable, reason) in reachability.items():
            if not reachable:
                self._emit(
                    "status",
                    {"event": "target_unreachable_preflight", "host": host, "reason": reason},
                )
                unreachable.append((host, reason))
        if self.config.fail_on_unreachable_targets and unreachable:
            detail = "; ".join(f"{host}: {reason}" for host, reason in unreachable)
            raise TargetUnreachableError(
                f"target reachability preflight failed ({detail}) and "
                "fail_on_unreachable_targets is set"
            )
        if self.config.fail_on_broken_login and login_failures:
            detail = "; ".join(
                f"{identity_id}/{scheme_name}: {reason}"
                for identity_id, scheme_name, reason in login_failures
            )
            raise LoginFailedError(
                f"login preflight failed ({detail}) and fail_on_broken_login is set"
            )

        container = RuntimeContainer(self.config.container_config)
        self._container = container
        container.start()
        try:
            oast = OASTServer()
            oast.start()
            try:
                # Lazily-started (BrowserSession never actually launches
                # Chromium until a mission calls "browser" for the first
                # time) - created eagerly here anyway so its cleanup lives
                # alongside the container/OAST server's, in the same
                # try/finally shape, rather than needing a third nesting
                # level inside _run_inside for a resource _run_inside itself
                # doesn't otherwise need to know how to tear down.
                browser = BrowserSession(scope)
                try:
                    return self._run_inside(router, scope, engagement, container, oast, browser)
                finally:
                    browser.close()
            finally:
                oast.stop()
        finally:
            container.stop()
            self._container = None

    def _run_inside(
        self,
        router: ModelRouter,
        scope: ScopeGuard,
        engagement: Engagement,
        container: RuntimeContainer,
        oast: OASTServer,
        browser: BrowserSession,
    ) -> ScanOutcome:
        # ponytail: snapshot-then-diff against the lifetime usage ledger is
        # this-run's token count on a fresh start; a resumed run only counts
        # the resumed portion (the crashed attempt's own usage was already
        # persisted before this process started) -- exact cross-resume
        # accounting would need the snapshot itself persisted into the run
        # manifest, not worth it for a single display number.
        usage_path = self.config.usage_path
        usage_before = load_usage(usage_path) if usage_path is not None else None

        graph_path = self.config.run_dir / "graph.json"
        # A graph.json left behind by a prior crashed attempt at this SAME
        # run_dir (manifest-verified above to be the same authorized config)
        # means this is a resume, not a fresh start -- load what was already
        # found rather than discarding it.
        graph = ReachabilityGraph.load(graph_path) if graph_path.exists() else ReachabilityGraph()
        journal = DurableJournal(_journal_path(self.config.run_dir))
        skills = load_skills()
        firer = HttpFirer(scope)
        # Built once here (not inside _build_registry, which runs once per
        # agent) so every agent in the hierarchy shares the same coverage
        # state, the same single-instance-per-scan pattern firer/scope use.
        access_control_matrix_tool = build_access_control_matrix_tool()
        identities = IdentityStore()
        for identity in self.config.identities.values():
            identities.add(identity)
        sessions = SessionRegistry(graph)
        coordinator = AgentCoordinator(max_depth=self.config.spawn_max_depth)
        budget = Budget(ceiling=self.config.budget_ceiling)
        tracer = Tracer()
        system_prompt = render_prompt(
            "agent",
            engagement_scope=engagement.describe(),
            rules_of_engagement=(
                self.config.rules_of_engagement.strip()
                or "(none specified beyond the engagement scope and mission above)"
            ),
        )

        def _build_registry(agent_graph: ReachabilityGraph, self_id: str) -> ToolRegistry:
            def _run_child(child_id: str, _name: str, task: str) -> tuple[str, list[str], bool]:
                # Locked: spawn_agents can run several _run_child calls for
                # SIBLING children on real OS threads at once. agent_graph is
                # shared across them, so only the brief touches to it (the
                # before-snapshot/isolate here, the merge at the end) are
                # serialized - the long-running child_loop.run(task) below
                # operates purely on child_graph, its own private deep copy,
                # and executes fully unlocked/in parallel.
                with self._graph_lock:
                    before = set(agent_graph.nodes_of_kind(NodeKind.FINDING))
                    child_graph = isolate_for_child(agent_graph)
                child_registry = _build_registry(child_graph, child_id)
                child_loop = AgentLoop(
                    router,
                    child_registry,
                    system_prompt=system_prompt,
                    config=AgentConfig(max_steps=self.config.max_steps, is_root=False),
                    tracer=tracer,
                    budget=budget,
                    on_event=lambda ev, pl: self._on_agent_event(child_id, ev, pl),
                    should_stop=self._should_stop,
                    usage_path=self.config.usage_path,
                    agent_id=child_id,
                    get_steering=self._pending_steering,
                    pricing_table=self.config.pricing_table,
                )
                result = child_loop.run(task, journal=journal, agent_key=child_id)
                after = set(child_graph.nodes_of_kind(NodeKind.FINDING))
                new_ids = list(after - before)
                with self._graph_lock:
                    merge_finding_nodes(agent_graph, child_graph, new_ids)
                return result.summary, new_ids, result.stop_reason in _TERMINAL_SUCCESS

            # Coalesced (not passed straight to self._emit) so a single
            # verbose command's thousands of one-line chunk events can't
            # flood the shared, bounded EventLog -- see _ShellChunkCoalescer.
            shell_event_sink = _ShellChunkCoalescer(
                lambda payload: self._emit("shell", {"agent_id": self_id, **payload})
            )
            tools: list[Tool] = [
                build_run_command_tool(
                    container,
                    on_shell_event=shell_event_sink,
                ),
                build_http_tool(firer),
                build_fire_concurrent_tool(firer),
                build_diff_responses_tool(firer),
                build_raw_tcp_tool(scope),
                access_control_matrix_tool,
                build_record_finding_tool(agent_graph),
                *build_oast_tools(oast),
                build_recall_tool(skills),
                build_query_graph_tool(agent_graph),
                build_note_tool(agent_graph),
                build_recon_tool(firer, agent_graph, scope, container=container),
                build_jwt_tool(),
                build_browser_tool(browser),
            ]
            if identities.ids():
                tools.append(
                    build_login_tool(firer, identities, sessions, self.config.login_schemes)
                )
                tools.append(build_session_check_tool(firer, sessions))
            tools += [build_mcp_tool(conn) for conn in self.config.mcp_connections.values()]
            spawn_tool, view_graph_tool = build_spawn_tools(
                coordinator, _run_child, self_id=self_id
            )
            parallel_spawn_tool = build_parallel_spawn_tool(
                coordinator, _run_child, self_id=self_id
            )
            tools += [spawn_tool, parallel_spawn_tool, view_graph_tool]
            return ToolRegistry(tools)

        self._emit("status", {"event": "scan_started", "targets": self.config.target_specs})
        root_id = coordinator.register_root("root", self.config.mission)
        # Resume: reseed the child-id counter past whatever a crashed attempt
        # already used (see _max_spawned_agent_number/seed_counter's own
        # docstrings) BEFORE any live dispatch can call coordinator.spawn() --
        # a no-op on a fresh run, where the journal has no "agent-N:..." keys.
        coordinator.seed_counter(_max_spawned_agent_number(journal))
        root_registry = _build_registry(graph, root_id)
        root_loop = AgentLoop(
            router,
            root_registry,
            system_prompt=system_prompt,
            config=AgentConfig(max_steps=self.config.max_steps, is_root=True),
            tracer=tracer,
            budget=budget,
            on_event=lambda ev, pl: self._on_root_event(root_id, ev, pl, graph, graph_path),
            should_stop=self._should_stop,
            usage_path=self.config.usage_path,
            agent_id=root_id,
            get_steering=self._pending_steering,
            pricing_table=self.config.pricing_table,
        )
        # Every spawned child also journals its own steps now (agent_key=
        # child_id, wired in _run_child above), sharing this same journal
        # instance -- if a crash happens mid-child-execution, the root's own
        # not-yet-journaled spawn_agent step retries on resume, coordinator
        # child-id minting is deterministic (a fresh per-process counter
        # incremented only on real, non-replayed dispatch, so it reproduces
        # the same child_id), and the new child_loop.run() call resumes that
        # SAME child_id's own already-journaled steps instead of restarting
        # its task from scratch.
        result = root_loop.run(self.config.mission, journal=journal, agent_key="root")
        coordinator.record_result(
            root_id,
            summary=result.summary,
            finding_ids=list(graph.nodes_of_kind(NodeKind.FINDING)),
            success=result.stop_reason in _TERMINAL_SUCCESS,
        )

        for finding_id in graph.nodes_of_kind(NodeKind.FINDING):
            confidence = compute_confidence(graph, finding_id)
            review = run_adversarial_review(
                graph,
                finding_id,
                confidence,
                router,
                second_opinion=self.config.enable_second_opinion_review,
            )
            node = graph.node(finding_id)
            self._emit(
                "finding",
                {
                    "finding_id": finding_id,
                    "title": node.get("title", finding_id),
                    "severity": node.get("cvss_severity", "info"),
                    "confidence": confidence.score,
                    "verdict": review.verdict.value,
                },
            )

        for chain in graph.all_enabling_chains():
            self._emit("chain", {"node_ids": chain.node_ids})

        # Checked ahead of the ordinary stop_reason mapping: a wall-clock
        # kill goes through the exact same cooperative should_stop()/
        # "cancelled" path as a manual stop, so _terminal_status alone
        # cannot tell the two apart - this reclassifies it into its own
        # honest RunStatus rather than reporting it as an ambiguous,
        # unconfirmed stop.
        status = (
            RunStatus.WALL_CLOCK_EXCEEDED
            if self._wall_clock_exceeded
            else _terminal_status(result.stop_reason)
        )
        # Built before write_report, not after: usage_path is a LIFETIME
        # ledger potentially shared across many scans, so the report must
        # show this run's own delta, not the ledger's cumulative total -
        # exactly the subtraction the GUI's own usage_delta event already
        # does below, computed once here and reused for both.
        report_usage: ReportUsage | None = None
        usage_delta_by_agent: dict[str, dict[str, float]] | None = None
        if usage_path is not None and usage_before is not None:
            usage_after = load_usage(usage_path)
            usage_delta_by_agent = _diff_by_agent(usage_before.by_agent, usage_after.by_agent)
            report_usage = ReportUsage(
                total_requests=usage_after.total_requests - usage_before.total_requests,
                total_input_tokens=usage_after.total_input_tokens - usage_before.total_input_tokens,
                total_output_tokens=usage_after.total_output_tokens
                - usage_before.total_output_tokens,
                total_cost_usd=(
                    usage_after.total_cost_usd - usage_before.total_cost_usd
                    if self.config.pricing_table is not None
                    else None
                ),
            )
        report_paths = write_report(
            self.config.run_dir, graph, skills, status=status, usage=report_usage
        )
        write_report_manifest(self.config.run_dir, report_paths)
        graph.save(self.config.run_dir / "graph.json")
        _write_trace_file(self.config.run_dir, tracer)
        completed_payload: dict[str, object] = {
            "event": "scan_completed",
            "status": status.value,
            "report_paths": {fmt: str(path) for fmt, path in report_paths.items()},
            "trace_summary": _trace_summary(tracer),
        }
        if report_usage is not None:
            completed_payload["usage_delta"] = {
                "requests": report_usage.total_requests,
                "input_tokens": report_usage.total_input_tokens,
                "output_tokens": report_usage.total_output_tokens,
                "by_agent": usage_delta_by_agent,
            }
        self._emit("status", completed_payload)
        return ScanOutcome(status=status, result=result, report_paths=report_paths)
