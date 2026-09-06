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
from collections.abc import Mapping
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from .agent.loop import AgentConfig, AgentLoop, AgentResult
from .agent.spawn import AgentCoordinator, build_spawn_tools, isolate_for_child, merge_finding_nodes
from .agent.tools import Tool, ToolRegistry
from .browser.session import BrowserSession
from .browser.tool import build_browser_tool
from .core.atomic_io import atomic_write_verified
from .core.config import load_settings
from .core.errors import (
    AllProvidersFailedError,
    ConfigError,
    ContainerError,
    ResumeConfigMismatchError,
)
from .core.model_router import ModelRouter
from .core.providers import build_router, verify_router
from .core.usage import load_usage
from .execution.firer import HttpFirer, probe_reachability
from .execution.scope import ScopeGuard
from .execution.target import Engagement
from .execution.tool import build_http_tool
from .findings.confidence import compute_confidence
from .findings.review import run_adversarial_review
from .findings.tool import build_record_finding_tool
from .graph.model import NodeKind, ReachabilityGraph
from .graph.tool import build_note_tool, build_query_graph_tool
from .identity.credentials import Identity, IdentityStore
from .identity.login import LoginScheme, SessionRegistry
from .identity.tool import build_jwt_tool, build_login_tool
from .integrations.mcp_client import MCPServerConfig, build_mcp_tool
from .oast.server import OASTServer
from .oast.tool import build_oast_tools
from .observability.tracing import Tracer
from .orchestrator.budget import Budget, RunStatus
from .orchestrator.journal import DurableJournal
from .prompts import render_prompt
from .recon.tool import build_recon_tool
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
    egress_lock: bool = False
    max_steps: int = 25
    spawn_max_depth: int = 3
    budget_ceiling: int = 300
    identities: dict[str, Identity] = field(default_factory=dict)
    login_schemes: dict[str, LoginScheme] = field(default_factory=dict)
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
    actually define WHAT is authorized (mission, targets) or toggle a safety
    control (egress_lock) are locked; operational tuning knobs are free to
    change across a resume.
    """

    mission: str
    target_specs: list[str]
    egress_lock: bool

    @classmethod
    def from_config(cls, config: ScanConfig) -> _ResumeManifest:
        return cls(
            mission=config.mission,
            target_specs=list(config.target_specs),
            egress_lock=config.egress_lock,
        )


def _manifest_path(run_dir: Path) -> Path:
    return run_dir / "resume_manifest.json"


def _journal_path(run_dir: Path) -> Path:
    return run_dir / "journal.jsonl"


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

    def cancel(self) -> None:
        self._cancelled = True
        container = self._container
        if container is not None:
            container.stop()

    def _should_stop(self) -> bool:
        return self._cancelled

    def _emit(self, category: EventCategory, payload: dict[str, object]) -> None:
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

        engagement = Engagement.from_specs(self.config.target_specs)
        scope = ScopeGuard(engagement, egress_lock=self.config.egress_lock)
        preflight_firer = HttpFirer(scope)
        try:
            reachability = probe_reachability(engagement, preflight_firer)
        finally:
            preflight_firer.close()
        for host, (reachable, reason) in reachability.items():
            if not reachable:
                self._emit(
                    "status",
                    {"event": "target_unreachable_preflight", "host": host, "reason": reason},
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
        identities = IdentityStore()
        for identity in self.config.identities.values():
            identities.add(identity)
        sessions = SessionRegistry(graph)
        coordinator = AgentCoordinator(max_depth=self.config.spawn_max_depth)
        budget = Budget(ceiling=self.config.budget_ceiling)
        tracer = Tracer()
        system_prompt = render_prompt("agent", engagement_scope=engagement.describe())

        def _build_registry(agent_graph: ReachabilityGraph, self_id: str) -> ToolRegistry:
            def _run_child(child_id: str, _name: str, task: str) -> tuple[str, list[str], bool]:
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
                )
                result = child_loop.run(task)
                after = set(child_graph.nodes_of_kind(NodeKind.FINDING))
                new_ids = list(after - before)
                merge_finding_nodes(agent_graph, child_graph, new_ids)
                return result.summary, new_ids, result.stop_reason in _TERMINAL_SUCCESS

            tools: list[Tool] = [
                build_run_command_tool(container),
                build_http_tool(firer),
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
            tools += [build_mcp_tool(conn) for conn in self.config.mcp_connections.values()]
            spawn_tool, view_graph_tool = build_spawn_tools(
                coordinator, _run_child, self_id=self_id
            )
            tools += [spawn_tool, view_graph_tool]
            return ToolRegistry(tools)

        self._emit("status", {"event": "scan_started", "targets": self.config.target_specs})
        root_id = coordinator.register_root("root", self.config.mission)
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
        )
        # Only the root agent's own steps are journaled/resumable -- a spawned
        # child still mid-execution at crash time simply restarts from scratch
        # on the next spawn_agent call (see agent/loop.py's own Phase 2 note
        # for why this granularity was chosen over threading a live journal
        # down through every descendant).
        result = root_loop.run(self.config.mission, journal=journal, agent_key="root")
        coordinator.record_result(
            root_id,
            summary=result.summary,
            finding_ids=list(graph.nodes_of_kind(NodeKind.FINDING)),
            success=result.stop_reason in _TERMINAL_SUCCESS,
        )

        for finding_id in graph.nodes_of_kind(NodeKind.FINDING):
            confidence = compute_confidence(graph, finding_id)
            review = run_adversarial_review(graph, finding_id, confidence, router)
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

        report_paths = write_report(self.config.run_dir, graph, skills)
        graph.save(self.config.run_dir / "graph.json")
        status = _terminal_status(result.stop_reason)
        completed_payload: dict[str, object] = {
            "event": "scan_completed",
            "status": status.value,
            "report_paths": {fmt: str(path) for fmt, path in report_paths.items()},
        }
        if usage_path is not None and usage_before is not None:
            usage_after = load_usage(usage_path)
            completed_payload["usage_delta"] = {
                "requests": usage_after.total_requests - usage_before.total_requests,
                "input_tokens": usage_after.total_input_tokens - usage_before.total_input_tokens,
                "output_tokens": usage_after.total_output_tokens - usage_before.total_output_tokens,
            }
        self._emit("status", completed_payload)
        return ScanOutcome(status=status, result=result, report_paths=report_paths)
