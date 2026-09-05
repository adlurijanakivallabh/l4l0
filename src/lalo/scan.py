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
A concrete :class:`~lalo.recon.runner.ReconRunner` (nmap, via
:mod:`lalo.recon.scan`, wired into the ``recon`` tool's own ``scan_ports``
action) closes the gap this docstring originally described as out of scope —
built afterward, in direct response to today's own live end-to-end run
against a local target, not as part of this module's original pass. A
browser-automation tool remains out of scope: the free shell (``run_command``)
already covers ad-hoc external tool use, and building one would be a new
subsystem, not wiring.

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

from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from .agent.loop import AgentConfig, AgentLoop, AgentResult
from .agent.spawn import AgentCoordinator, build_spawn_tools, isolate_for_child, merge_finding_nodes
from .agent.tools import Tool, ToolRegistry
from .core.config import load_settings
from .core.errors import ConfigError, ContainerError
from .core.model_router import ModelRouter
from .core.providers import build_router
from .execution.firer import HttpFirer
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
from .oast.server import OASTServer
from .oast.tool import build_oast_tools
from .observability.tracing import Tracer
from .orchestrator.budget import Budget, RunStatus
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
    container_config: RuntimeConfig | None = None


@dataclass
class ScanOutcome:
    status: RunStatus
    result: AgentResult
    report_paths: dict[str, Path]


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
    request cooperative early termination."""

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

    def cancel(self) -> None:
        self._cancelled = True

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

    def run(self) -> ScanOutcome:
        settings = load_settings(self._env)
        if not settings.resolved:
            raise ConfigError(
                "no LLM provider credentials configured - set one of: "
                + ", ".join(sorted(settings.missing_credential_hints().values()))
            )
        router = build_router(settings)

        engagement = Engagement.from_specs(self.config.target_specs)
        scope = ScopeGuard(engagement, egress_lock=self.config.egress_lock)

        if not docker_available():
            raise ContainerError(
                "docker is not reachable - the disposable runtime container "
                "cannot start, and L4L0 never runs the free shell without it"
            )

        container = RuntimeContainer(self.config.container_config)
        container.start()
        try:
            oast = OASTServer()
            oast.start()
            try:
                return self._run_inside(router, scope, engagement, container, oast)
            finally:
                oast.stop()
        finally:
            container.stop()

    def _run_inside(
        self,
        router: ModelRouter,
        scope: ScopeGuard,
        engagement: Engagement,
        container: RuntimeContainer,
        oast: OASTServer,
    ) -> ScanOutcome:
        graph = ReachabilityGraph()
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
            ]
            if identities.ids():
                tools.append(
                    build_login_tool(firer, identities, sessions, self.config.login_schemes)
                )
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
            on_event=lambda ev, pl: self._on_agent_event(root_id, ev, pl),
            should_stop=self._should_stop,
        )
        result = root_loop.run(self.config.mission)
        coordinator.record_result(
            root_id,
            summary=result.summary,
            finding_ids=list(graph.nodes_of_kind(NodeKind.FINDING)),
            success=result.stop_reason in _TERMINAL_SUCCESS,
        )

        for finding_id in graph.nodes_of_kind(NodeKind.FINDING):
            confidence = compute_confidence(graph, finding_id)
            review = run_adversarial_review(graph, finding_id, confidence, router)
            self._emit(
                "finding",
                {
                    "finding_id": finding_id,
                    "confidence": confidence.score,
                    "verdict": review.verdict.value,
                },
            )

        report_paths = write_report(self.config.run_dir, graph, skills)
        graph.save(self.config.run_dir / "graph.json")
        status = _terminal_status(result.stop_reason)
        self._emit("status", {"event": "scan_completed", "status": status.value})
        return ScanOutcome(status=status, result=result, report_paths=report_paths)
