"""Multi-agent orchestration: agent-callable spawn/graph tools.

Reference reads for this phase (all five, real source): a reference tool
module's full ``agents_graph/tools.py`` (860 lines) and its coordinator
(``core/agents.py``, 578 lines) — adopted its single best idea, the
**authoritative-filed-reports pattern**: a child's own narrative summary is
never trusted as evidence of what it found; only what was actually recorded
through a real write path counts. Rejected its two weakest points: (1) a
single global coordinator/report-state object every agent (however deep)
reads and mutates directly — the shared-workspace-for-everyone pattern this
module explicitly avoids via the :class:`Isolatable` seam below; (2) no depth
ceiling anywhere in the spawn tool itself, so nothing stops runaway
grandchild-of-grandchild recursion. A second reference's child-delegation
tool (``task-tool.ts``, read in full) enforces a depth-1 cutoff the blunt way
— a child's own tool list simply excludes the delegation tool, so it can
never spawn further — which closes the same gap even more simply than a
numeric ceiling, at the cost of ever allowing deliberate multi-level
decomposition; this module keeps the more general numeric ceiling instead
(configurable, default shallow) since L4L0's mission-decomposition use case
plausibly wants more than one level. A third reference's declarative
``agents.yml`` format (read in full) confirmed the opposite extreme worth
rejecting outright: pre-declared, user-authored agent pairings are not a
runtime decision at all — L4L0's ``spawn_agent`` is deliberately
agent-callable, a live decision the model makes mid-run. A fourth
reference's ``subtask.go`` (read in full) and its ``flow.go`` worker loop
confirmed that its own two-role model has no agent-graph/dynamic-spawn
concept at all — a fixed, LLM-replanned linear subtask queue, not a tree of
spawned agents — useful as a contrast, not a source of adoptable mechanism
here.

**Deliberate scope simplification versus every reference's async/mailbox
model:** spawning here is synchronous (spawn, run the child to completion,
get its result back) rather than the concurrent parked-agent-with-a-mailbox
model every reference agent implements. This fits L4L0's own
:class:`~lalo.agent.loop.AgentLoop` (itself synchronous) and slots cleanly
into the durable journal's ``run_once`` model — each spawn is one resumable
step — without inventing an async messaging layer nothing in this phase's
verify criteria requires. True concurrent siblings, if ever needed, would be
an additive change on top of this, not a rewrite of it.

Re-verified against the full sequential five-reference cycle (this session's
standing methodology): the first reference's own ``create_agent`` tool
description (re-read in full alongside its coordinator, above) carries two
genuinely cheap, low-risk pieces of prompt-level guidance the original build
here had dropped — check ``view_agent_graph`` first so a duplicate specialist
doesn't waste turns, and state what's already known in ``task`` so a child
doesn't rediscover it — folded into ``spawn_agent``'s own tool description
below. Its per-child ``skills`` parameter (pre-declared at spawn time) was
deliberately NOT adopted: L4L0's children decide their own skill needs via
``recall`` once running, rather than having them assigned upfront. The other
four references' async inter-agent-messaging tools (send-a-message-to-any-
running-agent, wait-for-a-message) remain out of scope for the same reason
already stated above — no mailbox model exists here to hang them on.
"""

from __future__ import annotations

import json
import threading
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Protocol, Self, runtime_checkable

from ..core.errors import SpawnDepthExceededError
from ..findings.dedup import find_duplicate
from ..graph.model import NodeKind, ReachabilityGraph
from .tools import FunctionTool, Tool, ToolResult, str_arg

_MAX_PARALLEL_WORKERS = 8


class AgentStatus(StrEnum):
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


@runtime_checkable
class Isolatable(Protocol):
    """Shared state a spawned child needs its OWN independent copy of.

    Phase 7's reachability graph will implement this. Calling
    :func:`isolate_for_child` at every spawn point — instead of handing a
    child the parent's live object — is what keeps a child's mutations from
    leaking into a sibling's or the parent's view.
    """

    def snapshot(self) -> Self: ...


def isolate_for_child[T: Isolatable](state: T) -> T:
    """Return the child's own deep copy of shared state, never the parent's live object."""
    return state.snapshot()


def merge_finding_nodes(
    parent: ReachabilityGraph, child: ReachabilityGraph, finding_ids: list[str]
) -> None:
    """Copy a child's authoritative finding nodes onto the parent's graph.

    ``all_finding_ids`` (below) only ever returns the ids a child actually
    filed through ``record_finding`` — this is the other half CLAUDE.md's
    "merge only the child's authoritative finding-ids" rule needs: an id
    alone is meaningless to a report built from the PARENT's graph unless
    the finding node it names actually exists there too. Uses only the
    graph's existing public API (``node``/``has_node``/``add_node``), not a
    new bulk-copy method, since a handful of ids per spawn never needs one.
    An id already present on the parent (merged once already) is left
    untouched rather than overwritten — first writer wins. A finding whose
    id is new to the parent but whose ``dedup_key`` (class, target, param)
    already matches an existing parent finding is merged into that existing
    node instead of filed as a second one — this is the cross-agent
    counterpart of ``record_finding``'s own same-graph dedup: two
    *concurrently* spawned siblings (``spawn_agents``, below) each take
    their own isolated graph snapshot before either has merged anything
    back, so neither one's own dedup check can see the other's independent
    discovery of the exact same (class, target, param) - without this,
    parallel siblings could file the same real vulnerability twice.
    """
    for finding_id in finding_ids:
        if parent.has_node(finding_id) or not child.has_node(finding_id):
            continue
        attrs = child.node(finding_id)
        key = attrs.get("dedup_key")
        existing_id = find_duplicate(parent, key) if key else None
        if existing_id is not None:
            existing = parent.node(existing_id)
            parent.add_node(
                existing_id,
                NodeKind.FINDING,
                evidence=[*existing.get("evidence", []), *attrs.get("evidence", [])],
                identities_confirmed=sorted(
                    set(existing.get("identities_confirmed", []))
                    | set(attrs.get("identities_confirmed", []))
                ),
                reproduced=existing.get("reproduced", False) or attrs.get("reproduced", False),
                evidence_grounded=(
                    existing.get("evidence_grounded", False)
                    or attrs.get("evidence_grounded", False)
                ),
            )
            continue
        kind = NodeKind(attrs.pop("kind"))
        parent.add_node(finding_id, kind, **attrs)


@dataclass
class AgentNode:
    id: str
    name: str
    task: str
    parent_id: str | None
    depth: int
    status: AgentStatus = AgentStatus.RUNNING
    summary: str = ""
    finding_ids: list[str] = field(default_factory=list)


class AgentCoordinator:
    """Owns the spawn tree: parent/child links, the depth ceiling, and results.

    Only tracks the agent tree itself — not target/scan state, which is a
    separate concern threaded through :class:`Isolatable` instead, so this
    class stays reusable regardless of what a future phase's graph looks like.
    """

    def __init__(self, *, max_depth: int = 3) -> None:
        self.max_depth = max_depth
        self._nodes: dict[str, AgentNode] = {}
        self._counter = 0
        # Guards _counter/_nodes: multi-lane concurrent sub-agents
        # (spawn_agents, below) share ONE coordinator across every
        # concurrently-running child, and a child can itself spawn further
        # children from its own worker thread - the counter increment, the
        # dict writes, and iterating _nodes.values() (view_agent_graph can
        # run on one child's thread while another child's spawn() mutates
        # the same dict) are all unsafe against that without this.
        self._lock = threading.Lock()

    def register_root(self, name: str, task: str) -> str:
        with self._lock:
            self._counter += 1
            agent_id = f"agent-{self._counter}"
            self._nodes[agent_id] = AgentNode(agent_id, name, task, parent_id=None, depth=0)
            return agent_id

    def spawn(self, parent_id: str, name: str, task: str) -> str:
        with self._lock:
            parent = self._nodes[parent_id]
            child_depth = parent.depth + 1
            if child_depth > self.max_depth:
                raise SpawnDepthExceededError(
                    f"spawn depth {child_depth} exceeds ceiling {self.max_depth}"
                )
            self._counter += 1
            child_id = f"agent-{self._counter}"
            self._nodes[child_id] = AgentNode(
                child_id, name, task, parent_id=parent_id, depth=child_depth
            )
            return child_id

    def record_result(
        self,
        agent_id: str,
        *,
        summary: str,
        finding_ids: list[str] | None = None,
        success: bool = True,
    ) -> None:
        with self._lock:
            node = self._nodes[agent_id]
            node.summary = summary
            node.finding_ids = list(finding_ids or [])
            node.status = AgentStatus.COMPLETED if success else AgentStatus.FAILED

    def node(self, agent_id: str) -> AgentNode:
        return self._nodes[agent_id]

    def children_of(self, agent_id: str) -> list[str]:
        with self._lock:
            return [n.id for n in self._nodes.values() if n.parent_id == agent_id]

    def _subtree(self, root_id: str) -> list[str]:
        order = [root_id]
        stack = [root_id]
        while stack:
            current = stack.pop()
            for child in self.children_of(current):
                order.append(child)
                stack.append(child)
        return order

    def all_finding_ids(self, root_id: str) -> list[str]:
        """Every finding id filed anywhere in root_id's subtree, itself included.

        Reads ONLY each node's ``finding_ids`` (set exclusively by
        :meth:`record_result`) — never a node's ``summary`` prose — so a
        child's own claim of a finding it never actually registered can never
        silently count. This is the authoritative-filed-reports pattern.
        """
        ids: list[str] = []
        for agent_id in self._subtree(root_id):
            ids.extend(self._nodes[agent_id].finding_ids)
        return ids

    def render_tree(self, *, highlight: str | None = None) -> str:
        with self._lock:
            roots = [n.id for n in self._nodes.values() if n.parent_id is None]
        lines: list[str] = []

        def render(agent_id: str, depth: int) -> None:
            node = self.node(agent_id)
            marker = "  <- you" if agent_id == highlight else ""
            lines.append(f"{'  ' * depth}- {node.name} ({node.id}) [{node.status.value}]{marker}")
            for child in self.children_of(agent_id):
                render(child, depth + 1)

        for root in roots:
            render(root, 0)
        return "\n".join(lines) or "(no agents)"


ChildRunner = Callable[[str, str, str], tuple[str, list[str], bool]]


def build_spawn_tools(
    coordinator: AgentCoordinator,
    run_child: ChildRunner,
    *,
    self_id: str,
) -> tuple[Tool, Tool]:
    """Build the ``spawn_agent``/``view_agent_graph`` tools for one agent's registry.

    ``run_child(child_id, name, task) -> (summary, finding_ids, success)`` is
    the host's injected child-execution callback — build and run that child's
    own :class:`~lalo.agent.loop.AgentLoop` and return its real result. This
    keeps the tool itself free of scan-runner/threading concerns, the same
    injected-spawner seam a reference tool module uses for testability.
    """

    def _spawn(args: dict[str, object]) -> ToolResult:
        name = str_arg(args, "name").strip()
        task = str_arg(args, "task").strip()
        if not name or not task:
            return ToolResult(observation="error: 'name' and 'task' are required", ok=False)
        try:
            child_id = coordinator.spawn(self_id, name, task)
        except SpawnDepthExceededError as exc:
            return ToolResult(observation=f"error: {exc}", ok=False)
        try:
            summary, finding_ids, success = run_child(child_id, name, task)
        except Exception as exc:  # noqa: BLE001 - a crashed child must still reach a terminal
            # status, or view_agent_graph shows it "[running]" forever: nothing
            # in this module ever revisits a node once spawn() registers it.
            error = f"child crashed: {type(exc).__name__}: {exc}"
            coordinator.record_result(child_id, summary=error, finding_ids=[], success=False)
            return ToolResult(observation=f"error running child {child_id}: {error}", ok=False)
        coordinator.record_result(
            child_id, summary=summary, finding_ids=finding_ids, success=success
        )
        report = {
            "agent_id": child_id,
            "success": success,
            "summary": summary,
            "filed_finding_ids": finding_ids,
        }
        return ToolResult(observation=json.dumps(report), ok=success)

    def _view_graph(_args: dict[str, object]) -> ToolResult:
        return ToolResult(observation=coordinator.render_tree(highlight=self_id))

    spawn_tool = FunctionTool(
        name="spawn_agent",
        description=(
            "Spawn a child agent for a focused subtask; runs to completion and returns its "
            "authoritative filed finding ids — never trust its own prose as evidence. "
            "Call view_agent_graph first to confirm no existing agent already covers this "
            "scope — a duplicate specialist wastes turns. In 'task', state what is ALREADY "
            "KNOWN (what recon already mapped, which surfaces are already covered) so the "
            "child builds on it instead of rediscovering it from scratch. "
            'args: {"name": str, "task": str}'
        ),
        func=_spawn,
    )
    graph_tool = FunctionTool(
        name="view_agent_graph",
        description="View the multi-agent tree with every agent's status. args: {}",
        func=_view_graph,
    )
    return spawn_tool, graph_tool


def build_parallel_spawn_tool(
    coordinator: AgentCoordinator,
    run_child: ChildRunner,
    *,
    self_id: str,
) -> Tool:
    """Build ``spawn_agents`` — a bounded fan-out/join over the SAME
    ``run_child`` seam ``spawn_agent`` uses, additive on top of it rather
    than a replacement (see this module's own docstring: "True concurrent
    siblings, if ever needed, would be an additive change on top of
    [synchronous spawning], not a rewrite of it").

    Deliberately NOT a general async/mailbox model: this is one barrier —
    launch N independent children, wait for all of them, get every result
    back — never a park-and-poll-later primitive, matching the module
    docstring's own stated reason for not building one. Every child still
    runs its own ordinary, single-threaded :class:`~lalo.agent.loop.AgentLoop`;
    only the fan-out across children is concurrent. Each child gets its own
    ``isolate_for_child`` graph copy exactly as a serial spawn would (that
    isolation, plus this module's shared-state locks on
    :class:`AgentCoordinator`/:class:`~lalo.orchestrator.budget.Budget`/
    :class:`~lalo.observability.tracing.Tracer`, is what makes running
    several children's loops on real OS threads safe at all).
    """

    def _spawn_agents(args: dict[str, object]) -> ToolResult:
        raw_tasks = args.get("tasks")
        if not isinstance(raw_tasks, list) or len(raw_tasks) < 2:
            return ToolResult(
                observation=(
                    "error: 'tasks' must be a list of at least 2 tasks - use spawn_agent "
                    "instead for a single child"
                ),
                ok=False,
            )
        parsed: list[tuple[str, str]] = []
        for item in raw_tasks:
            if not isinstance(item, dict):
                return ToolResult(
                    observation="error: each task must be an object with 'name' and 'task'",
                    ok=False,
                )
            name = str_arg(item, "name").strip()
            task = str_arg(item, "task").strip()
            if not name or not task:
                return ToolResult(
                    observation="error: every task needs a non-empty 'name' and 'task'", ok=False
                )
            parsed.append((name, task))

        # Registered up front, sequentially, before any thread starts: every
        # task in one batch shares the exact same parent (self_id), so they
        # all pass or all fail the depth ceiling identically - no partial
        # batch to reconcile if one raised partway through.
        try:
            child_ids = [coordinator.spawn(self_id, name, task) for name, task in parsed]
        except SpawnDepthExceededError as exc:
            return ToolResult(observation=f"error: {exc}", ok=False)

        def _run_one(child_id: str, name: str, task: str) -> tuple[str, bool, str, list[str]]:
            try:
                summary, finding_ids, success = run_child(child_id, name, task)
            except Exception as exc:  # noqa: BLE001 - a crashed child must still reach a
                # terminal status, matching spawn_agent's own crash handling.
                return child_id, False, f"child crashed: {type(exc).__name__}: {exc}", []
            return child_id, success, summary, finding_ids

        with ThreadPoolExecutor(max_workers=min(len(parsed), _MAX_PARALLEL_WORKERS)) as pool:
            futures = [
                pool.submit(_run_one, child_id, name, task)
                for child_id, (name, task) in zip(child_ids, parsed, strict=True)
            ]
            results = [future.result() for future in futures]

        reports = []
        overall_ok = True
        for child_id, success, summary, finding_ids in results:
            coordinator.record_result(
                child_id, summary=summary, finding_ids=finding_ids, success=success
            )
            reports.append(
                {
                    "agent_id": child_id,
                    "success": success,
                    "summary": summary,
                    "filed_finding_ids": finding_ids,
                }
            )
            overall_ok = overall_ok and success
        return ToolResult(observation=json.dumps(reports), ok=overall_ok)

    return FunctionTool(
        name="spawn_agents",
        description=(
            "Spawn 2+ independent child agents to run CONCURRENTLY, then wait for all of "
            "them and get every result back at once - for genuinely independent lines of "
            "investigation (e.g. the same vuln class across several distinct hosts) that "
            "don't depend on each other's findings. Use spawn_agent instead for a single "
            "child, or when a later child's task depends on an earlier one's result. "
            'args: {"tasks": [{"name": str, "task": str}, ...]} (at least 2 entries)'
        ),
        func=_spawn_agents,
    )
