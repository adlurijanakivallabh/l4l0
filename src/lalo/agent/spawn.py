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
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Protocol, Self, runtime_checkable

from ..core.errors import SpawnDepthExceededError
from ..findings.dedup import find_duplicate
from ..graph.model import NodeKind, ReachabilityGraph
from ..skills.recall import token_overlap_ratio
from .tools import FunctionTool, Tool, ToolResult, str_arg

_MAX_PARALLEL_WORKERS = 8
_DUPLICATE_TASK_SIMILARITY_THRESHOLD = 0.6


class AgentStatus(StrEnum):
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    ORPHANED = "orphaned"


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
    role: str = "full"
    stop_reason: str = ""


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
        self._stopped: set[str] = set()
        self._pending: dict[str, Future[tuple[str, list[str], bool]]] = {}
        self._executor = ThreadPoolExecutor(max_workers=_MAX_PARALLEL_WORKERS)

    def seed_counter(self, minimum: int) -> None:
        """Advance the child-id counter to at least ``minimum``, never lower it.

        On a resumed process this counter starts fresh at 0 with no memory of
        ids a crashed attempt's already-journaled spawn steps used — those
        steps are replayed straight from the journal (see agent/loop.py's
        resume-replay loop) without ever calling :meth:`spawn` again, so the
        counter is under-incremented relative to the journal's own recorded
        ``agent-N:...`` keys. Called once, right after :meth:`register_root`
        and before any live dispatch can call :meth:`spawn`, seeded from the
        max N already present in the journal — otherwise the next genuinely
        new spawn mints an already-used id and its child_loop's own
        resume-replay silently splices an unrelated prior child's transcript
        into a brand-new task.
        """
        with self._lock:
            self._counter = max(self._counter, minimum)

    def register_root(self, name: str, task: str) -> str:
        with self._lock:
            self._counter += 1
            agent_id = f"agent-{self._counter}"
            self._nodes[agent_id] = AgentNode(agent_id, name, task, parent_id=None, depth=0)
            return agent_id

    def spawn(self, parent_id: str, name: str, task: str, *, role: str = "full") -> str:
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
                child_id, name, task, parent_id=parent_id, depth=child_depth, role=role
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

    def mark_stopped(self, agent_id: str, reason: str) -> None:
        with self._lock:
            self._stopped.add(agent_id)
            node = self._nodes.get(agent_id)
            if node is not None:
                node.stop_reason = reason

    def is_stopped(self, agent_id: str) -> bool:
        with self._lock:
            return agent_id in self._stopped

    def submit_background(
        self, agent_id: str, run: Callable[[], tuple[str, list[str], bool]]
    ) -> None:
        with self._lock:
            self._pending[agent_id] = self._executor.submit(run)

    def wait_for(
        self, agent_id: str, timeout: float | None = None
    ) -> tuple[str, list[str], bool] | None:
        with self._lock:
            future = self._pending.get(agent_id)
        if future is None:
            return None
        # Only popped once the result is actually in hand: a caller-supplied
        # timeout that expires raises TimeoutError before this line, leaving
        # the future in _pending so a later, unhurried wait_for(agent_id) can
        # still retry and join it - popping unconditionally up front (as a
        # first version of this did) would have discarded it right away,
        # permanently misreporting a merely-slow background agent as unknown/
        # already-awaited even though it was still alive and would finish.
        result = future.result(timeout=timeout)
        with self._lock:
            self._pending.pop(agent_id, None)
        return result

    def close(self) -> None:
        self._executor.shutdown(wait=False, cancel_futures=True)

    def node(self, agent_id: str) -> AgentNode:
        return self._nodes[agent_id]

    def has_node(self, agent_id: str) -> bool:
        return agent_id in self._nodes

    def register_orphan(
        self,
        agent_id: str,
        name: str,
        task: str,
        *,
        parent_id: str | None,
        depth: int,
        role: str,
    ) -> None:
        """Reconstruct a child that was genuinely mid-execution when the
        process crashed - its own journal entries survive under its
        original agent_id, but nothing durable ever recorded it as a node
        in THIS coordinator (a fresh instance every process start). Called
        once per detected orphan, before any live dispatch, from
        scan.py's own resume path - see _find_orphaned_children there.
        """
        with self._lock:
            self._nodes[agent_id] = AgentNode(
                agent_id,
                name,
                task,
                parent_id=parent_id,
                depth=depth,
                status=AgentStatus.ORPHANED,
                role=role,
            )

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


def _duplicate_task_warning(
    coordinator: AgentCoordinator, self_id: str, task: str, extra_tasks: tuple[str, ...] = ()
) -> str:
    """Warn, never block, when ``task`` looks like a near-duplicate of an
    already-spawned sibling's task, or of another task in the same
    ``spawn_agents`` batch (``extra_tasks``) - a running-siblings-only check
    would miss the latter, since batch siblings aren't registered with the
    coordinator until after every task in the batch is already collected.
    """
    for other_id in coordinator.children_of(self_id):
        other_task = coordinator.node(other_id).task
        if token_overlap_ratio(task, other_task) >= _DUPLICATE_TASK_SIMILARITY_THRESHOLD:
            return (
                f"warning: this task looks similar to running agent {other_id}'s task "
                f"({other_task!r}) - confirm this isn't a duplicate before proceeding.\n"
            )
    for other_task in extra_tasks:
        if token_overlap_ratio(task, other_task) >= _DUPLICATE_TASK_SIMILARITY_THRESHOLD:
            return (
                f"warning: this task looks similar to another task in the same batch "
                f"({other_task!r}) - confirm this isn't a duplicate before proceeding.\n"
            )
    return ""


def build_spawn_tools(
    coordinator: AgentCoordinator,
    run_child: ChildRunner,
    *,
    self_id: str,
    valid_roles: frozenset[str] = frozenset({"full"}),
) -> tuple[Tool, Tool, Tool]:
    """Build the ``spawn_agent``/``view_agent_graph``/``stop_agent`` tools for one agent's registry.

    ``run_child(child_id, name, task) -> (summary, finding_ids, success)`` is
    the host's injected child-execution callback — build and run that child's
    own :class:`~lalo.agent.loop.AgentLoop` and return its real result. This
    keeps the tool itself free of scan-runner/threading concerns, the same
    injected-spawner seam a reference tool module uses for testability.
    """

    def _spawn(args: dict[str, object]) -> ToolResult:
        resume_agent_id = str_arg(args, "resume_agent_id", "").strip()
        if resume_agent_id:
            if not coordinator.has_node(resume_agent_id):
                return ToolResult(
                    observation=(
                        f"error: {resume_agent_id!r} is not a known agent - "
                        "call view_agent_graph to see valid ids"
                    ),
                    ok=False,
                )
            node = coordinator.node(resume_agent_id)
            if node.status is not AgentStatus.ORPHANED:
                return ToolResult(
                    observation=(
                        f"error: {resume_agent_id!r} is not orphaned (status: "
                        f"{node.status.value}) - only an orphaned agent can be resumed"
                    ),
                    ok=False,
                )
            try:
                summary, finding_ids, success = run_child(resume_agent_id, node.name, node.task)
            except Exception as exc:  # noqa: BLE001 - a crashed child must still reach a
                # terminal status, matching the fresh-spawn path's own crash handling.
                error = f"child crashed: {type(exc).__name__}: {exc}"
                coordinator.record_result(
                    resume_agent_id, summary=error, finding_ids=[], success=False
                )
                return ToolResult(
                    observation=f"error resuming {resume_agent_id}: {error}", ok=False
                )
            coordinator.record_result(
                resume_agent_id, summary=summary, finding_ids=finding_ids, success=success
            )
            report = {
                "agent_id": resume_agent_id,
                "success": success,
                "summary": summary,
                "filed_finding_ids": finding_ids,
            }
            return ToolResult(observation=json.dumps(report), ok=success)

        name = str_arg(args, "name").strip()
        task = str_arg(args, "task").strip()
        role = str_arg(args, "role", "full").strip() or "full"
        if not name or not task:
            return ToolResult(observation="error: 'name' and 'task' are required", ok=False)
        if role not in valid_roles:
            return ToolResult(
                observation=f"error: 'role' must be one of {sorted(valid_roles)}", ok=False
            )
        warning = _duplicate_task_warning(coordinator, self_id, task)
        try:
            child_id = coordinator.spawn(self_id, name, task, role=role)
        except SpawnDepthExceededError as exc:
            return ToolResult(observation=f"error: {exc}", ok=False)
        background = bool(args.get("background", False))
        if background:

            def _run_background(
                _child_id: str = child_id, _name: str = name, _task: str = task
            ) -> tuple[str, list[str], bool]:
                try:
                    return run_child(_child_id, _name, _task)
                except Exception as exc:  # noqa: BLE001 - matches the synchronous path's
                    # own crash handling: a crashed background child must still resolve
                    # to a terminal tuple, never leave wait_for_agents hanging on an
                    # exception it has to catch itself.
                    return f"child crashed: {type(exc).__name__}: {exc}", [], False

            coordinator.submit_background(child_id, _run_background)
            return ToolResult(
                observation=(
                    f"{warning}started {child_id} in the background - call wait_for_agents "
                    f"with this agent_id once you need its result, or stop_agent to cancel it"
                ),
                ok=True,
            )
        try:
            summary, finding_ids, success = run_child(child_id, name, task)
        except Exception as exc:  # noqa: BLE001 - a crashed child must still reach a terminal
            # status, or view_agent_graph shows it "[running]" forever: nothing
            # in this module ever revisits a node once spawn() registers it.
            error = f"child crashed: {type(exc).__name__}: {exc}"
            coordinator.record_result(child_id, summary=error, finding_ids=[], success=False)
            return ToolResult(
                observation=f"{warning}error running child {child_id}: {error}", ok=False
            )
        coordinator.record_result(
            child_id, summary=summary, finding_ids=finding_ids, success=success
        )
        report = {
            "agent_id": child_id,
            "success": success,
            "summary": summary,
            "filed_finding_ids": finding_ids,
        }
        return ToolResult(observation=f"{warning}{json.dumps(report)}", ok=success)

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
            'args: {"name": str, "task": str, "role": "full"|"source_reviewer"|'
            '"dependency_analyst" (optional, '
            'default "full" - source_reviewer confines the child to run_command/'
            "record_finding/recall/query_graph/note only, no live-firing tools and no "
            "further spawning - use it for a subtask that's purely reading and reasoning "
            "about source code; dependency_analyst is the same confinement plus "
            "coverage_ledger, for manifest discovery/SCA-scanner/reachability-triage "
            'subtasks), "resume_agent_id": str (optional - resume an orphaned '
            "agent shown by view_agent_graph as [orphaned] (interrupted by a crash on a "
            "prior run) instead of starting a new one; when set, 'name'/'task'/'role' are "
            "ignored and the agent's own original task continues from its last completed "
            'step), "background": bool (optional, default false - when true, returns '
            "this agent's id immediately without waiting for it to finish; use "
            "wait_for_agents to get its result once you need it)}"
        ),
        func=_spawn,
    )
    graph_tool = FunctionTool(
        name="view_agent_graph",
        description="View the multi-agent tree with every agent's status. args: {}",
        func=_view_graph,
    )

    def _stop_agent(args: dict[str, object]) -> ToolResult:
        agent_id = str_arg(args, "agent_id", "").strip()
        reason = str_arg(args, "reason", "no reason given").strip()
        if not agent_id:
            return ToolResult(observation="error: 'agent_id' is required", ok=False)
        if not coordinator.has_node(agent_id):
            return ToolResult(
                observation=f"error: {agent_id!r} is not a known agent - "
                "call view_agent_graph to see valid ids",
                ok=False,
            )
        node = coordinator.node(agent_id)
        if node.status is not AgentStatus.RUNNING:
            return ToolResult(
                observation=f"error: {agent_id!r} is not running (status: "
                f"{node.status.value}) - only a running agent can be stopped",
                ok=False,
            )
        coordinator.mark_stopped(agent_id, reason)
        return ToolResult(
            observation=f"requested stop for {agent_id}: {reason} - it will stop at its "
            "next checkpoint, not necessarily instantly"
        )

    stop_tool = FunctionTool(
        name="stop_agent",
        description=(
            "Request that a running agent (yours or any descendant, per view_agent_graph) "
            "stop at its next checkpoint - e.g. a duplicate specialist, or one whose task "
            "is now known to be moot. Cooperative, not instant. args: "
            '{"agent_id": str, "reason": str}'
        ),
        func=_stop_agent,
    )
    return spawn_tool, graph_tool, stop_tool


def build_wait_for_agents_tool(coordinator: AgentCoordinator) -> Tool:
    """Join specific background-spawned children (see ``spawn_agent``'s ``background``
    arg) and get each one's authoritative result, without touching ``spawn_agents``'
    own separate wait-for-all-then-join-every-result barrier semantics.
    """

    def _wait(args: dict[str, object]) -> ToolResult:
        raw_ids = args.get("agent_ids")
        if not isinstance(raw_ids, list) or not raw_ids:
            return ToolResult(observation="error: 'agent_ids' must be a non-empty list", ok=False)
        reports: list[dict[str, object]] = []
        overall_ok = True
        for raw in raw_ids:
            agent_id = str(raw)
            result = coordinator.wait_for(agent_id)
            if result is None:
                reports.append(
                    {
                        "agent_id": agent_id,
                        "error": "not a background-spawned agent, or already awaited elsewhere",
                    }
                )
                overall_ok = False
                continue
            summary, finding_ids, success = result
            coordinator.record_result(
                agent_id, summary=summary, finding_ids=finding_ids, success=success
            )
            reports.append(
                {
                    "agent_id": agent_id,
                    "success": success,
                    "summary": summary,
                    "filed_finding_ids": finding_ids,
                }
            )
            overall_ok = overall_ok and success
        return ToolResult(observation=json.dumps(reports), ok=overall_ok)

    return FunctionTool(
        name="wait_for_agents",
        description=(
            "Block until every listed background-spawned agent (see spawn_agent's "
            "'background' arg) finishes, and get each one's authoritative result. "
            'args: {"agent_ids": list[str]}'
        ),
        func=_wait,
    )


def build_parallel_spawn_tool(
    coordinator: AgentCoordinator,
    run_child: ChildRunner,
    *,
    self_id: str,
    valid_roles: frozenset[str] = frozenset({"full"}),
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
        parsed: list[tuple[str, str, str]] = []
        for item in raw_tasks:
            if not isinstance(item, dict):
                return ToolResult(
                    observation="error: each task must be an object with 'name' and 'task'",
                    ok=False,
                )
            name = str_arg(item, "name").strip()
            task = str_arg(item, "task").strip()
            role = str_arg(item, "role", "full").strip() or "full"
            if not name or not task:
                return ToolResult(
                    observation="error: every task needs a non-empty 'name' and 'task'", ok=False
                )
            if role not in valid_roles:
                return ToolResult(
                    observation=f"error: 'role' must be one of {sorted(valid_roles)}", ok=False
                )
            parsed.append((name, task, role))

        warnings = [
            _duplicate_task_warning(
                coordinator,
                self_id,
                task,
                extra_tasks=tuple(t for j, (_, t, _r) in enumerate(parsed) if j != i),
            )
            for i, (_, task, _role) in enumerate(parsed)
        ]

        # Registered up front, sequentially, before any thread starts: every
        # task in one batch shares the exact same parent (self_id), so they
        # all pass or all fail the depth ceiling identically - no partial
        # batch to reconcile if one raised partway through.
        try:
            child_ids = [
                coordinator.spawn(self_id, name, task, role=role) for name, task, role in parsed
            ]
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
                for child_id, (name, task, _role) in zip(child_ids, parsed, strict=True)
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
        return ToolResult(
            observation=f"{''.join(w for w in warnings if w)}{json.dumps(reports)}", ok=overall_ok
        )

    return FunctionTool(
        name="spawn_agents",
        description=(
            "Spawn 2+ independent child agents to run CONCURRENTLY, then wait for all of "
            "them and get every result back at once - for genuinely independent lines of "
            "investigation (e.g. the same vuln class across several distinct hosts) that "
            "don't depend on each other's findings. Use spawn_agent instead for a single "
            "child, or when a later child's task depends on an earlier one's result. "
            'args: {"tasks": [{"name": str, "task": str, "role": '
            '"full"|"source_reviewer"|"dependency_analyst" '
            '(optional, default "full", same meaning as spawn_agent\'s own role arg)}, ...]} '
            "(at least 2 entries)"
        ),
        func=_spawn_agents,
    )
