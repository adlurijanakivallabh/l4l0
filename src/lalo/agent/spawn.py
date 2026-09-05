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
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Protocol, Self, runtime_checkable

from ..core.errors import SpawnDepthExceededError
from .tools import FunctionTool, Tool, ToolResult


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

    def _next_id(self) -> str:
        self._counter += 1
        return f"agent-{self._counter}"

    def register_root(self, name: str, task: str) -> str:
        agent_id = self._next_id()
        self._nodes[agent_id] = AgentNode(agent_id, name, task, parent_id=None, depth=0)
        return agent_id

    def spawn(self, parent_id: str, name: str, task: str) -> str:
        parent = self._nodes[parent_id]
        child_depth = parent.depth + 1
        if child_depth > self.max_depth:
            raise SpawnDepthExceededError(
                f"spawn depth {child_depth} exceeds ceiling {self.max_depth}"
            )
        child_id = self._next_id()
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
        node = self._nodes[agent_id]
        node.summary = summary
        node.finding_ids = list(finding_ids or [])
        node.status = AgentStatus.COMPLETED if success else AgentStatus.FAILED

    def node(self, agent_id: str) -> AgentNode:
        return self._nodes[agent_id]

    def children_of(self, agent_id: str) -> list[str]:
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
        roots = [n.id for n in self._nodes.values() if n.parent_id is None]
        lines: list[str] = []

        def render(agent_id: str, depth: int) -> None:
            node = self._nodes[agent_id]
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
        name = str(args.get("name", "")).strip()
        task = str(args.get("task", "")).strip()
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
