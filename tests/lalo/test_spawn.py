"""Tests for multi-agent spawn: depth ceiling, authoritative merge, isolation."""

from __future__ import annotations

from dataclasses import dataclass, field

import pytest

from lalo.agent.spawn import AgentCoordinator, AgentStatus, build_spawn_tools, isolate_for_child
from lalo.agent.tools import ToolRegistry
from lalo.core.errors import SpawnDepthExceededError


def test_spawn_increases_depth_from_parent() -> None:
    coord = AgentCoordinator(max_depth=5)
    root = coord.register_root("root", "do the thing")
    child = coord.spawn(root, "child", "sub thing")
    assert coord.node(child).depth == 1
    assert coord.node(root).depth == 0


def test_spawn_depth_ceiling_is_enforced() -> None:
    coord = AgentCoordinator(max_depth=1)
    root = coord.register_root("root", "mission")
    child = coord.spawn(root, "child", "subtask")  # depth 1, allowed
    with pytest.raises(SpawnDepthExceededError):
        coord.spawn(child, "grandchild", "sub-subtask")  # depth 2, exceeds ceiling of 1


def test_authoritative_finding_ids_ignore_prose_claims() -> None:
    coord = AgentCoordinator()
    root = coord.register_root("root", "mission")
    child = coord.spawn(root, "child", "subtask")
    # The child's own narrative claims a finding it never actually registered.
    coord.record_result(child, summary="I found a critical XSS!", finding_ids=[])
    assert coord.all_finding_ids(root) == []


def test_authoritative_finding_ids_include_real_registrations() -> None:
    coord = AgentCoordinator()
    root = coord.register_root("root", "mission")
    child = coord.spawn(root, "child", "subtask")
    coord.record_result(child, summary="confirmed", finding_ids=["f-1", "f-2"])
    assert coord.all_finding_ids(root) == ["f-1", "f-2"]


def test_all_finding_ids_walks_the_whole_subtree() -> None:
    coord = AgentCoordinator(max_depth=5)
    root = coord.register_root("root", "mission")
    child = coord.spawn(root, "child", "subtask")
    grandchild = coord.spawn(child, "grandchild", "sub-subtask")
    coord.record_result(root, summary="root work", finding_ids=["f-root"])
    coord.record_result(child, summary="child work", finding_ids=["f-child"])
    coord.record_result(grandchild, summary="grandchild work", finding_ids=["f-grandchild"])
    assert set(coord.all_finding_ids(root)) == {"f-root", "f-child", "f-grandchild"}


def test_record_result_marks_failure_status() -> None:
    coord = AgentCoordinator()
    root = coord.register_root("root", "mission")
    child = coord.spawn(root, "child", "subtask")
    coord.record_result(child, summary="hit a wall", finding_ids=[], success=False)
    assert coord.node(child).status is AgentStatus.FAILED


def test_render_tree_shows_hierarchy_status_and_highlight() -> None:
    coord = AgentCoordinator(max_depth=5)
    root = coord.register_root("root", "mission")
    child = coord.spawn(root, "child", "subtask")
    coord.record_result(child, summary="done", finding_ids=[])
    tree = coord.render_tree(highlight=child)
    assert "root (agent-1) [running]" in tree
    assert "child (agent-2) [completed]" in tree
    assert "<- you" in tree
    # child line is indented under root
    child_line = next(line for line in tree.splitlines() if "child" in line)
    assert child_line.startswith("  -")


@dataclass
class _FakeGraph:
    items: list[str] = field(default_factory=list)

    def snapshot(self) -> _FakeGraph:
        return _FakeGraph(items=list(self.items))


def test_isolate_for_child_returns_an_independent_copy() -> None:
    parent_state = _FakeGraph(items=["a"])
    child_state = isolate_for_child(parent_state)
    child_state.items.append("b")
    assert parent_state.items == ["a"]  # the parent's copy is untouched
    assert child_state.items == ["a", "b"]


def test_build_spawn_tools_dispatches_a_real_child_run() -> None:
    coord = AgentCoordinator(max_depth=5)
    root = coord.register_root("root", "mission")
    calls: list[tuple[str, str, str]] = []

    def run_child(child_id: str, name: str, task: str) -> tuple[str, list[str], bool]:
        calls.append((child_id, name, task))
        return "confirmed the bug", ["f-9"], True

    spawn_tool, graph_tool = build_spawn_tools(coord, run_child, self_id=root)
    registry = ToolRegistry([spawn_tool, graph_tool])

    result = registry.dispatch("spawn_agent", {"name": "XSS Specialist", "task": "test /search"})
    assert result.ok is True
    assert "f-9" in result.observation
    assert calls == [("agent-2", "XSS Specialist", "test /search")]
    assert coord.all_finding_ids(root) == ["f-9"]

    graph_result = registry.dispatch("view_agent_graph", {})
    assert "XSS Specialist" in graph_result.observation


def test_spawn_agent_tool_requires_name_and_task() -> None:
    coord = AgentCoordinator()
    root = coord.register_root("root", "mission")
    spawn_tool, _ = build_spawn_tools(coord, lambda *_a: ("", [], True), self_id=root)
    registry = ToolRegistry([spawn_tool])
    result = registry.dispatch("spawn_agent", {"name": "", "task": ""})
    assert result.ok is False


def test_spawn_agent_tool_reports_depth_ceiling_as_a_failed_result_not_an_exception() -> None:
    coord = AgentCoordinator(max_depth=0)
    root = coord.register_root("root", "mission")
    spawn_tool, _ = build_spawn_tools(coord, lambda *_a: ("", [], True), self_id=root)
    registry = ToolRegistry([spawn_tool])
    result = registry.dispatch("spawn_agent", {"name": "child", "task": "subtask"})
    assert result.ok is False
    assert "depth" in result.observation


def test_a_crashing_child_still_reaches_a_terminal_status_not_a_permanent_ghost() -> None:
    # Before the fix, an exception from run_child() skipped record_result()
    # entirely, leaving the child's AgentNode stuck at RUNNING forever --
    # view_agent_graph would show a dead agent as "[running]" indefinitely.
    coord = AgentCoordinator(max_depth=5)
    root = coord.register_root("root", "mission")

    def crashing_run_child(child_id: str, name: str, task: str) -> tuple[str, list[str], bool]:
        raise RuntimeError("child agent loop crashed")

    spawn_tool, _ = build_spawn_tools(coord, crashing_run_child, self_id=root)
    registry = ToolRegistry([spawn_tool])

    result = registry.dispatch("spawn_agent", {"name": "child", "task": "subtask"})
    assert result.ok is False
    assert "crashed" in result.observation

    child_id = "agent-2"
    assert coord.node(child_id).status is AgentStatus.FAILED
    assert coord.node(child_id).status is not AgentStatus.RUNNING
    assert "[failed]" in coord.render_tree()
