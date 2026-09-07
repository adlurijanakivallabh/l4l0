"""Tests for multi-agent spawn: depth ceiling, authoritative merge, isolation."""

from __future__ import annotations

import threading
from dataclasses import dataclass, field

import pytest

from lalo.agent.spawn import (
    AgentCoordinator,
    AgentStatus,
    build_parallel_spawn_tool,
    build_spawn_tools,
    isolate_for_child,
    merge_finding_nodes,
)
from lalo.agent.tools import ToolRegistry
from lalo.core.errors import SpawnDepthExceededError
from lalo.graph.model import NodeKind, ReachabilityGraph


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


def test_spawn_agent_tool_requires_name_and_task_even_as_explicit_json_null() -> None:
    """An explicit JSON null must be treated the same as an absent/empty
    field, not stringified into the literal, non-empty "None"."""
    coord = AgentCoordinator()
    root = coord.register_root("root", "mission")
    spawn_tool, _ = build_spawn_tools(coord, lambda *_a: ("", [], True), self_id=root)
    registry = ToolRegistry([spawn_tool])
    result = registry.dispatch("spawn_agent", {"name": None, "task": None})
    assert result.ok is False


def test_spawn_agent_tool_reports_depth_ceiling_as_a_failed_result_not_an_exception() -> None:
    coord = AgentCoordinator(max_depth=0)
    root = coord.register_root("root", "mission")
    spawn_tool, _ = build_spawn_tools(coord, lambda *_a: ("", [], True), self_id=root)
    registry = ToolRegistry([spawn_tool])
    result = registry.dispatch("spawn_agent", {"name": "child", "task": "subtask"})
    assert result.ok is False
    assert "depth" in result.observation


def test_spawn_warns_on_a_near_duplicate_sibling_task_but_still_succeeds() -> None:
    coord = AgentCoordinator(max_depth=5)
    root = coord.register_root("root", "mission")

    def run_child(child_id: str, name: str, task: str) -> tuple[str, list[str], bool]:
        return "confirmed", [], True

    spawn_tool, _ = build_spawn_tools(coord, run_child, self_id=root)
    registry = ToolRegistry([spawn_tool])

    first = registry.dispatch(
        "spawn_agent",
        {"name": "S3 Specialist", "task": "enumerate S3 buckets for public read access"},
    )
    assert first.ok is True
    assert "warning" not in first.observation

    second = registry.dispatch(
        "spawn_agent",
        {"name": "S3 Specialist Duplicate", "task": "enumerate S3 buckets for public read access"},
    )
    # Never a hard block: the second spawn must still succeed.
    assert second.ok is True
    assert "warning" in second.observation
    assert "agent-2" in second.observation  # names the similar sibling


def test_spawn_does_not_warn_on_unrelated_sibling_tasks() -> None:
    coord = AgentCoordinator(max_depth=5)
    root = coord.register_root("root", "mission")

    def run_child(child_id: str, name: str, task: str) -> tuple[str, list[str], bool]:
        return "confirmed", [], True

    spawn_tool, _ = build_spawn_tools(coord, run_child, self_id=root)
    registry = ToolRegistry([spawn_tool])

    registry.dispatch("spawn_agent", {"name": "S3 Specialist", "task": "enumerate S3 buckets"})
    second = registry.dispatch(
        "spawn_agent", {"name": "SQLi Specialist", "task": "fuzz the login form for SQL injection"}
    )
    assert second.ok is True
    assert "warning" not in second.observation


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


# --- AgentCoordinator: thread safety for multi-lane concurrent sub-agents ---


def test_agent_coordinator_spawn_is_thread_safe_under_concurrent_calls() -> None:
    """Without the lock, _counter += 1 from N threads loses increments and
    can hand out duplicate agent ids - both silently corrupt the spawn tree."""
    coord = AgentCoordinator(max_depth=5)
    root = coord.register_root("root", "mission")
    child_ids: list[str] = []
    lock = threading.Lock()

    def spawn_one() -> None:
        child_id = coord.spawn(root, "child", "subtask")
        with lock:
            child_ids.append(child_id)

    threads = [threading.Thread(target=spawn_one) for _ in range(50)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(child_ids) == 50
    assert len(set(child_ids)) == 50  # every id unique - no lost/duplicate increments
    assert len(coord.children_of(root)) == 50


# --- merge_finding_nodes: cross-child dedup ---------------------------------


def _finding_node(graph: ReachabilityGraph, node_id: str, **overrides: object) -> None:
    attrs: dict[str, object] = {
        "title": "SQLi in /search",
        "vuln_class": "sql-injection",
        "target": "https://x.example.com/search",
        "dedup_key": '["sql-injection", "https://x.example.com/search", ""]',
        "evidence": ["e1"],
        "identities_confirmed": [],
        "reproduced": False,
        "evidence_grounded": True,
    }
    attrs.update(overrides)
    graph.add_node(node_id, NodeKind.FINDING, **attrs)


def test_merge_finding_nodes_merges_a_dedup_key_match_instead_of_filing_a_second_node() -> None:
    parent = ReachabilityGraph()
    _finding_node(parent, "f-existing", evidence=["from-sibling-a"])
    child = ReachabilityGraph()
    _finding_node(child, "f-new", evidence=["from-sibling-b"])

    merge_finding_nodes(parent, child, ["f-new"])

    assert not parent.has_node("f-new")  # never filed as a second node
    merged = parent.node("f-existing")
    assert set(merged["evidence"]) == {"from-sibling-a", "from-sibling-b"}


def test_merge_finding_nodes_or_combines_reproduced_and_evidence_grounded() -> None:
    parent = ReachabilityGraph()
    _finding_node(parent, "f-existing", reproduced=False, evidence_grounded=False)
    child = ReachabilityGraph()
    _finding_node(child, "f-new", reproduced=True, evidence_grounded=True)

    merge_finding_nodes(parent, child, ["f-new"])

    merged = parent.node("f-existing")
    assert merged["reproduced"] is True
    assert merged["evidence_grounded"] is True


def test_merge_finding_nodes_unions_identities_confirmed() -> None:
    parent = ReachabilityGraph()
    _finding_node(parent, "f-existing", identities_confirmed=["alice"])
    child = ReachabilityGraph()
    _finding_node(child, "f-new", identities_confirmed=["bob"])

    merge_finding_nodes(parent, child, ["f-new"])

    assert parent.node("f-existing")["identities_confirmed"] == ["alice", "bob"]


def test_merge_finding_nodes_with_no_dedup_key_match_adds_a_new_node() -> None:
    parent = ReachabilityGraph()
    child = ReachabilityGraph()
    _finding_node(child, "f-new", dedup_key='["xss", "https://x.example.com/other", ""]')

    merge_finding_nodes(parent, child, ["f-new"])

    assert parent.has_node("f-new")
    assert parent.node("f-new")["vuln_class"] == "sql-injection"


def test_merge_finding_nodes_is_idempotent_for_an_id_already_on_the_parent() -> None:
    parent = ReachabilityGraph()
    _finding_node(parent, "f-1", evidence=["original"])
    child = ReachabilityGraph()
    _finding_node(child, "f-1", evidence=["should never be seen"])

    merge_finding_nodes(parent, child, ["f-1"])

    assert parent.node("f-1")["evidence"] == ["original"]


# --- spawn_agents: bounded parallel fan-out/join ----------------------------


def test_spawn_agents_actually_runs_children_concurrently_not_serially() -> None:
    """If this ran children one at a time, the first one's barrier.wait()
    would block until the 5s timeout and raise BrokenBarrierError - the only
    way all 3 reach the barrier is if they're genuinely running at once."""
    coord = AgentCoordinator(max_depth=5)
    root = coord.register_root("root", "mission")
    barrier = threading.Barrier(3, timeout=5)

    def run_child(child_id: str, name: str, task: str) -> tuple[str, list[str], bool]:
        barrier.wait()
        return f"done {name}", [], True

    tool = build_parallel_spawn_tool(coord, run_child, self_id=root)
    registry = ToolRegistry([tool])
    result = registry.dispatch(
        "spawn_agents",
        {"tasks": [{"name": f"c{i}", "task": f"t{i}"} for i in range(3)]},
    )
    assert result.ok is True


def test_spawn_agents_requires_at_least_two_tasks() -> None:
    coord = AgentCoordinator(max_depth=5)
    root = coord.register_root("root", "mission")
    tool = build_parallel_spawn_tool(coord, lambda *_a: ("", [], True), self_id=root)
    registry = ToolRegistry([tool])
    result = registry.dispatch("spawn_agents", {"tasks": [{"name": "a", "task": "t"}]})
    assert result.ok is False
    assert "spawn_agent" in result.observation  # nudges toward the singular tool


def test_spawn_agents_validates_each_tasks_name_and_task() -> None:
    coord = AgentCoordinator(max_depth=5)
    root = coord.register_root("root", "mission")
    tool = build_parallel_spawn_tool(coord, lambda *_a: ("", [], True), self_id=root)
    registry = ToolRegistry([tool])
    result = registry.dispatch(
        "spawn_agents", {"tasks": [{"name": "a", "task": "t"}, {"name": "", "task": ""}]}
    )
    assert result.ok is False


def test_spawn_agents_reports_depth_ceiling_as_a_failed_result_not_an_exception() -> None:
    coord = AgentCoordinator(max_depth=0)
    root = coord.register_root("root", "mission")
    tool = build_parallel_spawn_tool(coord, lambda *_a: ("", [], True), self_id=root)
    registry = ToolRegistry([tool])
    result = registry.dispatch(
        "spawn_agents", {"tasks": [{"name": "a", "task": "t"}, {"name": "b", "task": "t"}]}
    )
    assert result.ok is False
    assert "depth" in result.observation


def test_spawn_agents_a_crashing_child_still_reaches_a_terminal_status() -> None:
    coord = AgentCoordinator(max_depth=5)
    root = coord.register_root("root", "mission")

    def run_child(child_id: str, name: str, task: str) -> tuple[str, list[str], bool]:
        if name == "bad":
            raise RuntimeError("child agent loop crashed")
        return "ok", [], True

    tool = build_parallel_spawn_tool(coord, run_child, self_id=root)
    registry = ToolRegistry([tool])
    result = registry.dispatch(
        "spawn_agents", {"tasks": [{"name": "good", "task": "t"}, {"name": "bad", "task": "t"}]}
    )
    assert result.ok is False  # overall failure since one child crashed
    assert "crashed" in result.observation
    assert coord.node("agent-2").status is AgentStatus.COMPLETED
    assert coord.node("agent-3").status is AgentStatus.FAILED


def test_spawn_agents_merges_every_childs_finding_ids_and_summary() -> None:
    coord = AgentCoordinator(max_depth=5)
    root = coord.register_root("root", "mission")

    def run_child(child_id: str, name: str, task: str) -> tuple[str, list[str], bool]:
        return f"confirmed for {name}", [f"f-{name}"], True

    tool = build_parallel_spawn_tool(coord, run_child, self_id=root)
    registry = ToolRegistry([tool])
    result = registry.dispatch(
        "spawn_agents", {"tasks": [{"name": "a", "task": "t"}, {"name": "b", "task": "t"}]}
    )
    assert result.ok is True
    assert set(coord.all_finding_ids(root)) == {"f-a", "f-b"}
    assert "confirmed for a" in result.observation
    assert "confirmed for b" in result.observation


def test_spawn_agents_warns_about_a_duplicate_task_within_the_same_batch() -> None:
    coord = AgentCoordinator(max_depth=5)
    root = coord.register_root("root", "mission")

    def run_child(child_id: str, name: str, task: str) -> tuple[str, list[str], bool]:
        return "confirmed", [], True

    tool = build_parallel_spawn_tool(coord, run_child, self_id=root)
    registry = ToolRegistry([tool])

    result = registry.dispatch(
        "spawn_agents",
        {
            "tasks": [
                {"name": "a", "task": "enumerate S3 buckets for public read access"},
                {"name": "b", "task": "enumerate S3 buckets for public write access"},
            ]
        },
    )
    assert result.ok is True  # never blocked
    assert "similar to another task in the same batch" in result.observation


def test_spawn_agents_warns_about_a_duplicate_task_against_a_running_sibling() -> None:
    coord = AgentCoordinator(max_depth=5)
    root = coord.register_root("root", "mission")

    def run_child(child_id: str, name: str, task: str) -> tuple[str, list[str], bool]:
        return "confirmed", [], True

    spawn_tool, _ = build_spawn_tools(coord, run_child, self_id=root)
    ToolRegistry([spawn_tool]).dispatch(
        "spawn_agent",
        {"name": "S3 Specialist", "task": "enumerate S3 buckets for public read access"},
    )

    tool = build_parallel_spawn_tool(coord, run_child, self_id=root)
    registry = ToolRegistry([tool])
    result = registry.dispatch(
        "spawn_agents",
        {
            "tasks": [
                {"name": "c", "task": "enumerate S3 buckets for public read access"},
                {"name": "d", "task": "fuzz the login form for SQL injection"},
            ]
        },
    )
    assert result.ok is True  # never blocked
    assert "similar to running agent" in result.observation
