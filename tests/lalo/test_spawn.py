"""Tests for multi-agent spawn: depth ceiling, authoritative merge, isolation."""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field

import pytest

from lalo.agent.spawn import (
    AgentCoordinator,
    AgentStatus,
    build_parallel_spawn_tool,
    build_spawn_tools,
    build_wait_for_agents_tool,
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


def test_spawn_stores_the_full_role_by_default() -> None:
    coord = AgentCoordinator(max_depth=5)
    root = coord.register_root("root", "mission")
    child = coord.spawn(root, "child", "subtask")
    assert coord.node(child).role == "full"


def test_spawn_stores_an_explicit_role() -> None:
    coord = AgentCoordinator(max_depth=5)
    root = coord.register_root("root", "mission")
    child = coord.spawn(root, "child", "subtask", role="source_reviewer")
    assert coord.node(child).role == "source_reviewer"


def test_register_root_defaults_to_the_full_role() -> None:
    coord = AgentCoordinator()
    root = coord.register_root("root", "mission")
    assert coord.node(root).role == "full"


def test_register_orphan_creates_a_node_with_orphaned_status() -> None:
    coord = AgentCoordinator(max_depth=5)
    coord.register_orphan(
        "agent-7",
        "Source Reviewer",
        "read the repo",
        parent_id="agent-1",
        depth=1,
        role="source_reviewer",
    )
    node = coord.node("agent-7")
    assert node.status is AgentStatus.ORPHANED
    assert node.name == "Source Reviewer"
    assert node.task == "read the repo"
    assert node.parent_id == "agent-1"
    assert node.depth == 1
    assert node.role == "source_reviewer"


def test_has_node_reports_existence() -> None:
    coord = AgentCoordinator(max_depth=5)
    root = coord.register_root("root", "mission")
    assert coord.has_node(root) is True
    assert coord.has_node("agent-999") is False


def test_render_tree_shows_an_orphaned_node() -> None:
    coord = AgentCoordinator(max_depth=5)
    coord.register_orphan(
        "agent-7", "Source Reviewer", "read the repo", parent_id=None, depth=0, role="full"
    )
    tree = coord.render_tree()
    assert "Source Reviewer (agent-7) [orphaned]" in tree


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

    spawn_tool, graph_tool, _stop = build_spawn_tools(coord, run_child, self_id=root)
    registry = ToolRegistry([spawn_tool, graph_tool])

    result = registry.dispatch("spawn_agent", {"name": "XSS Specialist", "task": "test /search"})
    assert result.ok is True
    assert "f-9" in result.observation
    assert calls == [("agent-2", "XSS Specialist", "test /search")]
    assert coord.all_finding_ids(root) == ["f-9"]

    graph_result = registry.dispatch("view_agent_graph", {})
    assert "XSS Specialist" in graph_result.observation


def test_spawn_agent_rejects_an_unknown_role_without_registering_a_child() -> None:
    coord = AgentCoordinator(max_depth=5)
    root = coord.register_root("root", "mission")
    spawn_tool, _, _ = build_spawn_tools(
        coord,
        lambda *_a: ("", [], True),
        self_id=root,
        valid_roles=frozenset({"full", "source_reviewer"}),
    )
    registry = ToolRegistry([spawn_tool])
    result = registry.dispatch("spawn_agent", {"name": "x", "task": "y", "role": "not-a-real-role"})
    assert result.ok is False
    assert coord.children_of(root) == []


def test_spawn_agent_passes_a_valid_role_through_to_the_coordinator() -> None:
    coord = AgentCoordinator(max_depth=5)
    root = coord.register_root("root", "mission")
    spawn_tool, _, _ = build_spawn_tools(
        coord,
        lambda *_a: ("", [], True),
        self_id=root,
        valid_roles=frozenset({"full", "source_reviewer"}),
    )
    registry = ToolRegistry([spawn_tool])
    registry.dispatch("spawn_agent", {"name": "x", "task": "y", "role": "source_reviewer"})
    child_id = coord.children_of(root)[0]
    assert coord.node(child_id).role == "source_reviewer"


def test_spawn_agent_role_defaults_to_full_when_omitted() -> None:
    coord = AgentCoordinator(max_depth=5)
    root = coord.register_root("root", "mission")
    spawn_tool, _, _ = build_spawn_tools(coord, lambda *_a: ("", [], True), self_id=root)
    registry = ToolRegistry([spawn_tool])
    registry.dispatch("spawn_agent", {"name": "x", "task": "y"})
    child_id = coord.children_of(root)[0]
    assert coord.node(child_id).role == "full"


def test_spawn_agent_resumes_a_real_orphan_using_its_original_task() -> None:
    coord = AgentCoordinator(max_depth=5)
    root = coord.register_root("root", "mission")
    coord.register_orphan(
        "agent-7",
        "Source Reviewer",
        "the ORIGINAL task text",
        parent_id=root,
        depth=1,
        role="source_reviewer",
    )
    calls: list[tuple[str, str, str]] = []

    def run_child(child_id: str, name: str, task: str) -> tuple[str, list[str], bool]:
        calls.append((child_id, name, task))
        return "continued and confirmed", ["f-1"], True

    spawn_tool, _, _ = build_spawn_tools(coord, run_child, self_id=root)
    registry = ToolRegistry([spawn_tool])
    result = registry.dispatch(
        "spawn_agent",
        {"resume_agent_id": "agent-7", "task": "a DIFFERENT task the model tried to give"},
    )
    assert result.ok is True
    assert calls == [("agent-7", "Source Reviewer", "the ORIGINAL task text")]
    assert coord.node("agent-7").status is AgentStatus.COMPLETED


def test_spawn_agent_rejects_a_resume_agent_id_that_is_not_a_known_orphan() -> None:
    coord = AgentCoordinator(max_depth=5)
    root = coord.register_root("root", "mission")
    spawn_tool, _, _ = build_spawn_tools(coord, lambda *_a: ("", [], True), self_id=root)
    registry = ToolRegistry([spawn_tool])
    result = registry.dispatch("spawn_agent", {"resume_agent_id": "agent-999"})
    assert result.ok is False


def test_spawn_agent_rejects_resuming_a_node_that_is_not_orphaned() -> None:
    coord = AgentCoordinator(max_depth=5)
    root = coord.register_root("root", "mission")
    child = coord.spawn(root, "child", "subtask")
    coord.record_result(child, summary="done", finding_ids=[])
    spawn_tool, _, _ = build_spawn_tools(coord, lambda *_a: ("", [], True), self_id=root)
    registry = ToolRegistry([spawn_tool])
    result = registry.dispatch("spawn_agent", {"resume_agent_id": child})
    assert result.ok is False


def test_spawn_agent_tool_requires_name_and_task() -> None:
    coord = AgentCoordinator()
    root = coord.register_root("root", "mission")
    spawn_tool, _, _ = build_spawn_tools(coord, lambda *_a: ("", [], True), self_id=root)
    registry = ToolRegistry([spawn_tool])
    result = registry.dispatch("spawn_agent", {"name": "", "task": ""})
    assert result.ok is False


def test_spawn_agent_tool_requires_name_and_task_even_as_explicit_json_null() -> None:
    """An explicit JSON null must be treated the same as an absent/empty
    field, not stringified into the literal, non-empty "None"."""
    coord = AgentCoordinator()
    root = coord.register_root("root", "mission")
    spawn_tool, _, _ = build_spawn_tools(coord, lambda *_a: ("", [], True), self_id=root)
    registry = ToolRegistry([spawn_tool])
    result = registry.dispatch("spawn_agent", {"name": None, "task": None})
    assert result.ok is False


def test_spawn_agent_tool_reports_depth_ceiling_as_a_failed_result_not_an_exception() -> None:
    coord = AgentCoordinator(max_depth=0)
    root = coord.register_root("root", "mission")
    spawn_tool, _, _ = build_spawn_tools(coord, lambda *_a: ("", [], True), self_id=root)
    registry = ToolRegistry([spawn_tool])
    result = registry.dispatch("spawn_agent", {"name": "child", "task": "subtask"})
    assert result.ok is False
    assert "depth" in result.observation


def test_spawn_warns_on_a_near_duplicate_sibling_task_but_still_succeeds() -> None:
    coord = AgentCoordinator(max_depth=5)
    root = coord.register_root("root", "mission")

    def run_child(child_id: str, name: str, task: str) -> tuple[str, list[str], bool]:
        return "confirmed", [], True

    spawn_tool, _, _ = build_spawn_tools(coord, run_child, self_id=root)
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

    spawn_tool, _, _ = build_spawn_tools(coord, run_child, self_id=root)
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

    spawn_tool, _, _ = build_spawn_tools(coord, crashing_run_child, self_id=root)
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


def test_spawn_agents_rejects_the_whole_batch_when_any_role_is_invalid() -> None:
    coord = AgentCoordinator(max_depth=5)
    root = coord.register_root("root", "mission")
    parallel_tool = build_parallel_spawn_tool(
        coord,
        lambda *_a: ("", [], True),
        self_id=root,
        valid_roles=frozenset({"full", "source_reviewer"}),
    )
    registry = ToolRegistry([parallel_tool])
    result = registry.dispatch(
        "spawn_agents",
        {
            "tasks": [
                {"name": "a", "task": "task a", "role": "full"},
                {"name": "b", "task": "task b", "role": "not-a-real-role"},
            ]
        },
    )
    assert result.ok is False
    assert coord.children_of(root) == []


def test_spawn_agents_passes_each_tasks_own_role_through() -> None:
    coord = AgentCoordinator(max_depth=5)
    root = coord.register_root("root", "mission")
    parallel_tool = build_parallel_spawn_tool(
        coord,
        lambda *_a: ("", [], True),
        self_id=root,
        valid_roles=frozenset({"full", "source_reviewer"}),
    )
    registry = ToolRegistry([parallel_tool])
    registry.dispatch(
        "spawn_agents",
        {
            "tasks": [
                {"name": "a", "task": "task a", "role": "full"},
                {"name": "b", "task": "task b", "role": "source_reviewer"},
            ]
        },
    )
    roles = {coord.node(cid).role for cid in coord.children_of(root)}
    assert roles == {"full", "source_reviewer"}


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


def test_spawn_agents_warns_on_byte_identical_task_text_within_the_same_batch() -> None:
    """Two DIFFERENT batch entries with byte-identical task text (e.g. a
    copy-paste) is the most obvious duplicate a batch could produce - it must
    still warn, not be silently exempted just because the text matches exactly."""
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
                {"name": "b", "task": "enumerate S3 buckets for public read access"},
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

    spawn_tool, _, _ = build_spawn_tools(coord, run_child, self_id=root)
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


# --- stop_agent / background spawn_agent / wait_for_agents ------------------


def test_stop_agent_marks_a_running_agent_stopped() -> None:
    coordinator = AgentCoordinator()
    root_id = coordinator.register_root("root", "mission")
    child_id = coordinator.spawn(root_id, "child", "task")
    spawn_tool, view_tool, stop_tool = build_spawn_tools(
        coordinator, lambda cid, n, t: ("done", [], True), self_id=root_id
    )
    result = stop_tool.run({"agent_id": child_id, "reason": "duplicate of another agent"})
    assert result.ok
    assert coordinator.is_stopped(child_id)
    assert coordinator.node(child_id).stop_reason == "duplicate of another agent"


def test_stop_agent_rejects_an_unknown_id() -> None:
    coordinator = AgentCoordinator()
    root_id = coordinator.register_root("root", "mission")
    _spawn, _view, stop_tool = build_spawn_tools(
        coordinator, lambda cid, n, t: ("done", [], True), self_id=root_id
    )
    result = stop_tool.run({"agent_id": "agent-999", "reason": "x"})
    assert not result.ok


def test_stop_agent_rejects_an_already_completed_agent() -> None:
    coordinator = AgentCoordinator()
    root_id = coordinator.register_root("root", "mission")
    child_id = coordinator.spawn(root_id, "child", "task")
    coordinator.record_result(child_id, summary="done", success=True)
    _spawn, _view, stop_tool = build_spawn_tools(
        coordinator, lambda cid, n, t: ("done", [], True), self_id=root_id
    )
    result = stop_tool.run({"agent_id": child_id, "reason": "x"})
    assert not result.ok


def test_background_spawn_returns_immediately_and_wait_for_agents_joins_it() -> None:
    release = threading.Event()

    def _slow_run_child(child_id: str, name: str, task: str) -> tuple[str, list[str], bool]:
        release.wait(timeout=5)
        return "finished slowly", ["finding-1"], True

    coordinator = AgentCoordinator()
    root_id = coordinator.register_root("root", "mission")
    spawn_tool, _view, _stop = build_spawn_tools(coordinator, _slow_run_child, self_id=root_id)
    wait_tool = build_wait_for_agents_tool(coordinator)

    start = time.monotonic()
    spawn_result = spawn_tool.run({"name": "child", "task": "task", "background": True})
    elapsed = time.monotonic() - start
    assert spawn_result.ok
    assert elapsed < 1.0  # returned immediately, did not block on release
    import re

    match = re.search(r"agent-\d+", spawn_result.observation)
    assert match is not None
    child_id = match.group(0)

    release.set()
    wait_result = wait_tool.run({"agent_ids": [child_id]})
    assert wait_result.ok
    assert "finished slowly" in wait_result.observation
    assert coordinator.node(child_id).status is AgentStatus.COMPLETED


def test_wait_for_agents_reports_an_unknown_or_already_awaited_id() -> None:
    coordinator = AgentCoordinator()
    wait_tool = build_wait_for_agents_tool(coordinator)
    result = wait_tool.run({"agent_ids": ["agent-999"]})
    assert "error" in result.observation
