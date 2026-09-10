from lalo.graph.baseline import build_baseline_tool
from lalo.graph.model import NodeKind, ReachabilityGraph


def test_save_baseline_requires_summary_and_category() -> None:
    graph = ReachabilityGraph()
    tool = build_baseline_tool(graph, "agent-1")
    result = tool.run({"action": "save", "target": "api.example.com"})
    assert not result.ok


def test_save_then_get_baseline_round_trips() -> None:
    graph = ReachabilityGraph()
    tool = build_baseline_tool(graph, "agent-1")
    saved = tool.run(
        {
            "action": "save",
            "target": "https://api.example.com:443/",
            "category": "authentication",
            "summary": "JWT bearer tokens, no refresh rotation observed",
        }
    )
    assert saved.ok
    got = tool.run({"action": "get", "target": "api.example.com"})
    assert got.ok
    assert "JWT bearer tokens" in got.observation


def test_get_baseline_for_an_unknown_target_says_so_without_error() -> None:
    graph = ReachabilityGraph()
    tool = build_baseline_tool(graph, "agent-1")
    result = tool.run({"action": "get", "target": "nothing-here.example.com"})
    assert result.ok
    assert "no baseline" in result.observation


def test_save_twice_for_the_same_identity_is_rejected() -> None:
    graph = ReachabilityGraph()
    tool = build_baseline_tool(graph, "agent-1")
    tool.run({"action": "save", "target": "api.example.com", "category": "c", "summary": "s"})
    result = tool.run(
        {"action": "save", "target": "api.example.com", "category": "c2", "summary": "s2"}
    )
    assert not result.ok
    assert "already exists" in result.observation


def test_amend_appends_without_overwriting_the_original_summary() -> None:
    graph = ReachabilityGraph()
    tool = build_baseline_tool(graph, "agent-1")
    tool.run(
        {"action": "save", "target": "api.example.com", "category": "c", "summary": "original"}
    )
    amended = tool.run({"action": "amend", "target": "api.example.com", "text": "also found X"})
    assert amended.ok
    got = tool.run({"action": "get", "target": "api.example.com"})
    assert "original" in got.observation
    assert "also found X" in got.observation


def test_amend_before_any_save_is_rejected() -> None:
    graph = ReachabilityGraph()
    tool = build_baseline_tool(graph, "agent-1")
    result = tool.run({"action": "amend", "target": "api.example.com", "text": "x"})
    assert not result.ok


def test_https_and_bare_host_resolve_to_the_same_identity() -> None:
    graph = ReachabilityGraph()
    tool = build_baseline_tool(graph, "agent-1")
    tool.run(
        {"action": "save", "target": "https://api.example.com/", "category": "c", "summary": "s"}
    )
    assert len(graph.nodes_of_kind(NodeKind.BASELINE)) == 1
    got = tool.run({"action": "get", "target": "api.example.com:443"})
    assert "s" in got.observation
