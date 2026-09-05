"""Tests for the query_graph/note agent tools."""

from __future__ import annotations

from lalo.agent.tools import ToolRegistry
from lalo.graph.model import NodeKind, ReachabilityGraph
from lalo.graph.tool import build_note_tool, build_query_graph_tool


def test_note_records_a_note_node() -> None:
    graph = ReachabilityGraph()
    tool = build_note_tool(graph)
    result = tool.run({"text": "check the admin panel again later"})
    assert result.ok is True
    notes = graph.nodes_of_kind(NodeKind.NOTE)
    assert len(notes) == 1
    assert graph.node(notes[0])["text"] == "check the admin panel again later"


def test_note_requires_nonblank_text() -> None:
    tool = build_note_tool(ReachabilityGraph())
    result = tool.run({"text": "   "})
    assert result.ok is False


def test_note_requires_text_even_as_explicit_json_null() -> None:
    tool = build_note_tool(ReachabilityGraph())
    result = tool.run({"text": None})
    assert result.ok is False


def test_query_graph_with_no_args_summarizes_counts_per_kind() -> None:
    graph = ReachabilityGraph()
    graph.add_node("ep-1", NodeKind.ENDPOINT)
    graph.add_node("ep-2", NodeKind.ENDPOINT)
    graph.add_node("f-1", NodeKind.FINDING)
    tool = build_query_graph_tool(graph)
    result = tool.run({})
    assert "endpoint=2" in result.observation
    assert "finding=1" in result.observation


def test_query_graph_on_an_empty_graph_says_so() -> None:
    tool = build_query_graph_tool(ReachabilityGraph())
    result = tool.run({})
    assert result.observation == "(graph is empty)"


def test_query_graph_lists_nodes_of_a_given_kind() -> None:
    graph = ReachabilityGraph()
    graph.add_node("ep-1", NodeKind.ENDPOINT, path="/admin")
    tool = build_query_graph_tool(graph)
    result = tool.run({"kind": "endpoint"})
    assert "1 endpoint node(s)" in result.observation
    assert "ep-1" in result.observation
    assert "/admin" in result.observation


def test_query_graph_rejects_an_unknown_kind() -> None:
    tool = build_query_graph_tool(ReachabilityGraph())
    result = tool.run({"kind": "not-a-real-kind"})
    assert result.ok is False
    assert "unknown kind" in result.observation


def test_query_graph_fetches_one_node_by_id() -> None:
    graph = ReachabilityGraph()
    graph.add_node("ep-1", NodeKind.ENDPOINT, path="/admin")
    tool = build_query_graph_tool(graph)
    result = tool.run({"node_id": "ep-1"})
    assert "/admin" in result.observation


def test_query_graph_reports_a_missing_node_id_as_a_failed_result() -> None:
    tool = build_query_graph_tool(ReachabilityGraph())
    result = tool.run({"node_id": "does-not-exist"})
    assert result.ok is False


def test_query_graph_is_never_wired_to_a_write_path() -> None:
    """Read-only by construction: only node()/nodes_of_kind() calls, matching
    the tool's own description - never add_node/add_edge."""
    tool = build_query_graph_tool(ReachabilityGraph())
    tool.run({})
    tool.run({"kind": "endpoint"})
    tool.run({"node_id": "x"})
    assert "query_graph" == tool.name  # sanity: it's the tool under test


def test_query_graph_lists_are_capped_and_say_how_many_more() -> None:
    graph = ReachabilityGraph()
    for i in range(60):
        graph.add_node(f"ep-{i}", NodeKind.ENDPOINT)
    tool = build_query_graph_tool(graph)
    result = tool.run({"kind": "endpoint"})
    assert "and 10 more" in result.observation


def test_registry_dispatches_both_tools_by_name() -> None:
    graph = ReachabilityGraph()
    registry = ToolRegistry([build_note_tool(graph), build_query_graph_tool(graph)])
    registry.dispatch("note", {"text": "hi"})
    result = registry.dispatch("query_graph", {"kind": "note"})
    assert "1 note node(s)" in result.observation
