"""Tests for the reachability graph: isolation, chain solving, persistence."""

from __future__ import annotations

from pathlib import Path

from lalo.agent.spawn import Isolatable, isolate_for_child
from lalo.graph import Chain, EdgeKind, NodeKind, ReachabilityGraph


def test_satisfies_the_phase_6_isolatable_protocol_spawn_tools_depend_on() -> None:
    g = ReachabilityGraph()
    g.add_node("ep-1", NodeKind.ENDPOINT)
    assert isinstance(g, Isolatable)

    child_graph = isolate_for_child(g)
    child_graph.add_node("ep-2", NodeKind.ENDPOINT)
    assert not g.has_node("ep-2")  # spawn-time isolation actually holds end to end


def test_add_node_and_edge_basic() -> None:
    g = ReachabilityGraph()
    g.add_node("ep-1", NodeKind.ENDPOINT, path="/admin")
    g.add_node("id-1", NodeKind.IDENTITY, role="user")
    g.add_edge("id-1", "ep-1", EdgeKind.AUTHENTICATED_AS)
    assert g.node("ep-1")["path"] == "/admin"
    assert g.nodes_of_kind(NodeKind.ENDPOINT) == ["ep-1"]
    assert len(g) == 2


def test_snapshot_is_an_independent_deep_copy() -> None:
    parent = ReachabilityGraph()
    parent.add_node("ep-1", NodeKind.ENDPOINT)
    child = parent.snapshot()

    child.add_node("ep-2", NodeKind.ENDPOINT)
    child.add_edge("ep-1", "ep-2", EdgeKind.ENABLES)

    assert not parent.has_node("ep-2")  # the child's addition never leaked back
    assert len(parent) == 1
    assert len(child) == 2


def test_has_edge_of_kind_true_for_either_direction() -> None:
    g = ReachabilityGraph()
    g.add_node("a", NodeKind.FINDING)
    g.add_node("b", NodeKind.FINDING)
    g.add_edge("a", "b", EdgeKind.ENABLES)
    assert g.has_edge_of_kind("a", EdgeKind.ENABLES) is True
    assert g.has_edge_of_kind("b", EdgeKind.ENABLES) is True


def test_has_edge_of_kind_false_for_a_different_kind_or_unknown_node() -> None:
    g = ReachabilityGraph()
    g.add_node("a", NodeKind.FINDING)
    g.add_node("b", NodeKind.FINDING)
    g.add_edge("a", "b", EdgeKind.SUPPORTS)
    assert g.has_edge_of_kind("a", EdgeKind.ENABLES) is False
    assert g.has_edge_of_kind("nonexistent", EdgeKind.ENABLES) is False


def test_connected_via_returns_neighbors_in_either_direction() -> None:
    g = ReachabilityGraph()
    g.add_node("a", NodeKind.FINDING)
    g.add_node("b", NodeKind.FINDING)
    g.add_node("c", NodeKind.FINDING)
    g.add_edge("a", "b", EdgeKind.ENABLES)
    g.add_edge("c", "a", EdgeKind.ENABLES)
    assert set(g.connected_via("a", EdgeKind.ENABLES)) == {"b", "c"}


def test_connected_via_only_the_requested_edge_kind() -> None:
    g = ReachabilityGraph()
    g.add_node("a", NodeKind.FINDING)
    g.add_node("b", NodeKind.FINDING)
    g.add_edge("a", "b", EdgeKind.SUPPORTS)
    assert g.connected_via("a", EdgeKind.ENABLES) == []


def test_connected_via_an_unknown_node_is_empty() -> None:
    g = ReachabilityGraph()
    assert g.connected_via("nonexistent", EdgeKind.ENABLES) == []


def test_find_chains_solves_a_seeded_multistep_exploit_path() -> None:
    g = ReachabilityGraph()
    for node_id in ("idor", "admin", "upload", "rce"):
        g.add_node(node_id, NodeKind.FINDING)
    g.add_edge("idor", "admin", EdgeKind.ENABLES)
    g.add_edge("admin", "upload", EdgeKind.ENABLES)
    g.add_edge("upload", "rce", EdgeKind.ENABLES)

    chains = g.find_chains("idor", "rce")
    assert chains == [Chain(node_ids=["idor", "admin", "upload", "rce"])]


def test_find_chains_same_source_and_target_with_no_edges_finds_nothing() -> None:
    # networkx's own documented special case for source == target is a
    # trivial single-node "path" that traversed no edge at all -- that is
    # never a real chain, regardless of whether the node has any edges.
    g = ReachabilityGraph()
    g.add_node("a", NodeKind.FINDING)
    assert g.find_chains("a", "a") == []


def test_find_chains_deduplicates_parallel_edges_of_the_same_kind() -> None:
    # Two agents each recording their own ENABLES edge for the same
    # relationship is exactly the scenario the MultiDiGraph choice exists to
    # support -- it must not multiply into duplicate chain entries.
    g = ReachabilityGraph()
    g.add_node("a", NodeKind.FINDING)
    g.add_node("b", NodeKind.FINDING)
    g.add_edge("a", "b", EdgeKind.ENABLES, note="from-agent-1")
    g.add_edge("a", "b", EdgeKind.ENABLES, note="from-agent-2")
    assert g.find_chains("a", "b") == [Chain(node_ids=["a", "b"])]


def test_find_chains_ignores_edges_of_a_different_kind() -> None:
    g = ReachabilityGraph()
    g.add_node("a", NodeKind.FINDING)
    g.add_node("b", NodeKind.FINDING)
    # Only a HAS_PARAM edge connects them -- not an attack-chain step.
    g.add_edge("a", "b", EdgeKind.HAS_PARAM)
    assert g.find_chains("a", "b") == []


def test_find_chains_returns_empty_for_unknown_nodes_not_a_crash() -> None:
    g = ReachabilityGraph()
    g.add_node("a", NodeKind.FINDING)
    assert g.find_chains("a", "does-not-exist") == []
    assert g.find_chains("also-missing", "a") == []


def test_all_enabling_chains_on_an_empty_graph_is_empty() -> None:
    assert ReachabilityGraph().all_enabling_chains() == []


def test_all_enabling_chains_finds_every_root_to_leaf_path() -> None:
    g = ReachabilityGraph()
    for node_id in ("idor", "admin", "upload", "rce"):
        g.add_node(node_id, NodeKind.FINDING)
    g.add_edge("idor", "admin", EdgeKind.ENABLES)
    g.add_edge("admin", "upload", EdgeKind.ENABLES)
    g.add_edge("upload", "rce", EdgeKind.ENABLES)
    assert g.all_enabling_chains() == [Chain(node_ids=["idor", "admin", "upload", "rce"])]


def test_all_enabling_chains_finds_multiple_independent_chains() -> None:
    g = ReachabilityGraph()
    for node_id in ("a1", "a2", "b1", "b2"):
        g.add_node(node_id, NodeKind.FINDING)
    g.add_edge("a1", "a2", EdgeKind.ENABLES)
    g.add_edge("b1", "b2", EdgeKind.ENABLES)
    chains = g.all_enabling_chains()
    assert {tuple(c.node_ids) for c in chains} == {("a1", "a2"), ("b1", "b2")}


def test_all_enabling_chains_ignores_findings_with_no_enables_edge() -> None:
    g = ReachabilityGraph()
    g.add_node("lonely", NodeKind.FINDING)
    g.add_node("a", NodeKind.FINDING)
    g.add_node("b", NodeKind.FINDING)
    g.add_edge("a", "b", EdgeKind.ENABLES)
    chains = g.all_enabling_chains()
    assert len(chains) == 1
    assert "lonely" not in chains[0].node_ids


def test_all_enabling_chains_ignores_non_enables_edges() -> None:
    g = ReachabilityGraph()
    g.add_node("evidence-1", NodeKind.EVIDENCE)
    g.add_node("finding-1", NodeKind.FINDING)
    g.add_edge("evidence-1", "finding-1", EdgeKind.SUPPORTS)
    assert g.all_enabling_chains() == []


def test_save_and_load_round_trips_nodes_and_edges(tmp_path: Path) -> None:
    g = ReachabilityGraph()
    g.add_node("ep-1", NodeKind.ENDPOINT, path="/api/users/{id}")
    g.add_node("finding-1", NodeKind.FINDING, title="IDOR")
    g.add_edge("ep-1", "finding-1", EdgeKind.ENABLES, note="cross-identity proof")

    path = tmp_path / "graph.json"
    g.save(path)
    loaded = ReachabilityGraph.load(path)

    assert loaded.node("ep-1")["path"] == "/api/users/{id}"
    assert loaded.nodes_of_kind(NodeKind.FINDING) == ["finding-1"]
    assert loaded.find_chains("ep-1", "finding-1") == [Chain(node_ids=["ep-1", "finding-1"])]
