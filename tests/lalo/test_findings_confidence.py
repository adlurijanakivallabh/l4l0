"""Tests for the deterministic Confidence Score."""

from __future__ import annotations

from lalo.findings.confidence import compute_confidence
from lalo.graph.model import EdgeKind, NodeKind, ReachabilityGraph


def _add_finding(graph: ReachabilityGraph, node_id: str, **attrs: object) -> None:
    graph.add_node(node_id, NodeKind.FINDING, **attrs)


def test_a_fully_supported_finding_scores_the_maximum() -> None:
    graph = ReachabilityGraph()
    _add_finding(
        graph,
        "f1",
        evidence_grounded=True,
        reproduced=True,
        evidence=["e1", "e2", "e3", "e4"],
        evidence_excerpt="a genuinely specific and distinguishing proof string",
        identities_confirmed=["alice", "bob"],
    )
    graph.add_node("f2", NodeKind.FINDING)
    graph.add_edge("f1", "f2", EdgeKind.ENABLES)

    result = compute_confidence(graph, "f1")
    assert result.score == 100
    assert result.flags == []


def test_a_bare_minimum_finding_scores_zero_and_flags_every_gap() -> None:
    graph = ReachabilityGraph()
    _add_finding(graph, "f1", evidence_grounded=False, evidence=[], evidence_excerpt="")

    result = compute_confidence(graph, "f1")
    assert result.score == 0
    assert any("unverifiable" in flag for flag in result.flags)
    assert any("reproduced" in flag for flag in result.flags)


def test_ungrounded_evidence_never_drops_the_finding_only_zeroes_one_component() -> None:
    graph = ReachabilityGraph()
    _add_finding(
        graph,
        "f1",
        evidence_grounded=False,
        reproduced=True,
        evidence=["e1", "e2"],
        evidence_excerpt="a specific enough string to pass the length check",
        identities_confirmed=["alice", "bob"],
    )
    result = compute_confidence(graph, "f1")
    assert result.breakdown["evidence_provenance_match"] == 0
    assert result.score > 0  # every other component still contributes


def test_corroboration_count_scales_with_evidence_and_caps_at_four() -> None:
    graph = ReachabilityGraph()
    _add_finding(graph, "f1", evidence=["e1"])
    _add_finding(graph, "f2", evidence=["e1", "e2", "e3", "e4", "e5", "e6"])

    one_item = compute_confidence(graph, "f1").breakdown["corroboration_count"]
    many_items = compute_confidence(graph, "f2").breakdown["corroboration_count"]
    assert one_item == 5
    assert many_items == 20


def test_specificity_scales_with_excerpt_length() -> None:
    graph = ReachabilityGraph()
    _add_finding(graph, "f1", evidence_excerpt="")
    _add_finding(graph, "f2", evidence_excerpt="short one")
    _add_finding(graph, "f3", evidence_excerpt="a genuinely long and specific proof excerpt")

    assert compute_confidence(graph, "f1").breakdown["specificity"] == 0
    assert compute_confidence(graph, "f2").breakdown["specificity"] == 7
    assert compute_confidence(graph, "f3").breakdown["specificity"] == 15


def test_cross_context_reproduction_requires_at_least_two_distinct_identities() -> None:
    graph = ReachabilityGraph()
    _add_finding(graph, "f1", identities_confirmed=["alice"])
    _add_finding(graph, "f2", identities_confirmed=["alice", "alice"])
    _add_finding(graph, "f3", identities_confirmed=["alice", "bob"])

    assert compute_confidence(graph, "f1").breakdown["cross_context_reproduction"] == 0
    assert compute_confidence(graph, "f2").breakdown["cross_context_reproduction"] == 0
    assert compute_confidence(graph, "f3").breakdown["cross_context_reproduction"] == 10


def test_chained_impact_success_only_counts_enables_edges() -> None:
    graph = ReachabilityGraph()
    _add_finding(graph, "f1")
    _add_finding(graph, "f2")
    graph.add_edge("f1", "f2", EdgeKind.SUPPORTS)

    assert compute_confidence(graph, "f1").breakdown["chained_impact_success"] == 0

    graph.add_edge("f1", "f2", EdgeKind.ENABLES)
    assert compute_confidence(graph, "f1").breakdown["chained_impact_success"] == 10
