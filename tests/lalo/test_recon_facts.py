"""Tests for the scope-gated recon-fact-to-graph merge."""

from __future__ import annotations

from lalo.execution.scope import ScopeGuard
from lalo.execution.target import Engagement
from lalo.graph import NodeKind, ReachabilityGraph
from lalo.recon import FactKind, ReconFact, merge_facts


def _scope() -> ScopeGuard:
    return ScopeGuard(
        engagement=Engagement.from_specs(["app.example.com"]),
        resolver=lambda h: frozenset({"93.184.216.34"}),
    )


def test_in_engagement_fact_is_merged_as_a_graph_node() -> None:
    graph = ReachabilityGraph()
    fact = ReconFact(kind=FactKind.ENDPOINT, url="https://app.example.com/api/users", source="test")
    report = merge_facts(graph, _scope(), [fact])
    assert report.accepted == [fact]
    assert report.rejected == []
    assert graph.has_node("https://app.example.com/api/users")
    assert graph.node("https://app.example.com/api/users")["kind"] == NodeKind.ENDPOINT.value


def test_out_of_engagement_fact_is_rejected_not_merged() -> None:
    graph = ReachabilityGraph()
    fact = ReconFact(kind=FactKind.ENDPOINT, url="https://evil.example.org/api", source="test")
    report = merge_facts(graph, _scope(), [fact])
    assert report.accepted == []
    assert len(report.rejected) == 1
    rejected_fact, reason = report.rejected[0]
    assert rejected_fact is fact
    assert reason == "out_of_engagement"
    assert not graph.has_node("https://evil.example.org/api")


def test_fact_kind_maps_to_the_matching_node_kind() -> None:
    graph = ReachabilityGraph()
    facts = [
        ReconFact(kind=FactKind.HOST, url="https://app.example.com/", source="t"),
        ReconFact(kind=FactKind.TECHNOLOGY, url="https://app.example.com/tech", source="t"),
    ]
    merge_facts(graph, _scope(), facts)
    assert graph.node("https://app.example.com/")["kind"] == NodeKind.SERVICE.value
    assert graph.node("https://app.example.com/tech")["kind"] == NodeKind.FINGERPRINT.value


def test_merging_the_same_url_twice_does_not_duplicate_the_node() -> None:
    graph = ReachabilityGraph()
    fact = ReconFact(kind=FactKind.ENDPOINT, url="https://app.example.com/api", source="a")
    merge_facts(graph, _scope(), [fact])
    merge_facts(graph, _scope(), [fact])
    assert len(graph) == 1
