"""Tests for the record_coverage/list_coverage self-attestation ledger."""

from __future__ import annotations

from lalo.graph.coverage_ledger import build_coverage_ledger_tool
from lalo.graph.model import NodeKind, ReachabilityGraph


def test_record_coverage_requires_outcome_and_target() -> None:
    graph = ReachabilityGraph()
    tool = build_coverage_ledger_tool(graph)
    result = tool.run({"action": "record", "target": "https://x/api"})
    assert not result.ok


def test_record_coverage_rejects_an_unknown_outcome() -> None:
    graph = ReachabilityGraph()
    tool = build_coverage_ledger_tool(graph)
    result = tool.run(
        {"action": "record", "target": "https://x/api", "vuln_class": "ssrf", "outcome": "maybe"}
    )
    assert not result.ok
    assert "outcome must be one of" in result.observation


def test_record_and_list_coverage_round_trips() -> None:
    graph = ReachabilityGraph()
    tool = build_coverage_ledger_tool(graph)
    recorded = tool.run(
        {
            "action": "record",
            "target": "https://x/api",
            "vuln_class": "ssrf",
            "outcome": "not-applicable",
            "notes": "no outbound-URL-accepting parameter found",
        }
    )
    assert recorded.ok
    listed = tool.run({"action": "list"})
    assert listed.ok
    assert "ssrf" in listed.observation
    assert "not-applicable" in listed.observation
    assert len(graph.nodes_of_kind(NodeKind.COVERAGE_LEDGER)) == 1


def test_list_coverage_filters_by_outcome() -> None:
    graph = ReachabilityGraph()
    tool = build_coverage_ledger_tool(graph)
    tool.run({"action": "record", "target": "a", "vuln_class": "ssrf", "outcome": "not-applicable"})
    tool.run({"action": "record", "target": "b", "vuln_class": "xss", "outcome": "needs-follow-up"})
    listed = tool.run({"action": "list", "outcome": "needs-follow-up"})
    assert "xss" in listed.observation
    assert "ssrf" not in listed.observation
