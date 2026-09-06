"""Tests for report finding-record assembly and sorting."""

from __future__ import annotations

from lalo.agent.tools import ToolRegistry
from lalo.findings.tool import build_record_finding_tool
from lalo.graph.model import NodeKind, ReachabilityGraph
from lalo.report.collect import collect_findings, sort_findings

_HIGH_CVSS = {
    "attack_vector": "N",
    "attack_complexity": "L",
    "privileges_required": "N",
    "user_interaction": "N",
    "scope": "U",
    "confidentiality": "H",
    "integrity": "N",
    "availability": "N",
}
_LOW_CVSS = {
    "attack_vector": "L",
    "attack_complexity": "H",
    "privileges_required": "H",
    "user_interaction": "R",
    "scope": "U",
    "confidentiality": "L",
    "integrity": "N",
    "availability": "N",
}


def _file_finding(graph: ReachabilityGraph, **overrides: object) -> None:
    args: dict[str, object] = {
        "title": "A finding",
        "description": "desc",
        "vuln_class": "sql-injection",
        "target": "https://x.example.com/search",
        "evidence": ["real captured proof"],
        "evidence_excerpt": "real captured proof",
        "counterevidence": "none found",
        "severity_change_conditions": "would change if X",
        "remediation": "Apply input validation and least-privilege fixes.",
        "cvss_breakdown": _HIGH_CVSS,
    }
    args.update(overrides)
    ToolRegistry([build_record_finding_tool(graph)]).dispatch("record_finding", args)


def test_collect_findings_returns_one_record_per_finding_node() -> None:
    graph = ReachabilityGraph()
    _file_finding(graph, target="https://x.example.com/a")
    _file_finding(graph, target="https://x.example.com/b")
    records = collect_findings(graph)
    assert len(records) == 2
    assert {r.target for r in records} == {
        "https://x.example.com/a",
        "https://x.example.com/b",
    }


def test_collect_findings_computes_confidence_per_record() -> None:
    graph = ReachabilityGraph()
    _file_finding(graph)
    records = collect_findings(graph)
    assert records[0].confidence.score > 0


def test_collect_findings_on_an_empty_graph_returns_empty() -> None:
    assert collect_findings(ReachabilityGraph()) == []


def test_sort_findings_orders_by_severity_then_confidence() -> None:
    graph = ReachabilityGraph()
    _file_finding(graph, target="https://x.example.com/high", cvss_breakdown=_HIGH_CVSS)
    _file_finding(graph, target="https://x.example.com/low", cvss_breakdown=_LOW_CVSS)
    records = sort_findings(collect_findings(graph))
    assert records[0].cvss_severity == "high"
    assert records[1].cvss_severity in {"low", "medium"}


def test_sort_findings_breaks_severity_ties_by_confidence_descending() -> None:
    graph = ReachabilityGraph()
    _file_finding(
        graph,
        target="https://x.example.com/weak",
        evidence=["e"],
        evidence_excerpt="not-in-evidence-at-all",
    )
    _file_finding(
        graph,
        target="https://x.example.com/strong",
        evidence=["e1", "e2", "e3", "e4"],
        evidence_excerpt="e1",
        reproduced=True,
        identities_confirmed=["alice", "bob"],
    )
    records = sort_findings(collect_findings(graph))
    assert records[0].target == "https://x.example.com/strong"
    assert records[1].target == "https://x.example.com/weak"


def test_effective_severity_falls_back_to_cvss_severity_with_no_override() -> None:
    graph = ReachabilityGraph()
    _file_finding(graph)
    record = collect_findings(graph)[0]
    assert record.effective_severity == record.cvss_severity
    assert record.display_severity is None


def test_a_never_reviewed_finding_has_no_review_verdict() -> None:
    graph = ReachabilityGraph()
    _file_finding(graph)
    record = collect_findings(graph)[0]
    assert record.review_verdict is None
    assert record.review_proof_level is None


def test_a_persisted_review_verdict_is_read_back_onto_the_record() -> None:
    """run_adversarial_review persists onto the finding's own node - this
    confirms collect_findings actually reads that back, closing the gap
    where a real review verdict never reached a rendered report."""
    graph = ReachabilityGraph()
    _file_finding(graph)
    finding_id = collect_findings(graph)[0].finding_id
    graph.add_node(
        finding_id,
        NodeKind.FINDING,
        review_verdict="confirmed",
        review_proof_level="L3",
    )
    record = collect_findings(graph)[0]
    assert record.review_verdict == "confirmed"
    assert record.review_proof_level == "L3"
