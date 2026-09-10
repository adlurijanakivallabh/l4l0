"""Tests for report finding-record assembly and sorting."""

from __future__ import annotations

from dataclasses import replace

from lalo.agent.tools import ToolRegistry
from lalo.findings.confidence import ConfidenceScore
from lalo.findings.dedup import dedup_key
from lalo.findings.review import ReviewVerdict
from lalo.findings.tool import build_record_finding_tool
from lalo.graph.model import Chain, EdgeKind, NodeKind, ReachabilityGraph
from lalo.report.collect import (
    build_attack_surface_summary,
    build_chain_records,
    build_executive_summary,
    collect_findings,
    first_finding_id_by_vuln_class,
    group_by_verdict,
    sort_findings,
)

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
    assert record.review_adjusted_score is None


def test_collect_findings_populates_dedup_key_from_vuln_class_target_and_param() -> None:
    graph = ReachabilityGraph()
    _file_finding(graph)
    record = collect_findings(graph)[0]
    assert record.dedup_key == dedup_key(record.vuln_class, record.target, record.param)
    assert record.dedup_key != ""


def test_collect_findings_defaults_status_to_open() -> None:
    graph = ReachabilityGraph()
    _file_finding(graph)
    record = collect_findings(graph)[0]
    assert record.status == "open"


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


def test_a_persisted_adjusted_score_is_read_back_onto_the_record() -> None:
    """Regression: run_adversarial_review computed a clamped adjusted_score
    but never persisted it anywhere - this confirms collect_findings reads
    it back once the graph node actually carries it."""
    graph = ReachabilityGraph()
    _file_finding(graph)
    finding_id = collect_findings(graph)[0].finding_id
    graph.add_node(
        finding_id,
        NodeKind.FINDING,
        review_verdict="ruled_out",
        review_proof_level="L1",
        review_adjusted_score=12,
    )
    record = collect_findings(graph)[0]
    assert record.review_adjusted_score == 12


# --- build_executive_summary ----------------------------------------------


def test_build_executive_summary_counts_by_severity_and_category() -> None:
    graph = ReachabilityGraph()
    _file_finding(graph, target="https://x.example.com/a", cvss_breakdown=_HIGH_CVSS)
    _file_finding(
        graph, target="https://x.example.com/b", cvss_breakdown=_LOW_CVSS, vuln_class="xss"
    )
    _file_finding(graph, target="https://x.example.com/c", cvss_breakdown=_HIGH_CVSS)
    summary = build_executive_summary(collect_findings(graph))
    assert summary.total_findings == 3
    assert summary.by_severity["high"] == 2
    assert summary.by_vuln_class == {"sql-injection": 2, "xss": 1}
    assert summary.highest_severity == "high"


def test_build_executive_summary_orders_severities_worst_first() -> None:
    graph = ReachabilityGraph()
    _file_finding(graph, target="https://x.example.com/low", cvss_breakdown=_LOW_CVSS)
    _file_finding(graph, target="https://x.example.com/high", cvss_breakdown=_HIGH_CVSS)
    summary = build_executive_summary(collect_findings(graph))
    assert list(summary.by_severity) == ["high", "low"]


def test_build_executive_summary_on_no_findings_is_all_empty() -> None:
    summary = build_executive_summary([])
    assert summary.total_findings == 0
    assert summary.by_severity == {}
    assert summary.by_vuln_class == {}
    assert summary.highest_severity is None
    assert summary.by_confidence == {}
    assert summary.critical_findings == []


def test_build_executive_summary_buckets_by_confidence_band() -> None:
    graph = ReachabilityGraph()
    _file_finding(graph)
    record = collect_findings(graph)[0]
    high = replace(record, confidence=ConfidenceScore(score=90, breakdown={}))
    medium = replace(record, confidence=ConfidenceScore(score=60, breakdown={}))
    low = replace(record, confidence=ConfidenceScore(score=20, breakdown={}))
    summary = build_executive_summary([high, medium, low])
    assert summary.by_confidence == {"high": 1, "medium": 1, "low": 1}


def test_build_executive_summary_lists_critical_finding_titles() -> None:
    graph = ReachabilityGraph()
    _file_finding(graph)
    record = collect_findings(graph)[0]
    critical = replace(record, title="Unauth RCE via SSTI", display_severity="critical")
    medium = replace(record, title="Reflected XSS", display_severity="medium")
    summary = build_executive_summary([critical, medium])
    assert summary.critical_findings == ["Unauth RCE via SSTI"]


# --- build_attack_surface_summary -----------------------------------------


def test_build_attack_surface_summary_reads_endpoints_services_fingerprints() -> None:
    graph = ReachabilityGraph()
    graph.add_node(
        "https://x.example.com/api/users", NodeKind.ENDPOINT, source="js-mining", extra={}
    )
    graph.add_node(
        "tcp://x.example.com:443",
        NodeKind.SERVICE,
        source="nmap",
        extra={"name": "nginx", "version": "1.18"},
    )
    graph.add_node(
        "https://x.example.com/app.js",
        NodeKind.FINGERPRINT,
        source="fingerprint",
        extra={"technology": "Express", "version": "4.18"},
    )

    summary = build_attack_surface_summary(graph)
    assert any("api/users" in e for e in summary.endpoints)
    assert any("nginx" in s for s in summary.services)
    assert any("Express" in f for f in summary.fingerprints)


def test_build_attack_surface_summary_on_an_empty_graph_is_all_empty() -> None:
    summary = build_attack_surface_summary(ReachabilityGraph())
    assert summary == build_attack_surface_summary(ReachabilityGraph())
    assert summary.endpoints == []
    assert summary.services == []
    assert summary.fingerprints == []


# --- build_chain_records -------------------------------------------------


def test_build_chain_records_resolves_ids_to_titles() -> None:
    graph = ReachabilityGraph()
    _file_finding(graph, target="https://x.example.com/a")
    _file_finding(graph, target="https://x.example.com/b")
    records = collect_findings(graph)
    by_target = {r.target: r for r in records}
    a_id, b_id = (
        by_target["https://x.example.com/a"].finding_id,
        by_target["https://x.example.com/b"].finding_id,
    )
    graph.add_edge(a_id, b_id, EdgeKind.ENABLES)

    chains = build_chain_records(graph.all_enabling_chains(), records)
    assert len(chains) == 1
    assert chains[0].finding_ids == [a_id, b_id]
    assert chains[0].titles == ["A finding", "A finding"]


def test_build_chain_records_falls_back_to_the_bare_id_for_an_unknown_finding() -> None:
    chains = build_chain_records([Chain(node_ids=["ghost-1", "ghost-2"])], [])
    assert chains[0].titles == ["ghost-1", "ghost-2"]


def test_build_chain_records_on_no_chains_is_empty() -> None:
    assert build_chain_records([], []) == []


def test_group_by_verdict_buckets_every_real_verdict_plus_not_reviewed() -> None:
    graph = ReachabilityGraph()
    _file_finding(graph, target="https://x.example.com/a")
    _file_finding(graph, target="https://x.example.com/b")
    records = collect_findings(graph)
    confirmed = replace(records[0], review_verdict=ReviewVerdict.CONFIRMED.value)
    not_reviewed = replace(records[1], review_verdict=None)
    groups = group_by_verdict([confirmed, not_reviewed])
    assert [label for label, _ in groups] == [
        "Confirmed",
        "Not Reviewed",
        "Open Proof Gap",
        "Ruled Out",
    ]
    by_label = dict(groups)
    assert by_label["Confirmed"] == [confirmed]
    assert by_label["Not Reviewed"] == [not_reviewed]
    assert by_label["Open Proof Gap"] == []
    assert by_label["Ruled Out"] == []


def test_group_by_verdict_preserves_input_order_within_a_bucket() -> None:
    graph = ReachabilityGraph()
    _file_finding(graph, target="https://x.example.com/a")
    _file_finding(graph, target="https://x.example.com/b")
    records = collect_findings(graph)
    first = replace(records[0], review_verdict=ReviewVerdict.RULED_OUT.value, finding_id="f-first")
    second = replace(
        records[1], review_verdict=ReviewVerdict.RULED_OUT.value, finding_id="f-second"
    )
    groups = dict(group_by_verdict([first, second]))
    assert [r.finding_id for r in groups["Ruled Out"]] == ["f-first", "f-second"]


def test_collect_findings_strips_control_characters_from_the_title() -> None:
    graph = ReachabilityGraph()
    _file_finding(graph, title="Reflected value\r\ncontains a newline")
    record = collect_findings(graph)[0]
    assert "\r" not in record.title
    assert "\n" not in record.title
    assert "Reflected value" in record.title


def test_first_finding_id_by_vuln_class_keeps_the_first_occurrence() -> None:
    graph = ReachabilityGraph()
    _file_finding(graph, target="https://x.example.com/a", vuln_class="xss")
    _file_finding(graph, target="https://x.example.com/b", vuln_class="xss")
    records = collect_findings(graph)
    anchors = first_finding_id_by_vuln_class(records)
    assert anchors["xss"] == records[0].finding_id


def test_collect_findings_surfaces_dependency_and_fix_verification_fields() -> None:
    graph = ReachabilityGraph()
    graph.add_node(
        "finding-1",
        NodeKind.FINDING,
        title="t",
        description="d",
        vuln_class="dependency-vulnerability",
        target="pkg",
        evidence=["e"],
        evidence_excerpt="e",
        evidence_grounded=True,
        counterevidence="c",
        severity_change_conditions="s",
        remediation="r",
        cvss_score=6.5,
        cvss_severity="medium",
        cvss_vector="v",
        reproduced=False,
        identities_confirmed=[],
        dedup_key="k",
        package_name="lodash",
        ecosystem="npm",
        reachability="confirmed",
        contextual_cvss=6.5,
        code_locations=[{"location": "a.py:1", "fix_before": "x", "fix_after": "y"}],
        fix_verified=True,
    )
    records = collect_findings(graph)
    assert records[0].package_name == "lodash"
    assert records[0].reachability == "confirmed"
    assert records[0].fix_verified is True
    assert records[0].code_locations == [
        {"location": "a.py:1", "fix_before": "x", "fix_after": "y"}
    ]
