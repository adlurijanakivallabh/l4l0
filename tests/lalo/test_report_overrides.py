"""Tests for the display-only severity-override audit trail."""

from __future__ import annotations

from lalo.agent.tools import ToolRegistry
from lalo.findings.tool import build_record_finding_tool
from lalo.graph.model import ReachabilityGraph
from lalo.report.collect import collect_findings
from lalo.report.overrides import (
    SeverityOverride,
    StatusOverride,
    apply_overrides,
    apply_status_overrides,
)

_VALID_CVSS = {
    "attack_vector": "N",
    "attack_complexity": "L",
    "privileges_required": "N",
    "user_interaction": "N",
    "scope": "U",
    "confidentiality": "H",
    "integrity": "N",
    "availability": "N",
}


def _graph_with_finding() -> ReachabilityGraph:
    graph = ReachabilityGraph()
    ToolRegistry([build_record_finding_tool(graph)]).dispatch(
        "record_finding",
        {
            "title": "A finding",
            "description": "desc",
            "vuln_class": "sql-injection",
            "target": "https://x.example.com/search",
            "evidence": ["real captured proof"],
            "evidence_excerpt": "real captured proof",
            "counterevidence": "none found",
            "severity_change_conditions": "would change if X",
            "remediation": "Apply input validation and least-privilege fixes.",
            "cvss_breakdown": _VALID_CVSS,
        },
    )
    return graph


def test_apply_overrides_sets_the_display_severity_and_reason() -> None:
    graph = _graph_with_finding()
    records = collect_findings(graph)
    finding_id = records[0].finding_id
    overridden = apply_overrides(
        records,
        [SeverityOverride(finding_id, "critical", "chains to full RCE", "alice")],
    )
    assert overridden[0].display_severity == "critical"
    assert "chains to full RCE" in (overridden[0].override_reason or "")
    assert "alice" in (overridden[0].override_reason or "")
    assert overridden[0].effective_severity == "critical"


def test_apply_overrides_never_mutates_the_underlying_graph_node() -> None:
    graph = _graph_with_finding()
    records = collect_findings(graph)
    finding_id = records[0].finding_id
    original_severity = graph.node(finding_id)["cvss_severity"]

    apply_overrides(records, [SeverityOverride(finding_id, "critical", "reason", "alice")])

    assert graph.node(finding_id)["cvss_severity"] == original_severity


def test_apply_overrides_leaves_records_without_a_matching_override_unchanged() -> None:
    graph = _graph_with_finding()
    records = collect_findings(graph)
    overridden = apply_overrides(records, [SeverityOverride("nonexistent-id", "low", "r", "a")])
    assert overridden == records


def test_apply_overrides_the_last_override_for_a_finding_wins() -> None:
    graph = _graph_with_finding()
    records = collect_findings(graph)
    finding_id = records[0].finding_id
    overridden = apply_overrides(
        records,
        [
            SeverityOverride(finding_id, "low", "first guess", "alice"),
            SeverityOverride(finding_id, "critical", "corrected", "bob"),
        ],
    )
    assert overridden[0].display_severity == "critical"
    assert "corrected" in (overridden[0].override_reason or "")


def test_apply_overrides_with_no_overrides_returns_equivalent_records() -> None:
    graph = _graph_with_finding()
    records = collect_findings(graph)
    assert apply_overrides(records, []) == records


def test_apply_status_overrides_sets_only_the_targeted_records_status() -> None:
    graph = _graph_with_finding()
    records = collect_findings(graph)
    finding_id = records[0].finding_id
    assert records[0].status == "open"

    overridden = apply_status_overrides(
        records,
        [StatusOverride(finding_id, "false_positive", "manually verified benign", "alice")],
    )
    assert overridden[0].status == "false_positive"


def test_apply_status_overrides_never_mutates_the_input_list() -> None:
    graph = _graph_with_finding()
    records = collect_findings(graph)
    finding_id = records[0].finding_id
    original_status = records[0].status

    apply_status_overrides(records, [StatusOverride(finding_id, "remediated", "patched", "alice")])

    assert records[0].status == original_status


def test_apply_status_overrides_leaves_records_without_a_matching_override_unchanged() -> None:
    graph = _graph_with_finding()
    records = collect_findings(graph)
    overridden = apply_status_overrides(
        records, [StatusOverride("nonexistent-id", "remediated", "r", "a")]
    )
    assert overridden == records


def test_apply_status_overrides_the_last_override_for_a_finding_wins() -> None:
    graph = _graph_with_finding()
    records = collect_findings(graph)
    finding_id = records[0].finding_id
    overridden = apply_status_overrides(
        records,
        [
            StatusOverride(finding_id, "needs_retest", "first pass", "alice"),
            StatusOverride(finding_id, "remediated", "confirmed fixed", "bob"),
        ],
    )
    assert overridden[0].status == "remediated"


def test_apply_status_overrides_with_no_overrides_returns_equivalent_records() -> None:
    graph = _graph_with_finding()
    records = collect_findings(graph)
    assert apply_status_overrides(records, []) == records
