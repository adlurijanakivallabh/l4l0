"""Tests for deterministic Markdown rendering."""

from __future__ import annotations

from dataclasses import replace

from lalo.agent.tools import ToolRegistry
from lalo.findings.tool import build_record_finding_tool
from lalo.graph.model import ReachabilityGraph
from lalo.report.collect import FindingRecord, collect_findings
from lalo.report.coverage import CoverageSummary
from lalo.report.markdown import render_finding_md, render_report_md, safe_fence

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


def _record(
    evidence: list[str] | None = None, evidence_excerpt: str = "syntax error"
) -> FindingRecord:
    graph = ReachabilityGraph()
    ToolRegistry([build_record_finding_tool(graph)]).dispatch(
        "record_finding",
        {
            "title": "SQLi in /search",
            "description": "The q parameter is concatenated raw.",
            "vuln_class": "sql-injection",
            "target": "https://x.example.com/search",
            "param": "q",
            "evidence": evidence or ["HTTP/1.1 500\nsyntax error"],
            "evidence_excerpt": evidence_excerpt,
            "counterevidence": "No WAF observed.",
            "severity_change_conditions": "Confirmed exfil would raise severity.",
            "cvss_breakdown": _VALID_CVSS,
        },
    )
    return collect_findings(graph)[0]


def test_safe_fence_is_longer_than_any_backtick_run_in_content() -> None:
    assert safe_fence("no backticks") == "```"
    assert safe_fence("some ``` here") == "````"
    assert safe_fence("worse ```````` run") == "`````````"


def test_render_finding_md_includes_core_fields() -> None:
    record = _record()
    rendered = render_finding_md(record)
    assert "SQLi in /search" in rendered
    assert record.finding_id in rendered
    assert "sql-injection" in rendered
    assert "https://x.example.com/search" in rendered
    assert "`q`" in rendered
    assert "HIGH" in rendered.upper() or "MEDIUM" in rendered.upper()


def test_render_finding_md_evidence_cannot_break_out_of_its_fence() -> None:
    malicious_evidence = "normal text\n```\ninjected markdown after breakout\n```"
    record = _record(evidence=[malicious_evidence], evidence_excerpt="normal text")
    rendered = render_finding_md(record)
    # the evidence's own ``` run must never become the ACTUAL closing fence -
    # the real fence around it has to be a longer backtick run
    assert "````" in rendered


def test_render_finding_md_warns_when_evidence_is_not_grounded() -> None:
    record = _record(evidence_excerpt="this text was never actually captured")
    rendered = render_finding_md(record)
    assert "could not be verified" in rendered


def test_render_finding_md_shows_display_severity_and_override_reason() -> None:
    record = replace(_record(), display_severity="critical", override_reason="chains to RCE")
    rendered = render_finding_md(record)
    assert "CRITICAL" in rendered
    assert "chains to RCE" in rendered


def test_render_finding_md_shows_review_verdict_when_present() -> None:
    record = replace(_record(), review_verdict="confirmed", review_proof_level="L3")
    rendered = render_finding_md(record)
    assert "confirmed" in rendered
    assert "L3" in rendered


def test_render_report_md_states_findings_count_and_coverage() -> None:
    record = _record()
    coverage = CoverageSummary(assessed=["sql-injection"], not_assessed=["xss"])
    rendered = render_report_md([record], coverage, generated_at="2026-01-01")
    assert "**Findings:** 1" in rendered
    assert "sql-injection" in rendered
    assert "xss" in rendered
    assert "2026-01-01" in rendered
    assert "does not distinguish" in rendered


def test_render_report_md_with_no_findings_states_so() -> None:
    coverage = CoverageSummary(assessed=[], not_assessed=["xss"])
    rendered = render_report_md([], coverage)
    assert "No findings recorded." in rendered


def test_render_report_md_isolates_a_single_malformed_finding() -> None:
    good = _record()
    broken = replace(good, finding_id="broken-1", confidence=None)  # type: ignore[arg-type]
    coverage = CoverageSummary(assessed=[], not_assessed=[])
    rendered = render_report_md([good, broken], coverage)
    assert good.finding_id in rendered
    assert "Failed to render this finding" in rendered
    assert "broken-1" in rendered
