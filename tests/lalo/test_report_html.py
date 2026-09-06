"""Tests for deterministic HTML rendering - the shared source for PDF/DOCX export."""

from __future__ import annotations

from dataclasses import replace

from lalo.agent.tools import ToolRegistry
from lalo.findings.tool import build_record_finding_tool
from lalo.graph.model import ReachabilityGraph
from lalo.report.collect import ChainRecord, FindingRecord, collect_findings
from lalo.report.coverage import CoverageSummary
from lalo.report.html import render_finding_html, render_report_html

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


def _record(evidence: list[str] | None = None, title: str = "SQLi in /search") -> FindingRecord:
    graph = ReachabilityGraph()
    ToolRegistry([build_record_finding_tool(graph)]).dispatch(
        "record_finding",
        {
            "title": title,
            "description": "The q parameter is concatenated raw.",
            "vuln_class": "sql-injection",
            "target": "https://x.example.com/search",
            "param": "q",
            "evidence": evidence or ["HTTP/1.1 500\nsyntax error"],
            "evidence_excerpt": "syntax error",
            "counterevidence": "No WAF observed.",
            "severity_change_conditions": "Confirmed exfil would raise severity.",
            "remediation": "Apply input validation and least-privilege fixes.",
            "cvss_breakdown": _VALID_CVSS,
        },
    )
    return collect_findings(graph)[0]


def test_render_finding_html_includes_core_fields() -> None:
    record = _record()
    rendered = render_finding_html(record)
    assert "SQLi in /search" in rendered
    assert record.finding_id in rendered
    assert "sql-injection" in rendered
    assert "https://x.example.com/search" in rendered
    assert "<code>q</code>" in rendered


def test_render_finding_html_escapes_a_malicious_title_and_evidence() -> None:
    """Findings trace back to target-observed/LLM-authored content - a raw
    <script>/<img> tag must never reach the HTML document unescaped, since
    this same HTML is what the PDF renderer (a real HTML/CSS engine) parses."""
    record = _record(
        title="<script>alert(1)</script>",
        evidence=['<img src="http://attacker.example/pixel.png">'],
    )
    rendered = render_finding_html(record)
    assert "<script>" not in rendered
    assert "&lt;script&gt;" in rendered
    assert '<img src="http://attacker.example/pixel.png">' not in rendered
    assert "&lt;img" in rendered


def test_render_finding_html_warns_when_evidence_is_not_grounded() -> None:
    graph = ReachabilityGraph()
    ToolRegistry([build_record_finding_tool(graph)]).dispatch(
        "record_finding",
        {
            "title": "t",
            "description": "d",
            "vuln_class": "xss",
            "target": "https://x.example.com/",
            "evidence": ["real captured text"],
            "evidence_excerpt": "never actually captured",
            "counterevidence": "none",
            "severity_change_conditions": "none",
            "remediation": "Apply input validation and least-privilege fixes.",
            "cvss_breakdown": _VALID_CVSS,
        },
    )
    record = collect_findings(graph)[0]
    rendered = render_finding_html(record)
    assert "could not be verified" in rendered


def test_render_finding_html_shows_display_severity_and_override_reason() -> None:
    record = replace(_record(), display_severity="critical", override_reason="chains to RCE")
    rendered = render_finding_html(record)
    assert "CRITICAL" in rendered
    assert "chains to RCE" in rendered


def test_render_finding_html_shows_review_verdict_when_present() -> None:
    record = replace(_record(), review_verdict="confirmed", review_proof_level="L3")
    rendered = render_finding_html(record)
    assert "confirmed" in rendered
    assert "L3" in rendered


def test_render_report_html_is_well_formed_and_states_findings_count() -> None:
    record = _record()
    coverage = CoverageSummary(assessed=["sql-injection"], not_assessed=["xss"])
    rendered = render_report_html([record], coverage, generated_at="2026-01-01")
    assert rendered.startswith("<!doctype html>")
    assert rendered.rstrip().endswith("</html>")
    assert "Findings:</strong> 1" in rendered
    assert "sql-injection" in rendered
    assert "2026-01-01" in rendered


def test_render_report_html_with_no_findings_states_so() -> None:
    coverage = CoverageSummary(assessed=[], not_assessed=["xss"])
    rendered = render_report_html([], coverage)
    assert "No findings recorded." in rendered


def test_render_report_html_isolates_a_single_malformed_finding() -> None:
    good = _record()
    broken = replace(good, finding_id="broken-1", confidence=None)  # type: ignore[arg-type]
    coverage = CoverageSummary(assessed=[], not_assessed=[])
    rendered = render_report_html([good, broken], coverage)
    assert good.finding_id in rendered
    assert "Failed to render this finding" in rendered
    assert "broken-1" in rendered


def test_render_report_html_renders_an_attack_chains_section() -> None:
    coverage = CoverageSummary(assessed=[], not_assessed=[])
    chains = [ChainRecord(finding_ids=["f1", "f2"], titles=["IDOR in /api", "Admin RCE"])]
    rendered = render_report_html([], coverage, chains=chains)
    assert "<h2>Attack Chains</h2>" in rendered
    assert "IDOR in /api → Admin RCE" in rendered


def test_render_report_html_escapes_chain_titles() -> None:
    coverage = CoverageSummary(assessed=[], not_assessed=[])
    chains = [ChainRecord(finding_ids=["f1"], titles=["<script>alert(1)</script>"])]
    rendered = render_report_html([], coverage, chains=chains)
    assert "<script>alert(1)</script>" not in rendered
    assert "&lt;script&gt;" in rendered


def test_render_report_html_with_no_chains_has_no_chains_section() -> None:
    coverage = CoverageSummary(assessed=[], not_assessed=[])
    rendered = render_report_html([], coverage)
    assert "Attack Chains" not in rendered
