"""Tests for deterministic HTML rendering - the shared source for PDF/DOCX export."""

from __future__ import annotations

from dataclasses import replace

from lalo.agent.tools import ToolRegistry
from lalo.findings.review import ReviewVerdict
from lalo.findings.tool import build_record_finding_tool
from lalo.graph.model import ReachabilityGraph
from lalo.report.collect import (
    AttackSurfaceSummary,
    ChainRecord,
    ExecutiveSummary,
    FindingRecord,
    ReportMetadata,
    ReportUsage,
    collect_findings,
)
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


def test_render_finding_html_includes_the_cwe_line_when_mapped() -> None:
    record = _record()  # vuln_class="sql-injection" -> CWE-89
    rendered = render_finding_html(record)
    assert "<dt>CWE</dt><dd>CWE-89</dd>" in rendered


def test_render_finding_html_omits_the_cwe_line_when_unmapped() -> None:
    record = replace(_record(), vuln_class="not-a-real-class")
    rendered = render_finding_html(record)
    assert "<dt>CWE</dt>" not in rendered


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


def test_render_finding_html_labels_exploitation_section_only_when_reproduced() -> None:
    reproduced = render_finding_html(replace(_record(), reproduced=True))
    not_reproduced = render_finding_html(replace(_record(), reproduced=False))
    assert "Exploitation Steps" in reproduced
    assert "Analysis" in not_reproduced
    assert "Exploitation" not in not_reproduced


def test_render_report_html_renders_an_attack_surface_section() -> None:
    coverage = CoverageSummary(assessed=[], not_assessed=[])
    surface = AttackSurfaceSummary(
        endpoints=["https://x.example.com/api/users"],
        services=["nginx:443"],
        fingerprints=["Express 4.18"],
    )
    rendered = render_report_html([], coverage, attack_surface=surface)
    assert "Attack Surface" in rendered
    assert "https://x.example.com/api/users" in rendered
    assert "nginx:443" in rendered
    assert "Express 4.18" in rendered


def test_render_report_html_omits_attack_surface_section_when_empty() -> None:
    coverage = CoverageSummary(assessed=[], not_assessed=[])
    surface = AttackSurfaceSummary(endpoints=[], services=[], fingerprints=[])
    rendered = render_report_html([], coverage, attack_surface=surface)
    assert "Attack Surface" not in rendered


def test_render_report_html_includes_a_findings_overview_table() -> None:
    record = replace(_record(), finding_id="finding-1", title="SQLi")
    coverage = CoverageSummary(assessed=[], not_assessed=[])
    rendered = render_report_html([record], coverage)
    assert "Findings Overview" in rendered
    assert '<a href="#finding-1">finding-1</a>' in rendered


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


def test_render_report_html_shows_the_scan_status_when_given() -> None:
    coverage = CoverageSummary(assessed=[], not_assessed=[])
    rendered = render_report_html([], coverage, status="budget_exhausted")
    assert "<strong>Scan Status:</strong> budget_exhausted" in rendered


def test_render_report_html_with_no_status_has_no_status_line() -> None:
    coverage = CoverageSummary(assessed=[], not_assessed=[])
    rendered = render_report_html([], coverage)
    assert "Scan Status" not in rendered


def test_render_report_html_shows_usage_with_a_known_cost() -> None:
    coverage = CoverageSummary(assessed=[], not_assessed=[])
    usage = ReportUsage(
        total_requests=3, total_input_tokens=1000, total_output_tokens=200, total_cost_usd=0.0123
    )
    rendered = render_report_html([], coverage, usage=usage)
    assert "3 requests, 1,000 input / 200 output tokens, est. cost $0.0123" in rendered


def test_render_report_html_warns_when_usage_accounting_is_incomplete() -> None:
    coverage = CoverageSummary(assessed=[], not_assessed=[])
    usage = ReportUsage(
        total_requests=3,
        total_input_tokens=1000,
        total_output_tokens=200,
        total_cost_usd=0.0123,
        accounting_complete=False,
    )
    rendered = render_report_html([], coverage, usage=usage)
    assert "may be an undercount" in rendered


def test_render_report_html_shows_usage_without_a_configured_pricing_table() -> None:
    coverage = CoverageSummary(assessed=[], not_assessed=[])
    usage = ReportUsage(
        total_requests=3, total_input_tokens=1000, total_output_tokens=200, total_cost_usd=None
    )
    rendered = render_report_html([], coverage, usage=usage)
    assert "3 requests, 1,000 input / 200 output tokens" in rendered
    assert "cost" not in rendered.lower()


def test_render_report_html_with_no_usage_has_no_usage_line() -> None:
    coverage = CoverageSummary(assessed=[], not_assessed=[])
    rendered = render_report_html([], coverage)
    assert "LLM Usage" not in rendered


def test_render_report_html_renders_the_executive_summary_when_given() -> None:
    coverage = CoverageSummary(assessed=[], not_assessed=[])
    summary = ExecutiveSummary(
        total_findings=2,
        by_severity={"high": 1, "low": 1},
        by_vuln_class={"sql-injection": 1, "xss": 1},
        highest_severity="high",
    )
    rendered = render_report_html([], coverage, summary=summary)
    assert "<h2>Executive Summary</h2>" in rendered
    assert '<li class="stat-chip sev-high"><span class="stat-count">1</span> HIGH</li>' in rendered
    assert '<li class="stat-chip sev-low"><span class="stat-count">1</span> LOW</li>' in rendered
    assert "sql-injection: 1, xss: 1" in rendered
    assert "<strong>Highest severity:</strong> HIGH" in rendered


def test_render_report_html_escapes_the_vuln_class_in_the_executive_summary() -> None:
    coverage = CoverageSummary(assessed=[], not_assessed=[])
    summary = ExecutiveSummary(
        total_findings=1,
        by_severity={"high": 1},
        by_vuln_class={"<script>alert(1)</script>": 1},
        highest_severity="high",
    )
    rendered = render_report_html([], coverage, summary=summary)
    assert "<script>alert(1)</script>" not in rendered
    assert "&lt;script&gt;" in rendered


def test_render_report_html_with_no_summary_has_no_executive_summary_section() -> None:
    coverage = CoverageSummary(assessed=[], not_assessed=[])
    rendered = render_report_html([], coverage)
    assert "Executive Summary" not in rendered


def test_render_report_html_shows_engagement_scope_and_model_in_the_executive_summary() -> None:
    coverage = CoverageSummary(assessed=[], not_assessed=[])
    summary = ExecutiveSummary(
        total_findings=1,
        by_severity={"high": 1},
        by_vuln_class={"sql-injection": 1},
        highest_severity="high",
    )
    metadata = ReportMetadata(
        engagement_scope="- example.com", model_provider="anthropic:claude-sonnet-5"
    )
    rendered = render_report_html([], coverage, summary=summary, metadata=metadata)
    assert "<h2>Executive Summary</h2>" in rendered
    assert "<strong>Model / Provider:</strong> anthropic:claude-sonnet-5" in rendered
    assert "<strong>Target / Scope:</strong>" in rendered
    assert "<pre>- example.com</pre>" in rendered


def test_render_report_html_with_no_metadata_has_no_executive_summary_scope_or_model_lines() -> (
    None
):
    """The cover page (added later, unconditional) now always shows a
    "Model / Provider" / "Target / Engagement Scope" line with a
    "(not recorded)" fallback - see
    test_render_report_html_cover_page_falls_back_when_engagement_metadata_is_absent.
    This test's real intent survives as: the EXECUTIVE SUMMARY's own
    metadata-gated line must not ALSO render without real metadata, i.e.
    "Model / Provider" must appear exactly once (from the cover page),
    never duplicated by the Executive Summary block."""
    coverage = CoverageSummary(assessed=[], not_assessed=[])
    summary = ExecutiveSummary(
        total_findings=0, by_severity={}, by_vuln_class={}, highest_severity=None
    )
    rendered = render_report_html([], coverage, summary=summary)
    assert rendered.count("Model / Provider") == 1
    assert rendered.count("Target / Scope") == 0
    assert "Target / Engagement Scope" in rendered  # the cover page's own label


def test_render_report_html_omits_stat_chips_when_no_findings() -> None:
    coverage = CoverageSummary(assessed=[], not_assessed=[])
    summary = ExecutiveSummary(
        total_findings=0, by_severity={}, by_vuln_class={}, highest_severity=None
    )
    rendered = render_report_html([], coverage, summary=summary)
    assert '<ul class="stat-chips">' not in rendered


def test_render_report_html_stat_chip_falls_back_for_an_unrecognized_severity() -> None:
    """display_severity is operator-supplied (SeverityOverride) - an
    unexpected string must still render as a chip, never be silently
    dropped from the summary."""
    coverage = CoverageSummary(assessed=[], not_assessed=[])
    summary = ExecutiveSummary(
        total_findings=1, by_severity={"weird": 1}, by_vuln_class={}, highest_severity="weird"
    )
    rendered = render_report_html([], coverage, summary=summary)
    assert '<li class="stat-chip sev-info"><span class="stat-count">1</span> WEIRD</li>' in rendered


def test_render_finding_html_includes_the_owasp_line_when_mapped() -> None:
    record = replace(_record(), vuln_class="idor")
    rendered = render_finding_html(record)
    assert "<dt>OWASP API Top 10</dt><dd>API1:2023" in rendered
    assert "Broken Object Level Authorization" in rendered


def test_render_finding_html_omits_the_owasp_line_when_unmapped() -> None:
    assert "OWASP API Top 10" not in render_finding_html(_record())


def test_render_finding_html_heading_carries_an_id_anchor() -> None:
    record = _record()
    assert f'<h2 id="{record.finding_id}">' in render_finding_html(record)


def test_render_report_html_groups_findings_by_review_verdict() -> None:
    confirmed = replace(_record(), review_verdict=ReviewVerdict.CONFIRMED.value)
    coverage = CoverageSummary(assessed=["sql-injection"], not_assessed=[])
    rendered = render_report_html([confirmed], coverage)
    assert "<h3>Verdict: Confirmed (1)</h3>" in rendered
    assert "<h3>Verdict: Ruled Out (0)</h3>" in rendered
    assert "<p><em>None.</em></p>" in rendered


def test_render_report_html_with_no_findings_has_no_verdict_sections() -> None:
    coverage = CoverageSummary(assessed=[], not_assessed=[])
    assert "Verdict:" not in render_report_html([], coverage)


def test_render_report_html_quick_index_links_to_the_first_finding_of_each_category() -> None:
    record = _record()
    coverage = CoverageSummary(assessed=["sql-injection"], not_assessed=[])
    summary = ExecutiveSummary(
        total_findings=1,
        by_severity={"high": 1},
        by_vuln_class={"sql-injection": 1},
        highest_severity="high",
    )
    rendered = render_report_html([record], coverage, summary=summary)
    assert "<h2>Summary by Vulnerability Type</h2>" in rendered
    assert f'<li><a href="#{record.finding_id}">sql-injection (1)</a></li>' in rendered


def test_render_report_html_includes_a_cover_page_ahead_of_the_executive_summary() -> None:
    coverage = CoverageSummary(assessed=[], not_assessed=[])
    summary = ExecutiveSummary(
        total_findings=0, by_severity={}, by_vuln_class={}, highest_severity=None
    )
    rendered = render_report_html([], coverage, generated_at="2026-09-08", summary=summary)
    assert 'class="cover-page"' in rendered
    assert "2026-09-08" in rendered
    assert "Confidential" in rendered
    assert rendered.index('class="cover-page"') < rendered.index("<h2>Executive Summary</h2>")


def test_render_report_html_cover_page_falls_back_when_engagement_metadata_is_absent() -> None:
    coverage = CoverageSummary(assessed=[], not_assessed=[])
    assert "(not recorded)" in render_report_html([], coverage)


def test_render_report_html_cover_page_surfaces_real_engagement_metadata() -> None:
    """engagement_scope/model_provider come from the sibling report-metadata
    task's ReportMetadata, threaded in via the `metadata` parameter that
    task adds to render_report_html - a confirmed, real cross-task
    interface, not a forward guess."""
    metadata = ReportMetadata(
        engagement_scope="https://x.example.com", model_provider="opencodex:gpt-5.6"
    )
    coverage = CoverageSummary(assessed=[], not_assessed=[])
    rendered = render_report_html([], coverage, metadata=metadata)
    assert "https://x.example.com" in rendered
    assert "opencodex:gpt-5.6" in rendered
