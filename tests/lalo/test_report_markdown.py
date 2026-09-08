"""Tests for deterministic Markdown rendering."""

from __future__ import annotations

from dataclasses import replace

from lalo.agent.tools import ToolRegistry
from lalo.findings.review import ReviewVerdict
from lalo.findings.tool import build_record_finding_tool
from lalo.graph.model import ReachabilityGraph
from lalo.report.collect import (
    ChainRecord,
    ExecutiveSummary,
    FindingRecord,
    ReportMetadata,
    ReportUsage,
    collect_findings,
)
from lalo.report.coverage import CoverageSummary
from lalo.report.markdown import (
    _render_chains_mermaid,
    render_finding_md,
    render_report_md,
    safe_fence,
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
            "remediation": "Apply input validation and least-privilege fixes.",
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


def test_render_finding_md_includes_the_cwe_line_when_mapped() -> None:
    record = _record()  # vuln_class="sql-injection" -> CWE-89
    rendered = render_finding_md(record)
    assert "**CWE:** CWE-89" in rendered


def test_render_finding_md_omits_the_cwe_line_when_unmapped() -> None:
    record = replace(_record(), vuln_class="not-a-real-class")
    rendered = render_finding_md(record)
    assert "**CWE:**" not in rendered


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


def test_render_report_md_renders_an_attack_chains_section() -> None:
    coverage = CoverageSummary(assessed=[], not_assessed=[])
    chains = [ChainRecord(finding_ids=["f1", "f2"], titles=["IDOR in /api", "Admin RCE"])]
    rendered = render_report_md([], coverage, chains=chains)
    assert "## Attack Chains" in rendered
    assert "IDOR in /api → Admin RCE" in rendered


def test_render_report_md_attack_chains_section_also_includes_a_mermaid_block() -> None:
    """The Mermaid diagram is additive - it must appear ALONGSIDE the plain
    bullet, never replacing it, so a viewer with no Mermaid renderer still
    gets the readable fallback."""
    coverage = CoverageSummary(assessed=[], not_assessed=[])
    chains = [ChainRecord(finding_ids=["f1", "f2"], titles=["IDOR in /api", "Admin RCE"])]
    rendered = render_report_md([], coverage, chains=chains)
    assert "- IDOR in /api → Admin RCE" in rendered
    assert "```mermaid" in rendered
    assert "flowchart LR" in rendered


def test_render_chains_mermaid_empty_chains_renders_nothing() -> None:
    assert _render_chains_mermaid([]) == ""


def test_render_chains_mermaid_two_chains_sharing_one_node() -> None:
    chains = [
        ChainRecord(finding_ids=["f1", "f2"], titles=["IDOR in /api", "Admin RCE"]),
        ChainRecord(finding_ids=["f3", "f2"], titles=["SSRF in /fetch", "Admin RCE"]),
    ]
    rendered = _render_chains_mermaid(chains)
    assert rendered.startswith("```mermaid\nflowchart LR")
    assert rendered.endswith("```")
    assert '    c0n0["IDOR in /api"]' in rendered
    assert '    c0n1["Admin RCE"]' in rendered
    assert "    c0n0 --> c0n1" in rendered
    assert '    c1n0["SSRF in /fetch"]' in rendered
    assert '    c1n1["Admin RCE"]' in rendered
    assert "    c1n0 --> c1n1" in rendered


def test_render_chains_mermaid_escapes_a_double_quote_in_a_chain_title() -> None:
    chains = [ChainRecord(finding_ids=["f1"], titles=['SQLi in "search"'])]
    rendered = _render_chains_mermaid(chains)
    assert "c0n0[\"SQLi in 'search'\"]" in rendered
    assert '"search"' not in rendered


def test_render_report_md_with_no_chains_has_no_chains_section() -> None:
    coverage = CoverageSummary(assessed=[], not_assessed=[])
    rendered = render_report_md([], coverage)
    assert "Attack Chains" not in rendered


def test_render_report_md_shows_the_scan_status_when_given() -> None:
    coverage = CoverageSummary(assessed=[], not_assessed=[])
    rendered = render_report_md([], coverage, status="budget_exhausted")
    assert "**Scan Status:** budget_exhausted" in rendered


def test_render_report_md_with_no_status_has_no_status_line() -> None:
    coverage = CoverageSummary(assessed=[], not_assessed=[])
    rendered = render_report_md([], coverage)
    assert "Scan Status" not in rendered


def test_render_report_md_shows_usage_with_a_known_cost() -> None:
    coverage = CoverageSummary(assessed=[], not_assessed=[])
    usage = ReportUsage(
        total_requests=3, total_input_tokens=1000, total_output_tokens=200, total_cost_usd=0.0123
    )
    rendered = render_report_md([], coverage, usage=usage)
    assert "**LLM Usage:** 3 requests, 1,000 input / 200 output tokens, est. cost $0.0123" in (
        rendered
    )


def test_render_report_md_shows_usage_without_a_configured_pricing_table() -> None:
    """total_cost_usd=None must never render as a fabricated $0.00 - cost is
    unknown, not zero, when no pricing table was configured for the run."""
    coverage = CoverageSummary(assessed=[], not_assessed=[])
    usage = ReportUsage(
        total_requests=3, total_input_tokens=1000, total_output_tokens=200, total_cost_usd=None
    )
    rendered = render_report_md([], coverage, usage=usage)
    assert "**LLM Usage:** 3 requests, 1,000 input / 200 output tokens" in rendered
    assert "cost" not in rendered.lower()


def test_render_report_md_with_no_usage_has_no_usage_line() -> None:
    coverage = CoverageSummary(assessed=[], not_assessed=[])
    rendered = render_report_md([], coverage)
    assert "LLM Usage" not in rendered


def test_render_report_md_renders_the_executive_summary_when_given() -> None:
    coverage = CoverageSummary(assessed=[], not_assessed=[])
    summary = ExecutiveSummary(
        total_findings=2,
        by_severity={"high": 1, "low": 1},
        by_vuln_class={"sql-injection": 1, "xss": 1},
        highest_severity="high",
    )
    rendered = render_report_md([], coverage, summary=summary)
    assert "## Executive Summary" in rendered
    assert "**By severity:** high: 1, low: 1" in rendered
    assert "**By category:** sql-injection: 1, xss: 1" in rendered
    assert "**Highest severity:** HIGH" in rendered


def test_render_report_md_with_no_summary_has_no_executive_summary_section() -> None:
    coverage = CoverageSummary(assessed=[], not_assessed=[])
    rendered = render_report_md([], coverage)
    assert "Executive Summary" not in rendered


def test_render_report_md_shows_engagement_scope_and_model_in_the_executive_summary() -> None:
    coverage = CoverageSummary(assessed=[], not_assessed=[])
    summary = ExecutiveSummary(
        total_findings=1,
        by_severity={"high": 1},
        by_vuln_class={"sql-injection": 1},
        highest_severity="high",
    )
    metadata = ReportMetadata(
        engagement_scope="- example.com\n- *.internal.example.com",
        model_provider="anthropic:claude-sonnet-5",
    )
    rendered = render_report_md([], coverage, summary=summary, metadata=metadata)
    assert "## Executive Summary" in rendered
    assert "**Model / Provider:** anthropic:claude-sonnet-5" in rendered
    assert "**Target / Scope:**" in rendered
    assert "- example.com\n- *.internal.example.com" in rendered


def test_render_report_md_with_no_metadata_has_no_scope_or_model_lines() -> None:
    coverage = CoverageSummary(assessed=[], not_assessed=[])
    summary = ExecutiveSummary(
        total_findings=0, by_severity={}, by_vuln_class={}, highest_severity=None
    )
    rendered = render_report_md([], coverage, summary=summary)
    assert "Model / Provider" not in rendered
    assert "Target / Scope" not in rendered


def test_render_finding_md_includes_the_owasp_line_when_mapped() -> None:
    record = replace(_record(), vuln_class="idor")
    rendered = render_finding_md(record)
    assert "**OWASP API Top 10:** API1:2023 — Broken Object Level Authorization" in rendered


def test_render_finding_md_omits_the_owasp_line_when_unmapped() -> None:
    rendered = render_finding_md(_record())  # sql-injection has a CWE but no 2023 API category
    assert "OWASP API Top 10" not in rendered


def test_render_finding_md_has_an_anchor_for_the_quick_index_to_target() -> None:
    record = _record()
    assert f'<a id="{record.finding_id}"></a>' in render_finding_md(record)


def test_render_report_md_groups_findings_by_review_verdict() -> None:
    confirmed = replace(_record(), review_verdict=ReviewVerdict.CONFIRMED.value)
    not_reviewed = replace(
        _record(evidence=["e2"]), review_verdict=None, finding_id="f-not-reviewed"
    )
    coverage = CoverageSummary(assessed=["sql-injection"], not_assessed=[])
    rendered = render_report_md([confirmed, not_reviewed], coverage)
    assert "### Verdict: Confirmed (1)" in rendered
    assert "### Verdict: Not Reviewed (1)" in rendered
    assert "### Verdict: Open Proof Gap (0)" in rendered
    assert "### Verdict: Ruled Out (0)" in rendered
    assert "f-not-reviewed" in rendered


def test_render_report_md_with_no_findings_has_no_verdict_sections() -> None:
    coverage = CoverageSummary(assessed=[], not_assessed=[])
    assert "Verdict:" not in render_report_md([], coverage)


def test_render_report_md_quick_index_links_to_the_first_finding_of_each_category() -> None:
    record = _record()
    coverage = CoverageSummary(assessed=["sql-injection"], not_assessed=[])
    summary = ExecutiveSummary(
        total_findings=1,
        by_severity={"high": 1},
        by_vuln_class={"sql-injection": 1},
        highest_severity="high",
    )
    rendered = render_report_md([record], coverage, summary=summary)
    assert "## Summary by Vulnerability Type" in rendered
    assert f"- [sql-injection (1)](#{record.finding_id})" in rendered
