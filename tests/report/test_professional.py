"""Hermetic tests for the testfire-style professional report (Build Order 6)."""

from __future__ import annotations

from unittest.mock import Mock

from reachagent.graph.nodes import Finding, FindingStatus
from reachagent.graph.store import ReachabilityGraph
from reachagent.report.professional import render_professional_report_markdown


def _graph(*findings: tuple[str, str, str]) -> ReachabilityGraph:
    """findings: (vuln_class, severity, evidence_ref) tuples."""
    g = ReachabilityGraph()
    for vuln_class, severity, evidence_ref in findings:
        g.add_finding(
            Finding(
                vuln_class=vuln_class,
                severity=severity,
                oracle_used="differential",
                evidence_ref=evidence_ref,
                status=FindingStatus.CONFIRMED_VIOLATION,
            )
        )
    return g


def _quiet_client() -> Mock:
    mock = Mock()
    mock.propose.side_effect = RuntimeError("no llm in hermetic test")
    return mock


def test_empty_graph_no_findings_confirmed_message() -> None:
    out = render_professional_report_markdown(ReachabilityGraph(), client=_quiet_client())
    assert "No findings were confirmed" in out
    assert "# ReachAgent Security Assessment Report" in out


def test_confirmed_finding_gets_full_structured_section() -> None:
    g = _graph(("sqli", "high", "ref-0"))
    out = render_professional_report_markdown(g, client=_quiet_client())
    assert "## Confirmed Vulnerabilities" in out
    assert "WSTG-INPV-05" in out  # known WSTG mapping for sqli
    assert "**Remediation**" in out
    assert "**Risk**" in out
    assert "ref-0" in out
    assert "## Informational Observations" not in out


def test_informational_finding_kept_out_of_confirmed_section() -> None:
    g = _graph(("information_exposure", "informational", "ref-info"))
    out = render_professional_report_markdown(g, client=_quiet_client())
    assert "## Informational Observations" in out
    assert "## Confirmed Vulnerabilities" not in out
    assert "not confirmed vulnerabilities" in out
    # informational sections never carry a CVSS/remediation claim
    assert "indicative CVSS" not in out
    assert "**Remediation**" not in out


def test_mixed_confirmed_and_informational_both_sections_present() -> None:
    g = _graph(
        ("sqli", "high", "ref-0"),
        ("information_exposure", "informational", "ref-info"),
    )
    out = render_professional_report_markdown(g, client=_quiet_client())
    assert "## Confirmed Vulnerabilities" in out
    assert "## Informational Observations" in out
    assert out.index("## Confirmed Vulnerabilities") < out.index("## Informational Observations")


def test_unknown_vuln_class_falls_back_to_generic_wstg_info() -> None:
    g = _graph(("not_a_real_class", "medium", "ref-x"))
    out = render_professional_report_markdown(g, client=_quiet_client())
    assert "WSTG-INFO" in out
    assert "Review the finding evidence" in out


def test_report_card_orders_severity_critical_first() -> None:
    g = _graph(("sqli", "low", "ref-a"), ("xxe", "critical", "ref-b"))
    out = render_professional_report_markdown(g, client=_quiet_client())
    assert out.index("| Critical |") < out.index("| Low |")


def test_findings_sorted_by_severity_then_class_in_body() -> None:
    g = _graph(("sqli", "low", "ref-a"), ("xxe", "critical", "ref-b"))
    out = render_professional_report_markdown(g, client=_quiet_client())
    body = out[out.index("## Confirmed Vulnerabilities") :]
    assert body.index("xxe") < body.index("sqli")


def test_target_shown_when_provided() -> None:
    g = ReachabilityGraph()
    out = render_professional_report_markdown(
        g, client=_quiet_client(), target="http://example.test"
    )
    assert "**Target:** http://example.test" in out


def test_llm_narrative_used_as_executive_summary_when_available() -> None:
    g = _graph(("sqli", "high", "ref-0"))
    mock = Mock()
    mock.propose.return_value = {"narrative": "A SQL injection was confirmed."}
    out = render_professional_report_markdown(g, client=mock)
    assert "## Executive Summary" in out
    assert "A SQL injection was confirmed." in out
    assert out.index("## Executive Summary") < out.index("## Confirmed Vulnerabilities")


def test_no_secrets_leak_through_metadata_into_report() -> None:
    g = ReachabilityGraph()
    g.add_finding(
        Finding(
            vuln_class="sqli",
            severity="high",
            oracle_used="differential",
            evidence_ref="ref-0",
            status=FindingStatus.CONFIRMED_VIOLATION,
            metadata={"note": "token sk-supersecrettoken1234567890 seen in response"},
        )
    )
    out = render_professional_report_markdown(g, client=_quiet_client())
    assert "sk-supersecrettoken1234567890" not in out
