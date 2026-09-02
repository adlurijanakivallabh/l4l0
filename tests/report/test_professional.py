"""Hermetic tests for the testfire-style professional report (Build Order 6)."""

from __future__ import annotations

from unittest.mock import Mock

from reachagent.graph.nodes import Finding, FindingStatus, SuspectedFinding
from reachagent.graph.store import ReachabilityGraph
from reachagent.report.professional import methodology_markdown, render_professional_report_markdown


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


def test_report_includes_a_real_methodology_section() -> None:
    out = render_professional_report_markdown(
        _graph(("sqli", "high", "ref-1")), client=_quiet_client(), target="http://x.test"
    )
    assert "## Methodology" in out
    assert "Proof standard" in out
    assert "http://x.test" in out.split("## Methodology", 1)[1].split("##", 1)[0]
    # Methodology must appear before the findings sections, not after.
    assert out.index("## Methodology") < out.index("## Confirmed Vulnerabilities")


def test_methodology_mentions_llm_leads_only_when_any_exist() -> None:
    graph = ReachabilityGraph()
    without = methodology_markdown(graph, target="http://x.test")
    assert "LLM surface-judgment pass" not in without

    graph.add_suspected_finding(
        SuspectedFinding(
            vuln_class="idor",
            endpoint="/api/orders/{id}",
            location="id",
            source="llm_judgment",
            reason="flagged by LLM surface review",
            severity="medium",
            confidence="advisory — not oracle-verified",
        )
    )
    with_lead = methodology_markdown(graph, target="http://x.test")
    assert "LLM surface-judgment pass" in with_lead
    assert "1 lead(s)" in with_lead


def test_methodology_never_confuses_oracle_proof_with_llm_judgment() -> None:
    out = methodology_markdown(ReachabilityGraph())
    assert "never to decide that a finding is confirmed" in out


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


def test_confirmed_finding_shows_the_real_captured_evidence_snippet() -> None:
    """v2 Phase 6 Stage E1: the report must show the actual proof text an oracle
    captured, not only an opaque evidence_ref handle string."""
    from reachagent.oracles.structural import (
        StructuralCheckType,
        StructuralEvidence,
        StructuralOracle,
    )
    from reachagent.tools import validator

    g = ReachabilityGraph()
    verdict = StructuralOracle().run(
        StructuralEvidence(
            check_type=StructuralCheckType.PATH_TRAVERSAL,
            probe_status=200,
            sentinel="root:x:0:0",
            response_body="prefix " * 20 + "root:x:0:0:root:/root:/bin/bash",
            evidence_ref="path_traversal/report-e2e",
        )
    )
    validator.write_finding(
        g,
        Finding(vuln_class="path_traversal", severity="high", oracle_used="", evidence_ref=""),
        verdict,
    )
    out = render_professional_report_markdown(g, client=_quiet_client())
    assert "root:x:0:0:root:/root:/bin/bash" in out
    assert "~~~" in out  # fenced evidence block, not just a `handle` reference


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


# === White-box section (Build Order 7) ======================================


def test_no_whitebox_section_when_no_repo_scan_facts_exist() -> None:
    g = _graph(("sqli", "high", "ref-0"))
    out = render_professional_report_markdown(g, client=_quiet_client())
    assert "Static Analysis (White-Box" not in out


def test_static_advisory_appears_in_its_own_section_never_as_a_finding() -> None:
    from reachagent.graph.nodes import StaticAdvisory

    g = ReachabilityGraph()
    g.add_static_advisory(
        StaticAdvisory(
            ecosystem="pypi",
            package="requests",
            version="2.6.0",
            cve_id="CVE-2015-2296",
            manifest="requirements.txt",
            cvss_score=5.0,
            epss_score=0.03498,
        )
    )
    out = render_professional_report_markdown(g, client=_quiet_client())

    assert "## Static Analysis (White-Box — Unconfirmed Reachability)" in out
    assert "### Known-Vulnerable Dependencies" in out
    assert "CVE-2015-2296" in out
    assert "requests" in out
    assert "5.0" in out
    assert "0.035" in out
    # Never presented as a confirmed vulnerability.
    assert "## Confirmed Vulnerabilities" not in out
    assert "No findings were confirmed" in out


def test_source_file_hit_appears_in_sast_section() -> None:
    from reachagent.graph.nodes import SourceFile

    g = ReachabilityGraph()
    g.add_source_file(
        SourceFile(
            path="app/db.py",
            rule_id="python.sql-injection",
            line=42,
            message="tainted query | with a pipe",
            severity="error",
        )
    )
    out = render_professional_report_markdown(g, client=_quiet_client())

    assert "### Static Analysis Hits (SAST)" in out
    assert "app/db.py" in out
    assert "python.sql-injection" in out
    # A literal pipe in the message must not break the markdown table.
    assert "tainted query \\| with a pipe" in out


def test_secret_hit_appears_in_secrets_section_without_its_value() -> None:
    from reachagent.graph.nodes import Secret

    g = ReachabilityGraph()
    g.add_secret(Secret(path="config/.env", line=3, detector="AWS", verified=True))
    out = render_professional_report_markdown(g, client=_quiet_client())

    assert "### Detected Secrets" in out
    assert "config/.env" in out
    assert "AWS" in out
    assert "yes" in out
    assert "never captured" in out


def test_whitebox_section_appears_after_the_findings_sections() -> None:
    from reachagent.graph.nodes import StaticAdvisory

    g = _graph(("sqli", "high", "ref-0"))
    g.add_static_advisory(
        StaticAdvisory(
            ecosystem="pypi",
            package="requests",
            version="2.6.0",
            cve_id="CVE-2015-2296",
            manifest="requirements.txt",
        )
    )
    out = render_professional_report_markdown(g, client=_quiet_client())

    assert out.index("## Confirmed Vulnerabilities") < out.index("## Static Analysis (White-Box")
