"""Build Order v2 W2 — the Suspected/Unconfirmed tier.

A tried-but-unproven lead is recorded as a structurally-separate SuspectedFinding node,
never a Finding: it appears in its own report section and in the API snapshot, and NEVER in
graph.findings() or the confirmed section — so "no Finding without run_oracle" is untouched.
"""

from __future__ import annotations

from pathlib import Path

from reachagent.execution.audit import AuditLog
from reachagent.graph.chain_solver import ChainSolver
from reachagent.graph.nodes import SuspectedFinding
from reachagent.graph.persistence import dump_graph, load_graph
from reachagent.graph.store import ReachabilityGraph
from reachagent.report.professional import render_professional_report_markdown
from reachagent.scan.orchestrator import _ValidatorSeam


def test_suspected_finding_is_stored_separately_and_never_a_finding() -> None:
    graph = ReachabilityGraph()
    graph.add_suspected_finding(
        SuspectedFinding(
            vuln_class="sqli", endpoint="/login", location="user", source="oracle:sqli"
        )
    )
    assert len(graph.suspected_findings()) == 1
    assert graph.findings() == []  # the guarantee: never leaks into confirmed


def test_suspected_finding_is_idempotent_on_the_same_lead() -> None:
    graph = ReachabilityGraph()
    for _ in range(3):
        graph.add_suspected_finding(
            SuspectedFinding(vuln_class="sqli", endpoint="/x", location="q", source="oracle:sqli")
        )
    assert len(graph.suspected_findings()) == 1


def test_seam_record_suspected_writes_a_suspected_node_not_a_finding() -> None:
    graph = ReachabilityGraph()
    seam = _ValidatorSeam(graph)
    seam.record_suspected(
        "nosqli",
        endpoint="/api/users",
        location="filter",
        source="oracle:nosqli",
        reason="oracle_tested_no_confirmation",
        severity="high",
    )
    assert graph.findings() == []
    suspected = graph.suspected_findings()
    assert len(suspected) == 1
    _sid, s = suspected[0]
    assert s.vuln_class == "nosqli"
    assert s.reason == "oracle_tested_no_confirmation"


def test_report_renders_a_separate_suspected_section() -> None:
    graph = ReachabilityGraph()
    graph.add_suspected_finding(
        SuspectedFinding(
            vuln_class="command_injection",
            endpoint="/ping",
            location="host",
            source="signal-gated-tool",
            reason="scanner_claim_unverified",
        )
    )
    md = render_professional_report_markdown(graph)
    assert "Suspected / Unconfirmed (not oracle-verified)" in md
    # The suspected class must appear ONLY after the Suspected heading — never blended into the
    # confirmed portion above it (which, with no confirmed findings, says so explicitly).
    before, _, after = md.partition("Suspected / Unconfirmed")
    assert "command_injection" not in before
    assert "command_injection" in after
    assert "No findings were confirmed" in before


def test_empty_graph_has_no_suspected_section() -> None:
    md = render_professional_report_markdown(ReachabilityGraph())
    assert "Suspected / Unconfirmed" not in md


def test_persistence_round_trip_preserves_suspected_findings(tmp_path: Path) -> None:
    graph = ReachabilityGraph()
    graph.add_suspected_finding(
        SuspectedFinding(
            vuln_class="ldap_injection",
            endpoint="/auth",
            location="cn",
            source="oracle:ldap_injection",
            reason="oracle_tested_no_confirmation",
            severity="high",
        )
    )
    path = tmp_path / "state.json"
    dump_graph(graph, ChainSolver(graph), AuditLog(), path)
    loaded, _solver, _audit = load_graph(path)
    assert len(loaded.suspected_findings()) == 1
    _sid, s = loaded.suspected_findings()[0]
    assert s.vuln_class == "ldap_injection"
    assert s.reason == "oracle_tested_no_confirmation"
    assert loaded.findings() == []
