"""Hermetic tests for the GUI's live-data serialization (real graph, no mocks)."""

from __future__ import annotations

from reachagent.graph.nodes import Finding, FindingStatus, Session
from reachagent.graph.store import ReachabilityGraph, session_id
from reachagent.gui.app import _finding_rows


def _g_with_chain() -> tuple[ReachabilityGraph, str, str]:
    """A graph with two confirmed findings linked by an enables edge, the second
    yielding a derived credential — the chain the dashboard must draw."""
    g = ReachabilityGraph()
    a = g.add_finding(
        Finding(
            vuln_class="bola",
            severity="high",
            oracle_used="differential",
            evidence_ref="orchestrator/bola/1",
            status=FindingStatus.CONFIRMED_VIOLATION,
        )
    )
    b = g.add_finding(
        Finding(
            vuln_class="ssrf",
            severity="high",
            oracle_used="structural",
            evidence_ref="orchestrator/ssrf/1",
            status=FindingStatus.CONFIRMED_VIOLATION,
        )
    )
    g.add_enables(a, b)
    g.add_session(Session(token_ref="tok1", identity_ref="admin"))
    g.add_derived_credential(b, session_id("tok1"))
    return g, a, b


def test_finding_rows_include_real_oracle_fields() -> None:
    g, a, _b = _g_with_chain()
    rows = {r["finding_id"]: r for r in _finding_rows(g)}
    row = rows[a]
    assert row["vuln_class"] == "bola"
    assert row["severity"] == "high"
    assert row["oracle_used"] == "differential"
    assert row["evidence_ref"] == "orchestrator/bola/1"
    assert row["status"] == "confirmed_violation"


def test_finding_rows_draw_the_connected_chain() -> None:
    g, a, b = _g_with_chain()
    rows = {r["finding_id"]: r for r in _finding_rows(g)}
    # The first finding's maximal chain is bola →enables→ ssrf →derived_credential→ session.
    assert rows[a]["chains"], "bola finding must show a chain"
    path = rows[a]["chains"][0]
    assert path["nodes"] == ["bola", "ssrf", "session"]
    assert path["kinds"] == ["enables", "derived_credential"]
    # The second finding's own chain continues from it.
    assert rows[b]["chains"][0]["nodes"] == ["ssrf", "session"]


def test_finding_rows_no_chain_is_empty() -> None:
    g = ReachabilityGraph()
    a = g.add_finding(
        Finding(
            vuln_class="clickjacking",
            severity="medium",
            oracle_used="structural",
            evidence_ref="orchestrator/clickjacking/",
            status=FindingStatus.CONFIRMED_VIOLATION,
        )
    )
    rows = {r["finding_id"]: r for r in _finding_rows(g)}
    assert rows[a]["chains"] == []
