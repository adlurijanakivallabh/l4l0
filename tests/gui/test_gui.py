"""Hermetic tests for the GUI's live-data serialization (real graph, no mocks)."""

from __future__ import annotations

import json

from fastapi.testclient import TestClient

from reachagent.execution.audit import AuditLog
from reachagent.graph.nodes import Finding, FindingStatus, Session
from reachagent.graph.store import ReachabilityGraph, session_id
from reachagent.gui.app import _finding_rows, _scans, app


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


# -- report export (real Phase 4 report served for download) -----------------


def _seeded_export_scan() -> str:
    g = ReachabilityGraph()
    g.add_finding(
        Finding(
            vuln_class="bola",
            severity="high",
            oracle_used="differential",
            evidence_ref="orchestrator/bola/1",
            status=FindingStatus.CONFIRMED_VIOLATION,
        )
    )
    sid = "t-export"
    _scans[sid] = {
        "target": "https://demo.example",
        "status": "done",
        "phase": "report",
        "graph": g,
        "audit": AuditLog(),
        "events": [],
        "report_md": (
            "# ReachAgent report\n\n| finding_id | vuln_class |\n"
            "|---|---|\n| finding:bola:1 | bola |"
        ),
    }
    return sid


def test_export_markdown_serves_the_report_for_download() -> None:
    sid = _seeded_export_scan()
    r = TestClient(app).get(f"/api/scan/{sid}/export?format=markdown")
    assert r.status_code == 200
    assert "text/markdown" in r.headers["content-type"]
    assert "attachment" in r.headers["content-disposition"]
    assert "ReachAgent report" in r.text


def test_export_json_serves_deterministic_findings() -> None:
    sid = _seeded_export_scan()
    r = TestClient(app).get(f"/api/scan/{sid}/export?format=json")
    assert r.status_code == 200
    assert "application/json" in r.headers["content-type"]
    rows = json.loads(r.text)
    assert rows[0]["vuln_class"] == "bola"
    assert rows[0]["status"] == "confirmed_violation"


def test_export_html_is_self_contained() -> None:
    sid = _seeded_export_scan()
    r = TestClient(app).get(f"/api/scan/{sid}/export?format=html")
    assert r.status_code == 200
    assert "text/html" in r.headers["content-type"]
    assert "ReachAgent report" in r.text


def test_export_unknown_format_defaults_markdown() -> None:
    sid = _seeded_export_scan()
    r = TestClient(app).get(f"/api/scan/{sid}/export?format=xml")
    assert r.status_code == 200
    assert "text/markdown" in r.headers["content-type"]
