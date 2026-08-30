"""Focused Phase 12 report, export, redaction, and history checks."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from reachagent.execution.audit import AuditLog
from reachagent.graph.chain_solver import ChainSolver
from reachagent.graph.nodes import (
    Endpoint,
    Finding,
    FindingStatus,
    Host,
    Parameter,
    Service,
)
from reachagent.graph.persistence import dump_graph
from reachagent.graph.store import ReachabilityGraph
from reachagent.gui.app import _scans, app
from reachagent.report.renderer import (
    build_evidence_index,
    build_sarif_report,
    compare_persisted_snapshots,
    render_evidence_index_markdown,
    sanitize_report_markdown,
)


def _graph(*, extra: bool = False) -> tuple[ReachabilityGraph, AuditLog]:
    graph = ReachabilityGraph()
    audit = AuditLog()
    host = graph.add_host(Host(address="target.test", source="recon"))
    graph.add_service(host, Service(port=443, protocol="tcp", service_name="https"))
    endpoint = graph.add_endpoint(Endpoint(method="GET", path="/api/users/{id}"))
    graph.add_parameter(endpoint, Parameter(name="id", location="path"))
    graph.add_resolves_to(host, endpoint)
    graph.add_finding(
        Finding(
            vuln_class="bola",
            severity="high",
            oracle_used="differential",
            evidence_ref="evidence/bola/1",
            status=FindingStatus.CONFIRMED_VIOLATION,
            metadata={
                "scope": "target.test",
                "identity": "user_a",
                "tool": "payload_chain",
                "payload_ref": "payloads/bola/id",
                "chain_precondition": "cross_identity",
                "endpoint": "/api/users/{id}",
                "method": "GET",
                "timing_ms": "120",
                "evidence_metadata": (
                    '{"request_ref":"request-opaque-1","response_ref":"response-opaque-1"}'
                ),
            },
        )
    )
    if extra:
        graph.add_finding(
            Finding(
                vuln_class="ssrf",
                severity="medium",
                oracle_used="structural",
                evidence_ref="evidence/ssrf/2",
                status=FindingStatus.CONFIRMED_VIOLATION,
                metadata={"payload_ref": "payloads/ssrf/internal"},
            )
        )
    audit.record_oracle_result(
        "user_a", "https://target.test/api/users/{id}", "confirmed", evidence_ref="evidence/bola/1"
    )
    return graph, audit


def test_evidence_index_and_sarif_are_grounded_and_deterministic() -> None:
    graph, audit = _graph(extra=True)
    first = build_evidence_index(graph, audit, context={"run_id": "run-1", "scope": "target.test"})
    second = build_evidence_index(graph, audit, context={"run_id": "run-1", "scope": "target.test"})
    assert first == second
    assert first["summary"]["counts"]["findings"] == 2
    assert first["findings"][0]["evidence_handles"]["evidence_ref"] == "evidence/bola/1"
    assert first["findings"][0]["evidence_handles"]["request_ref"] == "request-opaque-1"
    assert first["findings"][0]["audit"]

    sarif = build_sarif_report(graph, context={"target": "https://target.test"})
    assert sarif["version"] == "2.1.0"
    results = sarif["runs"][0]["results"]
    assert len(results) == 2
    assert all(result["properties"]["oracle"] for result in results)
    assert "payloads/bola/id" in json.dumps(sarif)
    assert "raw-body" not in json.dumps(sarif)
    assert "confirmed_violation" not in {result["level"] for result in results}

    markdown = render_evidence_index_markdown(graph, audit)
    assert "Evidence index" in markdown
    assert "evidence/bola/1" in markdown


def test_report_sanitizer_removes_secret_shapes() -> None:
    source = (
        "Authorization: Bearer bearer-secret-value\n"
        "password=plain-secret\n"
        "Cookie: session=hidden-cookie\n"
        "https://user:password-value@target.test/private\n"
        "sk-abcdefghijklmnop\n"
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signature-value"
    )
    clean = sanitize_report_markdown(source)
    assert "bearer-secret-value" not in clean
    assert "plain-secret" not in clean
    assert "hidden-cookie" not in clean
    assert "password-value@" not in clean
    assert "sk-abcdefghijklmnop" not in clean
    assert "eyJhbGciOiJIUzI1NiJ9" not in clean


def test_gui_exports_include_sarif_evidence_bundle_and_redaction() -> None:
    graph, audit = _graph()
    scan_id = "phase12-export"
    _scans[scan_id] = {
        "target": "https://target.test",
        "in_scope": "target.test",
        "out_of_scope": None,
        "status": "done",
        "phase": "report",
        "graph": graph,
        "audit": audit,
        "events": [],
        "report_md": (
            "# Report\n\nAuthorization: Bearer bearer-secret-value\n"
            "password=plain-secret\nCookie: session=hidden-cookie"
        ),
    }
    client = TestClient(app)
    try:
        evidence = client.get(f"/api/scan/{scan_id}/evidence")
        assert evidence.status_code == 200
        assert evidence.json()["summary"]["counts"]["findings"] == 1

        sarif = client.get(f"/api/scan/{scan_id}/export?format=sarif")
        assert sarif.status_code == 200
        assert "application/sarif+json" in sarif.headers["content-type"]
        assert "bearer-secret-value" not in sarif.text

        bundle = client.get(f"/api/scan/{scan_id}/export?format=bundle")
        assert bundle.status_code == 200
        assert "plain-secret" not in bundle.text
        assert "evidence" in bundle.json()

        html = client.get(f"/api/scan/{scan_id}/export?format=html")
        assert html.status_code == 200
        assert "bearer-secret-value" not in html.text
        assert "hidden-cookie" not in html.text
        assert "Evidence index" in html.text

        markdown = client.get(f"/api/scan/{scan_id}/export?format=markdown")
        assert markdown.status_code == 200
        assert "plain-secret" not in markdown.text

        served = client.get(f"/api/report/{scan_id}")
        assert served.status_code == 200
        assert "bearer-secret-value" not in served.json()["report_md"]

        findings = client.get(f"/api/scan/{scan_id}/export?format=json")
        assert findings.status_code == 200
        assert findings.json()[0]["status"] == "confirmed_violation"
    finally:
        _scans.pop(scan_id, None)


def test_process_local_history_comparison_is_read_only() -> None:
    left, left_audit = _graph()
    right, right_audit = _graph(extra=True)
    left_id, right_id = "phase12-left", "phase12-right"
    _scans[left_id] = {"graph": left, "audit": left_audit}
    _scans[right_id] = {"graph": right, "audit": right_audit}
    try:
        response = TestClient(app).get(f"/api/scans/compare?left={left_id}&right={right_id}")
        assert response.status_code == 200
        body = response.json()
        assert body["delta"]["findings"] == 1
        assert body["findings"]["added"][0]["vuln_class"] == "ssrf"
    finally:
        _scans.pop(left_id, None)
        _scans.pop(right_id, None)


def test_persisted_history_comparison_uses_graph_and_audit_snapshots(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    left, left_audit = _graph()
    right, right_audit = _graph(extra=True)
    left_path, right_path = tmp_path / "left.json", tmp_path / "right.json"
    dump_graph(left, ChainSolver(left), left_audit, left_path)
    dump_graph(right, ChainSolver(right), right_audit, right_path)
    comparison = compare_persisted_snapshots(left_path, right_path)
    assert comparison["delta"]["findings"] == 1
    encoded = json.dumps(comparison)
    assert "secret" not in encoded.lower()
    assert str(tmp_path) not in encoded

    # The HTTP route accepts only JSON snapshots below the configured root.
    import os

    monkeypatch.setenv("REACHAGENT_HISTORY_DIR", str(tmp_path))
    client = TestClient(app)
    response = client.get(
        "/api/history/compare",
        params={"left": "left.json", "right": "right.json"},
    )
    assert response.status_code == 200
    blocked = client.get(
        "/api/history/compare",
        params={"left": "../left.json", "right": "right.json"},
    )
    assert blocked.status_code == 404
    assert os.environ.get("REACHAGENT_HISTORY_DIR") == str(tmp_path)


def test_json_export_does_not_require_narrative_report() -> None:
    graph, audit = _graph()
    scan_id = "phase12-json-without-report"
    _scans[scan_id] = {"graph": graph, "audit": audit, "report_md": ""}
    try:
        response = TestClient(app).get(f"/api/scan/{scan_id}/export?format=json")
        assert response.status_code == 200
        assert response.json()[0]["vuln_class"] == "bola"
    finally:
        _scans.pop(scan_id, None)
