"""Focused Phase 11 API and projection checks for the production workspace."""

from __future__ import annotations

import threading

from fastapi.testclient import TestClient

from reachagent.graph.nodes import Endpoint, Finding, FindingStatus
from reachagent.graph.store import ReachabilityGraph
from reachagent.gui.app import _ScanControl, _scans, app
from reachagent.scan.orchestrator import ScanEvent


def _scan(scan_id: str, *, graph: ReachabilityGraph | None = None) -> dict[str, object]:
    return {
        "target": "https://target.test",
        "status": "running",
        "lifecycle": "running",
        "phase": "payloads",
        "events": [
            ScanEvent("payloads", "step", "selecting a payload", {"tool": "scanner"}),
        ],
        "graph": graph,
        "audit": None,
        "report_md": "",
        "created_at": "2026-08-30T12:00:00+00:00",
        "updated_at": "2026-08-30T12:00:01+00:00",
        "finished_at": None,
        "control": _ScanControl(),
        "cancel_requested": False,
    }


def test_scan_status_uses_real_graph_counts_and_canonical_lifecycle() -> None:
    graph = ReachabilityGraph()
    graph.add_endpoint(Endpoint("GET", "/health"))
    scan_id = "phase11-status"
    _scans[scan_id] = _scan(scan_id, graph=graph)
    try:
        response = TestClient(app).get(f"/api/scan/{scan_id}")
        assert response.status_code == 200
        body = response.json()
        assert body["lifecycle"] == "running"
        assert body["graph"]["available"] is True
        assert body["graph"]["counts"]["endpoints"] == 1
        assert body["event_count"] == 1
        assert body["latest_event"]["message"] == "selecting a payload"
    finally:
        _scans.pop(scan_id, None)


def test_event_delta_redacts_secrets_and_ephemeral_handles() -> None:
    scan_id = "phase11-events"
    item = _scan(scan_id)
    item["events"] = [
        ScanEvent(
            "payloads",
            "step",
            "Authorization: Bearer secret-value",
            {"token": "secret-value", "fire_ref": "fire-abc", "safe": "kept"},
        )
    ]
    _scans[scan_id] = item
    try:
        body = TestClient(app).get(f"/api/scan/{scan_id}/events?after=0").json()
        event = body["events"][0]
        rendered = str(event)
        assert "secret-value" not in rendered
        assert "fire-abc" not in rendered
        assert event["details"]["safe"] == "kept"
    finally:
        _scans.pop(scan_id, None)


def test_cancel_is_cooperative_and_does_not_confirm_anything() -> None:
    scan_id = "phase11-cancel"
    item = _scan(scan_id)
    control = item["control"]
    assert isinstance(control, _ScanControl)
    assert isinstance(control.cancel_event, threading.Event)
    _scans[scan_id] = item
    try:
        response = TestClient(app).post(f"/api/scan/{scan_id}/cancel")
        assert response.status_code == 200
        # Cooperative: the worker's cancel_event is set; nothing is force-killed.
        assert control.cancel_event.is_set()
        assert response.json()["status"] == "cancelling"
        # W3: cancelling is now a DISTINCT lifecycle (was collapsed to "running"),
        # so the operator gets real feedback the cancel registered.
        assert response.json()["lifecycle"] == "cancelling"
        assert response.json()["counts"] == {}
    finally:
        _scans.pop(scan_id, None)


def test_history_contains_only_server_scans_and_real_finding_count() -> None:
    graph = ReachabilityGraph()
    graph.add_finding(
        Finding(
            vuln_class="ssrf",
            severity="high",
            oracle_used="structural",
            evidence_ref="phase11/evidence",
            status=FindingStatus.CONFIRMED_VIOLATION,
        )
    )
    scan_id = "phase11-history"
    _scans[scan_id] = _scan(scan_id, graph=graph)
    try:
        body = TestClient(app).get("/api/scans").json()
        row = next(item for item in body["scans"] if item["scan_id"] == scan_id)
        assert row["counts"]["findings"] == 1
        assert row["lifecycle"] == "running"
    finally:
        _scans.pop(scan_id, None)


def test_missing_graph_is_explicitly_unavailable() -> None:
    scan_id = "phase11-empty"
    _scans[scan_id] = _scan(scan_id)
    try:
        body = TestClient(app).get(f"/api/scan/{scan_id}").json()
        assert body["graph"]["available"] is False
        assert body["graph"]["counts"] == {}
    finally:
        _scans.pop(scan_id, None)
