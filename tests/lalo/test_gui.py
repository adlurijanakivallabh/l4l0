"""GUI tests: scan launch, status, and cursor-resumable WebSocket streaming."""

from __future__ import annotations

import time

from fastapi.testclient import TestClient

from lalo.gui.app import ScanManager, build_app


def _fake_scan(manager: ScanManager, scan_id: str) -> None:
    manager.push_event(scan_id, {"type": "log", "line": "recon"})
    manager.add_finding(
        scan_id,
        {
            "id": "abc",
            "title": "Reflected XSS",
            "vuln_class": "xss",
            "severity": "high",
            "confidence": 72.0,
            "target": "https://app/x",
        },
    )
    manager.push_event(scan_id, {"type": "log", "line": "done"})


def _client() -> TestClient:
    return TestClient(build_app(ScanManager(scan_fn=_fake_scan)))


def _wait_completed(client: TestClient, scan_id: str) -> dict[str, object]:
    for _ in range(100):
        state = client.get(f"/api/scan/{scan_id}").json()
        if state["status"] in ("completed", "error"):
            return state
        time.sleep(0.02)
    raise AssertionError("scan did not complete")


def test_index_served() -> None:
    body = _client().get("/").text
    assert "L4L0" in body


def test_scan_launch_and_status() -> None:
    client = _client()
    scan_id = client.post("/api/scan", json={"targets": ["app"], "objective": "test"}).json()[
        "scan_id"
    ]
    state = _wait_completed(client, scan_id)
    assert state["status"] == "completed"
    assert len(state["findings"]) == 1
    assert state["findings"][0]["vuln_class"] == "xss"


def test_websocket_streams_events() -> None:
    client = _client()
    scan_id = client.post("/api/scan", json={"targets": ["app"], "objective": "t"}).json()[
        "scan_id"
    ]
    _wait_completed(client, scan_id)
    with client.websocket_connect(f"/ws/{scan_id}") as ws:
        seen_types = []
        for _ in range(10):
            ev = ws.receive_json()
            seen_types.append(ev["type"])
            if ev["type"] == "status" and ev.get("status") == "completed":
                break
    assert "finding" in seen_types
    assert "log" in seen_types


def test_websocket_cursor_resume() -> None:
    client = _client()
    scan_id = client.post("/api/scan", json={"targets": ["app"], "objective": "t"}).json()[
        "scan_id"
    ]
    state = _wait_completed(client, scan_id)
    total = int(state["event_count"])  # type: ignore[arg-type]
    # Reconnect from a cursor near the end -> only later events replay.
    with client.websocket_connect(f"/ws/{scan_id}?cursor={total - 1}") as ws:
        ev = ws.receive_json()
        assert ev["seq"] >= total - 1
