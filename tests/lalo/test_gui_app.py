"""Tests for the GUI's FastAPI backend: token gating and cursor-resumable WebSocket."""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

import lalo.gui.app as app_module
from lalo.core.errors import AllProvidersFailedError
from lalo.gui.app import build_app, generate_token
from lalo.gui.events import EventLog
from lalo.scan import ScanConfig


def _client(
    token: str = "test-token", *, runs_dir: Path | None = None
) -> tuple[TestClient, EventLog]:
    event_log = EventLog()
    app = build_app(event_log, token, runs_dir=runs_dir)
    return TestClient(app), event_log


class _FakeScanRunner:
    """Stands in for ScanRunner: no real Docker/LLM, just observable state."""

    block: threading.Event | None = None
    raises: Exception | None = None
    last_instance: _FakeScanRunner | None = None

    def __init__(self, config: object, *, env: object = None, event_log: object = None) -> None:
        self.config = config
        self.cancelled = False
        _FakeScanRunner.last_instance = self

    def run(self) -> None:
        if self.block is not None:
            self.block.wait(timeout=5)
        if self.raises is not None:
            raise self.raises

    def cancel(self) -> None:
        self.cancelled = True


def current_config() -> ScanConfig:
    """The ScanConfig the most recently constructed _FakeScanRunner received."""
    assert _FakeScanRunner.last_instance is not None
    return _FakeScanRunner.last_instance.config  # type: ignore[return-value]


def _wait_until(
    predicate: Callable[[], bool], *, timeout: float = 5.0, interval: float = 0.01
) -> bool:
    """Poll for a background-thread side effect - `done` firing inside the fake
    runner races the caller's own except/finally handling in app.py, which is
    what actually appends the event this waits for."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return predicate()


def test_generate_token_produces_a_real_unguessable_token() -> None:
    a, b = generate_token(), generate_token()
    assert a != b
    assert len(a) >= 32


def test_index_serves_the_spa_shell_unauthenticated() -> None:
    client, _ = _client()
    response = client.get("/")
    assert response.status_code == 200
    assert "L4L0" in response.text


def test_ws_rejects_a_missing_token() -> None:
    client, _ = _client()
    with pytest.raises(WebSocketDisconnect) as exc_info, client.websocket_connect("/ws"):
        pass
    assert exc_info.value.code == 4401


def test_ws_rejects_a_wrong_token() -> None:
    client, _ = _client(token="real-token")
    with (
        pytest.raises(WebSocketDisconnect) as exc_info,
        client.websocket_connect("/ws?token=wrong"),
    ):
        pass
    assert exc_info.value.code == 4401


def test_ws_with_a_valid_token_sends_a_full_snapshot() -> None:
    client, event_log = _client()
    event_log.append("log", {"text": "hello"})
    with client.websocket_connect("/ws?token=test-token") as ws:
        message = ws.receive_json()
    assert message["cursor"] == 1
    assert len(message["events"]) == 1
    assert message["events"][0]["payload"] == {"text": "hello"}


def test_ws_reconnect_with_a_cursor_only_receives_what_changed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import lalo.gui.app as app_module

    monkeypatch.setattr(app_module, "_POLL_INTERVAL_S", 0.01)
    client, event_log = _client()
    event_log.append("log", {"text": "old"})
    with client.websocket_connect("/ws?token=test-token") as ws:
        first = ws.receive_json()
    last_cursor = first["cursor"]

    event_log.append("log", {"text": "new"})
    with client.websocket_connect(f"/ws?token=test-token&cursor={last_cursor}") as ws:
        message = ws.receive_json()
    assert len(message["events"]) == 1
    assert message["events"][0]["payload"] == {"text": "new"}


def test_ws_rejects_a_cursor_outside_the_logs_history() -> None:
    client, _ = _client()
    with client.websocket_connect("/ws?token=test-token&cursor=999") as ws:
        data = ws.receive()
    assert data["type"] == "websocket.close"
    assert data["code"] == 4400


def test_ws_receives_a_live_update_pushed_after_connecting(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import lalo.gui.app as app_module

    monkeypatch.setattr(app_module, "_POLL_INTERVAL_S", 0.01)
    client, event_log = _client()
    with client.websocket_connect("/ws?token=test-token") as ws:
        initial = ws.receive_json()
        assert initial["events"] == []
        event_log.append("log", {"text": "live"})
        pushed = ws.receive_json()
    assert pushed["events"][0]["payload"] == {"text": "live"}


def test_steer_requires_a_valid_token() -> None:
    client, _ = _client(token="real-token")
    response = client.post("/steer?token=wrong", json={"text": "hi"})
    assert response.status_code == 403


def test_steer_requires_nonblank_text() -> None:
    client, _ = _client()
    response = client.post("/steer?token=test-token", json={"text": "   "})
    assert response.status_code == 400


def test_steer_appends_a_steering_event_and_nothing_else() -> None:
    client, event_log = _client()
    response = client.post("/steer?token=test-token", json={"text": "check the admin panel"})
    assert response.status_code == 200
    _cursor, events = event_log.snapshot()
    assert len(events) == 1
    assert events[0].category == "steering"
    assert events[0].payload == {"text": "check the admin panel"}


def test_status_requires_a_valid_token() -> None:
    client, _ = _client(token="real-token")
    response = client.get("/status?token=wrong")
    assert response.status_code == 403


def test_status_with_no_scan_run_yet() -> None:
    client, _ = _client()
    response = client.get("/status?token=test-token")
    assert response.status_code == 200
    assert response.json() == {
        "running": False,
        "cursor": 0,
        "findings_count": 0,
        "last_status": None,
    }


def test_status_counts_findings_and_reports_the_running_flag() -> None:
    client, event_log = _client()
    event_log.append("finding", {"finding_id": "f1"})
    event_log.append("finding", {"finding_id": "f2"})
    event_log.append("log", {"text": "noise"})
    response = client.get("/status?token=test-token")
    body = response.json()
    assert body["findings_count"] == 2
    assert body["running"] is False


def test_status_reports_the_most_recent_status_event() -> None:
    client, event_log = _client()
    event_log.append("status", {"event": "scan_started", "targets": ["example.com"]})
    event_log.append("status", {"event": "scan_completed", "status": "completed"})
    response = client.get("/status?token=test-token")
    assert response.json()["last_status"] == {"event": "scan_completed", "status": "completed"}


def test_list_runs_requires_a_valid_token(tmp_path: Path) -> None:
    client, _ = _client(token="real-token", runs_dir=tmp_path)
    response = client.get("/runs?token=wrong")
    assert response.status_code == 403


def test_list_runs_on_an_empty_runs_dir_is_empty(tmp_path: Path) -> None:
    client, _ = _client(runs_dir=tmp_path)
    response = client.get("/runs?token=test-token")
    assert response.json() == {"runs": []}


def test_list_runs_on_a_runs_dir_that_does_not_exist_yet_is_empty(tmp_path: Path) -> None:
    client, _ = _client(runs_dir=tmp_path / "never-created")
    response = client.get("/runs?token=test-token")
    assert response.json() == {"runs": []}


def test_list_runs_returns_mission_and_report_status_from_a_real_run_dir(
    tmp_path: Path,
) -> None:
    run_dir = tmp_path / "abc123"
    run_dir.mkdir()
    (run_dir / "resume_manifest.json").write_text(
        '{"mission": "find a bug", "target_specs": ["example.com"], "egress_lock": false}',
        encoding="utf-8",
    )
    (run_dir / "report.json").write_text("{}", encoding="utf-8")

    client, _ = _client(runs_dir=tmp_path)
    response = client.get("/runs?token=test-token")
    runs = response.json()["runs"]
    assert len(runs) == 1
    assert runs[0]["run_id"] == "abc123"
    assert runs[0]["mission"] == "find a bug"
    assert runs[0]["target_specs"] == ["example.com"]
    assert runs[0]["has_report"] is True


def test_list_runs_without_a_manifest_still_lists_with_no_mission(tmp_path: Path) -> None:
    (tmp_path / "no-manifest-yet").mkdir()
    client, _ = _client(runs_dir=tmp_path)
    runs = client.get("/runs?token=test-token").json()["runs"]
    assert runs[0]["run_id"] == "no-manifest-yet"
    assert runs[0]["mission"] is None
    assert runs[0]["has_report"] is False


def test_run_events_requires_a_valid_token(tmp_path: Path) -> None:
    client, _ = _client(token="real-token", runs_dir=tmp_path)
    response = client.get("/runs/abc123/events?token=wrong")
    assert response.status_code == 403


def test_run_events_on_an_unknown_run_id_is_404(tmp_path: Path) -> None:
    client, _ = _client(runs_dir=tmp_path)
    response = client.get("/runs/no-such-run/events?token=test-token")
    assert response.status_code == 404


def test_run_events_rejects_a_dot_dot_run_id(tmp_path: Path) -> None:
    client, _ = _client(runs_dir=tmp_path)
    response = client.get("/runs/../events?token=test-token")
    assert response.status_code in (400, 404)  # 404 if the router itself normalizes the path


def test_run_events_replays_a_persisted_runs_narration(tmp_path: Path) -> None:
    run_dir = tmp_path / "abc123"
    run_dir.mkdir()
    (run_dir / "events.jsonl").write_text(
        '{"category": "status", "payload": {"event": "scan_started"}}\n'
        '{"category": "finding", "payload": {"finding_id": "f1"}}\n',
        encoding="utf-8",
    )
    client, _ = _client(runs_dir=tmp_path)
    response = client.get("/runs/abc123/events?token=test-token")
    assert response.status_code == 200
    body = response.json()
    categories = [e["category"] for e in body["events"]]
    assert categories == ["status", "finding"]


def test_scan_requires_a_valid_token(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(app_module, "ScanRunner", _FakeScanRunner)
    client, _ = _client(token="real-token", runs_dir=tmp_path)
    response = client.post(
        "/scan?token=wrong", json={"mission": "find a bug", "targets": ["example.com"]}
    )
    assert response.status_code == 403


def test_scan_requires_mission_and_targets(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(app_module, "ScanRunner", _FakeScanRunner)
    client, _ = _client(runs_dir=tmp_path)
    response = client.post("/scan?token=test-token", json={"mission": "  ", "targets": []})
    assert response.status_code == 400


def test_scan_launches_a_runner_and_returns_a_run_dir(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(app_module, "ScanRunner", _FakeScanRunner)
    client, _ = _client(runs_dir=tmp_path)
    response = client.post(
        "/scan?token=test-token", json={"mission": "find a bug", "targets": ["example.com"]}
    )
    assert response.status_code == 200
    assert response.json()["ok"] is True
    assert Path(response.json()["run_dir"]).parent == tmp_path


def test_scan_request_passes_exclude_targets_through_to_scan_config(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(app_module, "ScanRunner", _FakeScanRunner)
    client, _ = _client(runs_dir=tmp_path)
    response = client.post(
        "/scan?token=test-token",
        json={
            "mission": "find a bug",
            "targets": ["*.example.com"],
            "exclude_targets": ["admin.example.com", "  "],
        },
    )
    assert response.status_code == 200
    # blank entries are stripped the same way `targets` already are
    assert current_config().exclude_target_specs == ["admin.example.com"]


def test_scan_request_defaults_exclude_targets_to_empty(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(app_module, "ScanRunner", _FakeScanRunner)
    client, _ = _client(runs_dir=tmp_path)
    client.post(
        "/scan?token=test-token", json={"mission": "find a bug", "targets": ["example.com"]}
    )
    assert current_config().exclude_target_specs == []


def test_scan_request_passes_rules_of_engagement_through_to_scan_config(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(app_module, "ScanRunner", _FakeScanRunner)
    client, _ = _client(runs_dir=tmp_path)
    client.post(
        "/scan?token=test-token",
        json={
            "mission": "find a bug",
            "targets": ["example.com"],
            "rules_of_engagement": "  no destructive testing  ",
        },
    )
    assert current_config().rules_of_engagement == "no destructive testing"


def test_scan_request_defaults_rules_of_engagement_to_empty(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(app_module, "ScanRunner", _FakeScanRunner)
    client, _ = _client(runs_dir=tmp_path)
    client.post(
        "/scan?token=test-token", json={"mission": "find a bug", "targets": ["example.com"]}
    )
    assert current_config().rules_of_engagement == ""


def test_scan_refuses_a_second_launch_while_one_is_running(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    block = threading.Event()
    _FakeScanRunner.block = block
    monkeypatch.setattr(app_module, "ScanRunner", _FakeScanRunner)
    try:
        client, _ = _client(runs_dir=tmp_path)
        body = {"mission": "find a bug", "targets": ["example.com"]}
        first = client.post("/scan?token=test-token", json=body)
        assert first.status_code == 200
        second = client.post("/scan?token=test-token", json=body)
        assert second.status_code == 409
    finally:
        block.set()
        _FakeScanRunner.block = None


def test_scan_stop_requires_a_running_scan(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(app_module, "ScanRunner", _FakeScanRunner)
    client, _ = _client(runs_dir=tmp_path)
    response = client.post("/scan/stop?token=test-token")
    assert response.status_code == 400


def test_scan_stop_cancels_the_current_runner(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    block = threading.Event()
    _FakeScanRunner.block = block
    monkeypatch.setattr(app_module, "ScanRunner", _FakeScanRunner)
    try:
        client, _ = _client(runs_dir=tmp_path)
        client.post(
            "/scan?token=test-token", json={"mission": "find a bug", "targets": ["example.com"]}
        )
        response = client.post("/scan/stop?token=test-token")
        assert response.status_code == 200
    finally:
        block.set()
        _FakeScanRunner.block = None


def test_status_reports_running_while_a_scan_is_in_flight(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    block = threading.Event()
    _FakeScanRunner.block = block
    monkeypatch.setattr(app_module, "ScanRunner", _FakeScanRunner)
    try:
        client, _ = _client(runs_dir=tmp_path)
        client.post(
            "/scan?token=test-token", json={"mission": "find a bug", "targets": ["example.com"]}
        )
        response = client.get("/status?token=test-token")
        assert response.json()["running"] is True
    finally:
        block.set()
        _FakeScanRunner.block = None


def test_a_failed_scan_emits_a_status_event_instead_of_dying_silently(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _FakeScanRunner.raises = RuntimeError("boom")
    monkeypatch.setattr(app_module, "ScanRunner", _FakeScanRunner)
    try:
        client, event_log = _client(runs_dir=tmp_path)
        client.post(
            "/scan?token=test-token", json={"mission": "find a bug", "targets": ["example.com"]}
        )

        def _failed_event_landed() -> bool:
            _cursor, events = event_log.snapshot()
            return any(
                e.category == "status" and e.payload.get("event") == "scan_failed" for e in events
            )

        assert _wait_until(_failed_event_landed)
    finally:
        _FakeScanRunner.raises = None


def test_a_failed_scan_with_all_providers_failed_surfaces_structured_per_provider_detail(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _FakeScanRunner.raises = AllProvidersFailedError(
        role="reasoning",
        failures=[("anthropic", "401 unauthorized"), ("openai", "timeout")],
    )
    monkeypatch.setattr(app_module, "ScanRunner", _FakeScanRunner)
    try:
        client, event_log = _client(runs_dir=tmp_path)
        client.post(
            "/scan?token=test-token", json={"mission": "find a bug", "targets": ["example.com"]}
        )

        def _failed_event() -> dict | None:
            _cursor, events = event_log.snapshot()
            for e in events:
                if e.category == "status" and e.payload.get("event") == "scan_failed":
                    return e.payload
            return None

        assert _wait_until(lambda: _failed_event() is not None)
        payload = _failed_event()
        assert payload is not None
        assert payload["role"] == "reasoning"
        assert payload["failures"] == [
            {"provider": "anthropic", "reason": "401 unauthorized"},
            {"provider": "openai", "reason": "timeout"},
        ]
    finally:
        _FakeScanRunner.raises = None


def test_a_failed_scan_with_a_plain_error_has_no_role_or_failures_fields(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _FakeScanRunner.raises = RuntimeError("boom")
    monkeypatch.setattr(app_module, "ScanRunner", _FakeScanRunner)
    try:
        client, event_log = _client(runs_dir=tmp_path)
        client.post(
            "/scan?token=test-token", json={"mission": "find a bug", "targets": ["example.com"]}
        )

        def _failed_event() -> dict | None:
            _cursor, events = event_log.snapshot()
            for e in events:
                if e.category == "status" and e.payload.get("event") == "scan_failed":
                    return e.payload
            return None

        assert _wait_until(lambda: _failed_event() is not None)
        payload = _failed_event()
        assert payload is not None
        assert "role" not in payload
        assert "failures" not in payload
    finally:
        _FakeScanRunner.raises = None
