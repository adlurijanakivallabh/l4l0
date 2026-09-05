"""Tests for the GUI's FastAPI backend: token gating and cursor-resumable WebSocket."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from lalo.gui.app import build_app, generate_token
from lalo.gui.events import EventLog


def _client(token: str = "test-token") -> tuple[TestClient, EventLog]:
    event_log = EventLog()
    app = build_app(event_log, token)
    return TestClient(app), event_log


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
