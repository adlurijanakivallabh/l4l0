"""Tests for the GUI's FastAPI backend: a cursor-resumable WebSocket + a minimal SPA shell."""

from __future__ import annotations

import os
import threading
import time
from collections.abc import Callable
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import lalo.gui.app as app_module
from lalo.core.errors import AllProvidersFailedError
from lalo.gui.app import build_app
from lalo.gui.events import EventLog
from lalo.scan import ScanConfig


def _client(*, runs_dir: Path | None = None) -> tuple[TestClient, EventLog]:
    event_log = EventLog()
    app = build_app(event_log, runs_dir=runs_dir)
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


def test_index_serves_the_spa_shell() -> None:
    client, _ = _client()
    response = client.get("/")
    assert response.status_code == 200
    assert "L4L0" in response.text


def test_ws_sends_a_full_snapshot() -> None:
    client, event_log = _client()
    event_log.append("log", {"text": "hello"})
    with client.websocket_connect("/ws") as ws:
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
    with client.websocket_connect("/ws") as ws:
        first = ws.receive_json()
    last_cursor = first["cursor"]

    event_log.append("log", {"text": "new"})
    with client.websocket_connect(f"/ws?cursor={last_cursor}") as ws:
        message = ws.receive_json()
    assert len(message["events"]) == 1
    assert message["events"][0]["payload"] == {"text": "new"}


def test_ws_rejects_a_cursor_outside_the_logs_history() -> None:
    client, _ = _client()
    with client.websocket_connect("/ws?cursor=999") as ws:
        data = ws.receive()
    assert data["type"] == "websocket.close"
    assert data["code"] == 4400


def test_ws_receives_a_live_update_pushed_after_connecting(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import lalo.gui.app as app_module

    monkeypatch.setattr(app_module, "_POLL_INTERVAL_S", 0.01)
    client, event_log = _client()
    with client.websocket_connect("/ws") as ws:
        initial = ws.receive_json()
        assert initial["events"] == []
        event_log.append("log", {"text": "live"})
        pushed = ws.receive_json()
    assert pushed["events"][0]["payload"] == {"text": "live"}


def test_steer_requires_nonblank_text() -> None:
    client, _ = _client()
    response = client.post("/steer", json={"text": "   "})
    assert response.status_code == 400


def test_steer_appends_a_steering_event_and_nothing_else() -> None:
    client, event_log = _client()
    response = client.post("/steer", json={"text": "check the admin panel"})
    assert response.status_code == 200
    _cursor, events = event_log.snapshot()
    assert len(events) == 1
    assert events[0].category == "steering"
    assert events[0].payload == {"text": "check the admin panel"}


def test_status_with_no_scan_run_yet() -> None:
    client, _ = _client()
    response = client.get("/status")
    assert response.status_code == 200
    assert response.json() == {
        "running": False,
        "cursor": 0,
        "findings_count": 0,
        "last_status": None,
        "active_run_ids": [],
    }


def test_status_counts_findings_and_reports_the_running_flag() -> None:
    client, event_log = _client()
    event_log.append("finding", {"finding_id": "f1"})
    event_log.append("finding", {"finding_id": "f2"})
    event_log.append("log", {"text": "noise"})
    response = client.get("/status")
    body = response.json()
    assert body["findings_count"] == 2
    assert body["running"] is False


def test_status_reports_the_most_recent_status_event() -> None:
    client, event_log = _client()
    event_log.append("status", {"event": "scan_started", "targets": ["example.com"]})
    event_log.append("status", {"event": "scan_completed", "status": "completed"})
    response = client.get("/status")
    assert response.json()["last_status"] == {"event": "scan_completed", "status": "completed"}


def test_list_runs_on_an_empty_runs_dir_is_empty(tmp_path: Path) -> None:
    client, _ = _client(runs_dir=tmp_path)
    response = client.get("/runs")
    assert response.json() == {"runs": []}


def test_list_runs_on_a_runs_dir_that_does_not_exist_yet_is_empty(tmp_path: Path) -> None:
    client, _ = _client(runs_dir=tmp_path / "never-created")
    response = client.get("/runs")
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
    (run_dir / "report.md").write_text("# report", encoding="utf-8")

    client, _ = _client(runs_dir=tmp_path)
    response = client.get("/runs")
    runs = response.json()["runs"]
    assert len(runs) == 1
    assert runs[0]["run_id"] == "abc123"
    assert runs[0]["mission"] == "find a bug"
    assert runs[0]["target_specs"] == ["example.com"]
    assert runs[0]["has_report"] is True
    assert set(runs[0]["report_formats"]) == {"json", "md"}


def test_list_runs_without_a_manifest_still_lists_with_no_mission(tmp_path: Path) -> None:
    (tmp_path / "no-manifest-yet").mkdir()
    client, _ = _client(runs_dir=tmp_path)
    runs = client.get("/runs").json()["runs"]
    assert runs[0]["run_id"] == "no-manifest-yet"
    assert runs[0]["mission"] is None
    assert runs[0]["has_report"] is False
    assert runs[0]["report_formats"] == []


def test_list_runs_report_formats_reflects_a_partial_pdf_failure(tmp_path: Path) -> None:
    """pdf/docx are each independently best-effort at write time - a run
    with a canonical report but no pdf must not silently claim it has one."""
    run_dir = tmp_path / "abc123"
    run_dir.mkdir()
    (run_dir / "report.json").write_text("{}", encoding="utf-8")
    (run_dir / "report.md").write_text("# report", encoding="utf-8")
    # no report.pdf / report.docx written for this run
    client, _ = _client(runs_dir=tmp_path)
    runs = client.get("/runs").json()["runs"]
    assert "pdf" not in runs[0]["report_formats"]
    assert "docx" not in runs[0]["report_formats"]


def test_run_report_rejects_an_unknown_format(tmp_path: Path) -> None:
    run_dir = tmp_path / "abc123"
    run_dir.mkdir()
    (run_dir / "report.md").write_text("# report", encoding="utf-8")
    client, _ = _client(runs_dir=tmp_path)
    response = client.get("/runs/abc123/report/exe")
    assert response.status_code == 400


def test_run_report_on_a_missing_file_is_404(tmp_path: Path) -> None:
    run_dir = tmp_path / "abc123"
    run_dir.mkdir()
    client, _ = _client(runs_dir=tmp_path)
    response = client.get("/runs/abc123/report/pdf")
    assert response.status_code == 404


def test_run_report_rejects_a_dot_dot_run_id(tmp_path: Path) -> None:
    client, _ = _client(runs_dir=tmp_path)
    response = client.get("/runs/../report/md")
    assert response.status_code in (400, 404)


def test_run_report_serves_the_real_file_with_the_right_media_type(tmp_path: Path) -> None:
    run_dir = tmp_path / "abc123"
    run_dir.mkdir()
    (run_dir / "report.md").write_text("# a real report\n", encoding="utf-8")
    client, _ = _client(runs_dir=tmp_path)
    response = client.get("/runs/abc123/report/md")
    assert response.status_code == 200
    assert response.content == b"# a real report\n"
    assert response.headers["content-type"].startswith("text/markdown")


def test_run_report_serves_csv_with_the_right_media_type(tmp_path: Path) -> None:
    run_dir = tmp_path / "abc123"
    run_dir.mkdir()
    (run_dir / "findings.csv").write_text("finding_id,title\nf1,SQLi\n", encoding="utf-8")
    client, _ = _client(runs_dir=tmp_path)
    response = client.get("/runs/abc123/report/csv")
    assert response.status_code == 200
    assert response.content == b"finding_id,title\nf1,SQLi\n"
    assert response.headers["content-type"].startswith("text/csv")


def test_list_runs_report_formats_includes_csv(tmp_path: Path) -> None:
    run_dir = tmp_path / "abc123"
    run_dir.mkdir()
    (run_dir / "report.json").write_text("{}", encoding="utf-8")
    (run_dir / "findings.csv").write_text("finding_id,title\n", encoding="utf-8")
    client, _ = _client(runs_dir=tmp_path)
    runs = client.get("/runs").json()["runs"]
    assert "csv" in runs[0]["report_formats"]


def test_run_events_on_an_unknown_run_id_is_404(tmp_path: Path) -> None:
    client, _ = _client(runs_dir=tmp_path)
    response = client.get("/runs/no-such-run/events")
    assert response.status_code == 404


def test_run_events_rejects_a_dot_dot_run_id(tmp_path: Path) -> None:
    client, _ = _client(runs_dir=tmp_path)
    response = client.get("/runs/../events")
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
    response = client.get("/runs/abc123/events")
    assert response.status_code == 200
    body = response.json()
    categories = [e["category"] for e in body["events"]]
    assert categories == ["status", "finding"]


def test_scan_requires_mission_and_targets(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(app_module, "ScanRunner", _FakeScanRunner)
    client, _ = _client(runs_dir=tmp_path)
    response = client.post("/scan", json={"mission": "  ", "targets": []})
    assert response.status_code == 400


def test_scan_launches_a_runner_and_returns_a_run_dir(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(app_module, "ScanRunner", _FakeScanRunner)
    client, _ = _client(runs_dir=tmp_path)
    response = client.post("/scan", json={"mission": "find a bug", "targets": ["example.com"]})
    assert response.status_code == 200
    assert response.json()["ok"] is True
    assert Path(response.json()["run_dir"]).parent == tmp_path


def test_scan_resume_run_id_on_a_run_with_no_manifest_is_404(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(app_module, "ScanRunner", _FakeScanRunner)
    client, _ = _client(runs_dir=tmp_path)
    response = client.post("/scan", json={"resume_run_id": "no-such-run"})
    assert response.status_code == 404


def test_scan_resume_run_id_rejects_a_dot_dot_run_id(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(app_module, "ScanRunner", _FakeScanRunner)
    client, _ = _client(runs_dir=tmp_path)
    response = client.post("/scan", json={"resume_run_id": ".."})
    assert response.status_code == 400


def test_scan_resume_run_id_rejects_a_real_path_traversal_payload(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The actual bug a security review caught: unlike /runs/{run_id}/...,
    resume_run_id is a JSON body string with no Starlette path-segment
    protection against an embedded "/" - a bare ".", ".." check (the
    original, insufficient fix) lets "../escaped_dir" straight through to
    runs_dir / run_id, escaping runs_dir entirely. A real manifest placed
    outside runs_dir proves the traversal would otherwise have worked."""
    monkeypatch.setattr(app_module, "ScanRunner", _FakeScanRunner)
    runs_dir = tmp_path / "runs"
    runs_dir.mkdir()
    escaped_dir = tmp_path / "escaped_dir"
    escaped_dir.mkdir()
    (escaped_dir / "resume_manifest.json").write_text(
        '{"mission": "escaped the runs directory", "target_specs": ["evil.example.com"], '
        '"egress_lock": false}',
        encoding="utf-8",
    )
    client, _ = _client(runs_dir=runs_dir)
    response = client.post("/scan", json={"resume_run_id": "../escaped_dir"})
    assert response.status_code == 400


def test_scan_resume_run_id_reads_the_locked_fields_from_the_manifest_not_the_request(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Closes a real gap: /scan always minted a fresh run_dir, so a
    crashed/stopped run's own persisted manifest could never be matched
    again - scan.py's real resume mechanism (DurableJournal,
    _ResumeManifest) was genuine and unit-tested but structurally
    unreachable through the one interface this project actually has."""
    monkeypatch.setattr(app_module, "ScanRunner", _FakeScanRunner)
    run_dir = tmp_path / "abc123"
    run_dir.mkdir()
    (run_dir / "resume_manifest.json").write_text(
        '{"mission": "the ORIGINAL authorized mission", '
        '"target_specs": ["original.example.com"], "egress_lock": false}',
        encoding="utf-8",
    )
    client, _ = _client(runs_dir=tmp_path)
    # Any mission/targets in the request body must be ignored for a resume -
    # only the manifest's own locked fields may ever reach ScanConfig.
    response = client.post(
        "/scan",
        json={
            "resume_run_id": "abc123",
            "mission": "a DIFFERENT, unauthorized mission",
            "targets": ["evil.example.com"],
        },
    )
    assert response.status_code == 200
    config = current_config()
    assert config.mission == "the ORIGINAL authorized mission"
    assert config.target_specs == ["original.example.com"]
    assert config.run_dir == run_dir


def test_scan_request_passes_exclude_targets_through_to_scan_config(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(app_module, "ScanRunner", _FakeScanRunner)
    client, _ = _client(runs_dir=tmp_path)
    response = client.post(
        "/scan",
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
    client.post("/scan", json={"mission": "find a bug", "targets": ["example.com"]})
    assert current_config().exclude_target_specs == []


def test_scan_request_passes_rules_of_engagement_through_to_scan_config(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(app_module, "ScanRunner", _FakeScanRunner)
    client, _ = _client(runs_dir=tmp_path)
    client.post(
        "/scan",
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
    client.post("/scan", json={"mission": "find a bug", "targets": ["example.com"]})
    assert current_config().rules_of_engagement == ""


def test_scan_resume_refuses_relaunching_the_same_run_id_while_running(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A fresh launch always mints a new run_id (never a collision, see
    test_scan_allows_two_concurrent_fresh_launches below) - the 409 only
    guards against relaunching the SAME run_id (via resume_run_id) while
    it's already running."""
    block = threading.Event()
    _FakeScanRunner.block = block
    monkeypatch.setattr(app_module, "ScanRunner", _FakeScanRunner)
    run_dir = tmp_path / "abc123"
    run_dir.mkdir()
    (run_dir / "resume_manifest.json").write_text(
        '{"mission": "find a bug", "target_specs": ["example.com"], "egress_lock": false}',
        encoding="utf-8",
    )
    try:
        client, _ = _client(runs_dir=tmp_path)
        first = client.post("/scan", json={"resume_run_id": "abc123"})
        assert first.status_code == 200
        second = client.post("/scan", json={"resume_run_id": "abc123"})
        assert second.status_code == 409
    finally:
        block.set()
        _FakeScanRunner.block = None


def test_scan_allows_two_concurrent_fresh_launches(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Superset of the old single-scan ceiling: the GUI supports genuinely
    concurrent scans, each with its own run_id and its own live event
    stream (see test_status_scoped_to_a_specific_non_primary_run_id,
    test_ws_streams_a_specific_non_primary_run_id below)."""
    block = threading.Event()
    _FakeScanRunner.block = block
    monkeypatch.setattr(app_module, "ScanRunner", _FakeScanRunner)
    try:
        client, _ = _client(runs_dir=tmp_path)
        body = {"mission": "find a bug", "targets": ["example.com"]}
        first = client.post("/scan", json=body)
        second = client.post("/scan", json=body)
        assert first.status_code == 200
        assert second.status_code == 200
        first_id, second_id = first.json()["run_id"], second.json()["run_id"]
        assert first_id != second_id
        active = client.get("/status").json()["active_run_ids"]
        assert set(active) == {first_id, second_id}
    finally:
        block.set()
        _FakeScanRunner.block = None


def test_status_scoped_to_a_specific_non_primary_run_id(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    block = threading.Event()
    _FakeScanRunner.block = block
    monkeypatch.setattr(app_module, "ScanRunner", _FakeScanRunner)
    try:
        client, primary_log = _client(runs_dir=tmp_path)
        body = {"mission": "find a bug", "targets": ["example.com"]}
        client.post("/scan", json=body)
        second_id = client.post("/scan", json=body).json()["run_id"]
        primary_log.append("finding", {"finding_id": "only-in-primary"})
        assert client.get("/status").json()["findings_count"] == 1
        assert client.get(f"/status?run_id={second_id}").json()["findings_count"] == 0
    finally:
        block.set()
        _FakeScanRunner.block = None


def test_ws_streams_a_specific_non_primary_run_id(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    block = threading.Event()
    _FakeScanRunner.block = block
    monkeypatch.setattr(app_module, "ScanRunner", _FakeScanRunner)
    try:
        client, primary_log = _client(runs_dir=tmp_path)
        body = {"mission": "find a bug", "targets": ["example.com"]}
        client.post("/scan", json=body)
        second_id = client.post("/scan", json=body).json()["run_id"]
        primary_log.append("log", {"text": "primary-only"})
        with client.websocket_connect(f"/ws?run_id={second_id}") as ws:
            message = ws.receive_json()
        assert message["events"] == []
    finally:
        block.set()
        _FakeScanRunner.block = None


def test_ws_closes_with_an_error_for_an_unknown_run_id() -> None:
    client, _ = _client()
    with client.websocket_connect("/ws?run_id=no-such-run") as ws:
        data = ws.receive()
    assert data["type"] == "websocket.close"
    assert data["code"] == 4404


def test_scan_stop_is_scoped_to_the_named_run_id(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    block = threading.Event()
    _FakeScanRunner.block = block
    monkeypatch.setattr(app_module, "ScanRunner", _FakeScanRunner)
    try:
        client, _ = _client(runs_dir=tmp_path)
        body = {"mission": "find a bug", "targets": ["example.com"]}
        client.post("/scan", json=body)
        second_id = client.post("/scan", json=body).json()["run_id"]
        # An unrelated/unknown run_id is refused even though scans are
        # genuinely running.
        assert client.post("/scan/stop?run_id=not-a-real-run").status_code == 400
        assert client.post(f"/scan/stop?run_id={second_id}").status_code == 200
    finally:
        block.set()
        _FakeScanRunner.block = None


def test_steer_is_scoped_to_the_named_run_id(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    block = threading.Event()
    _FakeScanRunner.block = block
    monkeypatch.setattr(app_module, "ScanRunner", _FakeScanRunner)
    try:
        client, primary_log = _client(runs_dir=tmp_path)
        body = {"mission": "find a bug", "targets": ["example.com"]}
        client.post("/scan", json=body)
        second_id = client.post("/scan", json=body).json()["run_id"]
        response = client.post(f"/steer?run_id={second_id}", json={"text": "check admin panel"})
        assert response.status_code == 200
        with client.websocket_connect(f"/ws?run_id={second_id}") as ws:
            message = ws.receive_json()
        assert message["events"][-1]["payload"] == {"text": "check admin panel"}
        assert primary_log.snapshot()[1] == []
    finally:
        block.set()
        _FakeScanRunner.block = None


def test_list_runs_marks_multiple_concurrently_running_runs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    block = threading.Event()
    _FakeScanRunner.block = block
    monkeypatch.setattr(app_module, "ScanRunner", _FakeScanRunner)
    try:
        client, _ = _client(runs_dir=tmp_path)
        body = {"mission": "find a bug", "targets": ["example.com"]}
        first = client.post("/scan", json=body)
        second = client.post("/scan", json=body)
        for response in (first, second):
            Path(response.json()["run_dir"]).mkdir(parents=True, exist_ok=True)
        runs = {r["run_id"]: r["running"] for r in client.get("/runs").json()["runs"]}
        assert runs[first.json()["run_id"]] is True
        assert runs[second.json()["run_id"]] is True
    finally:
        block.set()
        _FakeScanRunner.block = None


def test_scan_stop_requires_a_running_scan(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(app_module, "ScanRunner", _FakeScanRunner)
    client, _ = _client(runs_dir=tmp_path)
    response = client.post("/scan/stop")
    assert response.status_code == 400


def test_scan_stop_cancels_the_current_runner(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    block = threading.Event()
    _FakeScanRunner.block = block
    monkeypatch.setattr(app_module, "ScanRunner", _FakeScanRunner)
    try:
        client, _ = _client(runs_dir=tmp_path)
        client.post("/scan", json={"mission": "find a bug", "targets": ["example.com"]})
        response = client.post("/scan/stop")
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
        client.post("/scan", json={"mission": "find a bug", "targets": ["example.com"]})
        response = client.get("/status")
        assert response.json()["running"] is True
    finally:
        block.set()
        _FakeScanRunner.block = None


def test_list_runs_marks_the_currently_running_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    block = threading.Event()
    _FakeScanRunner.block = block
    monkeypatch.setattr(app_module, "ScanRunner", _FakeScanRunner)
    try:
        client, _ = _client(runs_dir=tmp_path)
        response = client.post("/scan", json={"mission": "find a bug", "targets": ["example.com"]})
        run_dir = Path(response.json()["run_dir"])
        # _FakeScanRunner never touches the filesystem, unlike the real
        # ScanRunner.run() (which mkdir()s run_dir as its very first action)
        # - created here so _list_runs' filesystem enumeration sees it.
        run_dir.mkdir(parents=True, exist_ok=True)
        runs = client.get("/runs").json()["runs"]
        assert len(runs) == 1
        assert runs[0]["run_id"] == run_dir.name
        assert runs[0]["running"] is True
    finally:
        block.set()
        _FakeScanRunner.block = None


def test_list_runs_reports_false_for_a_completed_run(tmp_path: Path) -> None:
    (tmp_path / "abc123").mkdir()
    client, _ = _client(runs_dir=tmp_path)
    runs = client.get("/runs").json()["runs"]
    assert runs[0]["running"] is False


def test_a_failed_scan_emits_a_status_event_instead_of_dying_silently(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _FakeScanRunner.raises = RuntimeError("boom")
    monkeypatch.setattr(app_module, "ScanRunner", _FakeScanRunner)
    try:
        client, event_log = _client(runs_dir=tmp_path)
        client.post("/scan", json={"mission": "find a bug", "targets": ["example.com"]})

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
        client.post("/scan", json={"mission": "find a bug", "targets": ["example.com"]})

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
        client.post("/scan", json={"mission": "find a bug", "targets": ["example.com"]})

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


def test_get_settings_providers_reports_which_are_configured(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-real")
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    client, _ = _client(runs_dir=tmp_path)
    response = client.get("/settings/providers")
    assert response.status_code == 200
    providers = {p["id"]: p["configured"] for p in response.json()["providers"]}
    assert providers["anthropic"] is True
    assert providers["openai"] is False


def test_post_settings_providers_verifies_and_writes_env_and_updates_process_env(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # setenv (not delenv(raising=False)) so monkeypatch records an undo even
    # though this key isn't already set - the route mutates os.environ for
    # real, and delenv(raising=False) on an absent key leaves no teardown,
    # which leaked ANTHROPIC_API_KEY into every later test in this session.
    monkeypatch.setenv("ANTHROPIC_API_KEY", "placeholder")
    env_path = tmp_path / ".env"
    monkeypatch.setattr(app_module, "_SETTINGS_ENV_PATH", env_path)
    monkeypatch.setattr(app_module, "verify_router", lambda _router: {"anthropic": (True, "ok")})
    client, _ = _client(runs_dir=tmp_path)
    response = client.post(
        "/settings/providers",
        json={"provider_id": "anthropic", "api_key": "sk-ant-real", "extra": {}},
    )
    assert response.status_code == 200
    assert env_path.read_text(encoding="utf-8") == "ANTHROPIC_API_KEY=sk-ant-real\n"
    assert os.environ["ANTHROPIC_API_KEY"] == "sk-ant-real"  # picked up by THIS process immediately


def test_post_settings_providers_writes_nothing_on_failed_verification(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    env_path = tmp_path / ".env"
    monkeypatch.setattr(app_module, "_SETTINGS_ENV_PATH", env_path)
    monkeypatch.setattr(
        app_module, "verify_router", lambda _router: {"anthropic": (False, "401 unauthorized")}
    )
    client, _ = _client(runs_dir=tmp_path)
    response = client.post(
        "/settings/providers",
        json={"provider_id": "anthropic", "api_key": "sk-ant-bad", "extra": {}},
    )
    assert response.status_code == 400
    assert not env_path.exists()


def test_post_settings_providers_rejects_an_unknown_provider_id(
    tmp_path: Path,
) -> None:
    client, _ = _client(runs_dir=tmp_path)
    response = client.post(
        "/settings/providers",
        json={"provider_id": "not-a-real-provider", "api_key": "x", "extra": {}},
    )
    assert response.status_code == 400


def test_post_settings_providers_rejects_an_unexpected_extra_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`extra` is restricted to a provider's own `extra_required_envs` - it must
    not be a way to set arbitrary environment variable names (an injection
    point into both .env and this process's os.environ)."""
    env_path = tmp_path / ".env"
    monkeypatch.setattr(app_module, "_SETTINGS_ENV_PATH", env_path)
    client, _ = _client(runs_dir=tmp_path)
    response = client.post(
        "/settings/providers",
        json={
            "provider_id": "anthropic",
            "api_key": "sk-ant-real",
            "extra": {"SOME_INJECTED_VAR": "evil"},
        },
    )
    assert response.status_code == 400
    assert not env_path.exists()
    assert "SOME_INJECTED_VAR" not in os.environ


def test_scan_request_advanced_options_pass_through_to_scan_config(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(app_module, "ScanRunner", _FakeScanRunner)
    client, _ = _client(runs_dir=tmp_path)
    client.post(
        "/scan",
        json={
            "mission": "find a bug",
            "targets": ["example.com"],
            "max_steps": 10,
            "budget_ceiling": 50,
            "egress_lock": True,
            "redact_findings": True,
        },
    )
    config = current_config()
    assert config.max_steps == 10
    assert config.budget_ceiling == 50
    assert config.redact_findings is True
    assert config.egress_lock is True


def test_scan_request_advanced_options_default_to_scan_configs_own_defaults(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(app_module, "ScanRunner", _FakeScanRunner)
    client, _ = _client(runs_dir=tmp_path)
    client.post("/scan", json={"mission": "find a bug", "targets": ["example.com"]})
    config = current_config()
    assert config.max_steps == 40
    assert config.budget_ceiling == 300
    assert config.egress_lock is False
    assert config.redact_findings is False


def test_scan_derives_targets_from_mission_when_none_are_given(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(app_module, "ScanRunner", _FakeScanRunner)

    def fake_parse_scan_intent(mission, router):
        from lalo.intake import ParsedIntent

        assert mission == "test this website localhost:5000, focus on api"
        return ParsedIntent(
            targets=["localhost:5000"],
            exclude_targets=[],
            rules_of_engagement="Focus on API endpoints.",
        )

    monkeypatch.setattr(app_module, "parse_scan_intent", fake_parse_scan_intent)
    client, _ = _client(runs_dir=tmp_path)
    response = client.post(
        "/scan", json={"mission": "test this website localhost:5000, focus on api"}
    )
    assert response.status_code == 200
    body = response.json()
    assert body["resolved_targets"] == ["localhost:5000"]
    assert body["resolved_rules_of_engagement"] == "Focus on API endpoints."
    assert current_config().target_specs == ["localhost:5000"]
    assert current_config().rules_of_engagement == "Focus on API endpoints."


def test_scan_skips_the_parser_entirely_when_targets_are_explicit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(app_module, "ScanRunner", _FakeScanRunner)
    called = False

    def fake_parse_scan_intent(mission, router):
        nonlocal called
        called = True
        raise AssertionError("must not be called when targets are already explicit")

    monkeypatch.setattr(app_module, "parse_scan_intent", fake_parse_scan_intent)
    client, _ = _client(runs_dir=tmp_path)
    response = client.post("/scan", json={"mission": "find a bug", "targets": ["example.com"]})
    assert response.status_code == 200
    assert called is False
    assert response.json()["resolved_targets"] == ["example.com"]


def test_scan_still_400s_when_the_parser_finds_no_target_either(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(app_module, "ScanRunner", _FakeScanRunner)

    def fake_parse_scan_intent(mission, router):
        from lalo.intake import ParsedIntent

        return ParsedIntent(targets=[], exclude_targets=[], rules_of_engagement="")

    monkeypatch.setattr(app_module, "parse_scan_intent", fake_parse_scan_intent)
    client, _ = _client(runs_dir=tmp_path)
    response = client.post("/scan", json={"mission": "what can you do?"})
    assert response.status_code == 400
    assert "required" in response.json()["error"]


def test_scan_surfaces_a_structured_503_when_every_provider_fails_during_parse(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(app_module, "ScanRunner", _FakeScanRunner)

    def fake_parse_scan_intent(mission, router):
        raise AllProvidersFailedError(role="intake", failures=[("anthropic", "401 unauthorized")])

    monkeypatch.setattr(app_module, "parse_scan_intent", fake_parse_scan_intent)
    client, _ = _client(runs_dir=tmp_path)
    response = client.post("/scan", json={"mission": "test localhost:5000"})
    assert response.status_code == 503
    body = response.json()
    assert body["role"] == "intake"
    assert body["failures"] == [{"provider": "anthropic", "reason": "401 unauthorized"}]


def test_scan_resume_response_also_carries_resolved_fields(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(app_module, "ScanRunner", _FakeScanRunner)
    run_dir = tmp_path / "abc123"
    run_dir.mkdir()
    (run_dir / "resume_manifest.json").write_text(
        '{"mission": "m", "target_specs": ["example.com"], "egress_lock": false}',
        encoding="utf-8",
    )
    client, _ = _client(runs_dir=tmp_path)
    response = client.post("/scan", json={"resume_run_id": "abc123"})
    assert response.status_code == 200
    assert response.json()["resolved_targets"] == ["example.com"]
