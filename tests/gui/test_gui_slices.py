"""Read-only GUI graph slices expose the real stored surface."""

from __future__ import annotations

from importlib import import_module

import pytest
from fastapi.testclient import TestClient

from reachagent.graph.nodes import Endpoint, Host, Parameter, Service
from reachagent.graph.store import ReachabilityGraph
from reachagent.gui.app import _ScanControl, _scans, app

gui_app = import_module("reachagent.gui.app")


def test_surface_slice_contains_host_service_endpoint_parameter_tree() -> None:
    graph = ReachabilityGraph()
    host = graph.add_host(Host(address="demo.example", source="test"))
    graph.add_service(host, Service(port=443, protocol="tcp", service_name="https"))
    endpoint = graph.add_endpoint(Endpoint(method="GET", path="/search"))
    graph.add_parameter(endpoint, Parameter(name="q", location="query"))
    graph.add_resolves_to(host, endpoint)
    scan_id = "surface-slice"
    _scans[scan_id] = {"graph": graph, "status": "running", "events": []}
    try:
        payload = TestClient(app).get(f"/api/scan/{scan_id}/surface").json()
        assert payload["hosts"][0]["services"][0]["port"] == 443
        assert payload["hosts"][0]["endpoints"][0]["parameters"][0]["name"] == "q"
    finally:
        _scans.pop(scan_id, None)


def test_audit_slice_bounds_limit() -> None:
    scan_id = "audit-slice"
    _scans[scan_id] = {"audit": None}
    try:
        response = TestClient(app).get(f"/api/scan/{scan_id}/audit?limit=0")
        assert response.status_code == 200
        assert response.json()["entries"] == []
    finally:
        _scans.pop(scan_id, None)


def test_scan_endpoint_rejects_deterministic_only_mode() -> None:
    before = set(_scans)
    response = TestClient(app).post(
        "/api/scan",
        json={
            "target": "https://demo.example",
            "in_scope": "demo.example",
            "use_llm": False,
        },
    )
    assert response.status_code == 400
    assert response.json()["code"] == "llm_required"
    assert set(_scans) == before


def test_scan_endpoint_preflights_named_provider_values(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        gui_app,
        "_load_providers",
        lambda: [
            {
                "id": "unit-provider",
                "name": "unit-provider",
                "provider": "openai-compatible",
                "api_key": "unit-test-key",
                "base_url": "https://llm.example/v1/responses",
                "model": "unit-model",
                "api_style": "responses",
            }
        ],
    )

    async def noop_scan(*_args: object, **_kwargs: object) -> None:
        return None

    monkeypatch.setattr(gui_app, "_run_scan", noop_scan)
    response = TestClient(app).post(
        "/api/scan",
        json={
            "target": "https://demo.example",
            "in_scope": "demo.example",
            "use_llm": True,
            "llm_provider": "named:unit-provider",
        },
    )
    assert response.status_code == 200
    _scans.pop(response.json()["scan_id"], None)


def _stub_named_provider(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        gui_app,
        "_load_providers",
        lambda: [
            {
                "id": "unit-provider",
                "name": "unit-provider",
                "provider": "openai-compatible",
                "api_key": "unit-test-key",
                "base_url": "https://llm.example/v1/responses",
                "model": "unit-model",
                "api_style": "responses",
            }
        ],
    )


def test_scan_endpoint_passes_checked_tuning_flags_as_env_overrides(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The 3 tuning checkboxes are the only GUI control that can ever turn these
    flag-gated recon layers on — the env-override plumbing must actually reach
    _run_scan with the right keys, or the checkboxes silently do nothing.
    """
    _stub_named_provider(monkeypatch)
    captured: list[object] = []

    async def capturing_scan(*args: object, **_kwargs: object) -> None:
        captured.extend(args)

    monkeypatch.setattr(gui_app, "_run_scan", capturing_scan)
    response = TestClient(app).post(
        "/api/scan",
        json={
            "target": "https://demo.example",
            "in_scope": "demo.example",
            "use_llm": True,
            "llm_provider": "named:unit-provider",
            "surface_tuning": True,
            "signal_tuning": True,
            "transport_tuning": False,
        },
    )
    assert response.status_code == 200
    env_overrides = captured[-2]
    assert env_overrides["REACHAGENT_SURFACE_TUNING"] == "1"
    assert env_overrides["REACHAGENT_SIGNAL_TUNING"] == "1"
    assert "REACHAGENT_TRANSPORT_TUNING" not in env_overrides
    _scans.pop(response.json()["scan_id"], None)


def test_scan_endpoint_omits_tuning_flags_when_nothing_checked(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _stub_named_provider(monkeypatch)
    captured: list[object] = []

    async def capturing_scan(*args: object, **_kwargs: object) -> None:
        captured.extend(args)

    monkeypatch.setattr(gui_app, "_run_scan", capturing_scan)
    response = TestClient(app).post(
        "/api/scan",
        json={
            "target": "https://demo.example",
            "in_scope": "demo.example",
            "use_llm": True,
            "llm_provider": "named:unit-provider",
        },
    )
    assert response.status_code == 200
    env_overrides = captured[-2]
    assert not any(k.endswith("_TUNING") for k in env_overrides)
    _scans.pop(response.json()["scan_id"], None)


def test_scan_endpoint_uses_single_saved_provider_when_form_omits_selection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("REACHAGENT_LLM_PROVIDER", raising=False)
    monkeypatch.delenv("REACHAGENT_LLM_API_KEY", raising=False)
    monkeypatch.setattr(
        gui_app,
        "_load_providers",
        lambda: [
            {
                "id": "only-provider",
                "name": "only-provider",
                "provider": "openai-compatible",
                "api_key": "unit-test-key",
                "base_url": "https://llm.example/v1/responses",
                "model": "unit-model",
                "api_style": "responses",
            }
        ],
    )

    async def noop_scan(*_args: object, **_kwargs: object) -> None:
        return None

    monkeypatch.setattr(gui_app, "_run_scan", noop_scan)
    response = TestClient(app).post(
        "/api/scan",
        json={"target": "https://demo.example", "in_scope": "demo.example", "use_llm": True},
    )
    assert response.status_code == 200
    _scans.pop(response.json()["scan_id"], None)


def test_report_endpoint_serves_the_stored_phase4_report() -> None:
    graph = ReachabilityGraph()
    scan_id = "stored-report"
    report = "# LLM report\n\nProvider-authored narrative"
    _scans[scan_id] = {"graph": graph, "report_md": report}
    try:
        response = TestClient(app).get(f"/api/report/{scan_id}")
        assert response.status_code == 200
        assert response.json() == {"scan_id": scan_id, "report_md": report}
    finally:
        _scans.pop(scan_id, None)


def test_report_endpoint_does_not_regenerate_without_phase4_output() -> None:
    scan_id = "missing-report"
    _scans[scan_id] = {"graph": ReachabilityGraph()}
    try:
        response = TestClient(app).get(f"/api/report/{scan_id}")
        assert response.status_code == 409
        assert response.json()["error"] == "report not ready"
    finally:
        _scans.pop(scan_id, None)


def test_report_export_requires_stored_phase4_for_narrative_formats() -> None:
    scan_id = "missing-export-report"
    _scans[scan_id] = {"graph": ReachabilityGraph()}
    try:
        for format in ("markdown", "html"):
            response = TestClient(app).get(f"/api/scan/{scan_id}/export?format={format}")
            assert response.status_code == 409
            assert response.json()["error"] == "report not ready"
    finally:
        _scans.pop(scan_id, None)


# === Chat-intent extraction (/api/parse-intent) ==============================


def test_parse_intent_requires_a_message() -> None:
    response = TestClient(app).post("/api/parse-intent", json={"message": ""})
    assert response.status_code == 400


def test_parse_intent_degrades_gracefully_with_no_provider_configured(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(gui_app, "_load_providers", lambda: [])
    monkeypatch.setattr("reachagent.llm.runtime.selected_provider", lambda: "")
    response = TestClient(app).post(
        "/api/parse-intent", json={"message": "pentest https://demo.example"}
    )
    assert response.status_code == 200
    body = response.json()
    assert body["extracted"] is False
    assert body["credentials"] == []
    assert body["out_of_scope"] == ""
    assert body["goal"] == "pentest https://demo.example"


def test_parse_intent_extracts_and_normalizes_credentials(monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_named_provider(monkeypatch)

    class _FakeClient:
        def propose_json(self, prompt: str, *, max_tokens: int = 600) -> dict[str, object]:
            return {
                "target": "https://demo.example",
                "in_scope": "demo.example, api.demo.example",
                "out_of_scope": "admin.demo.example",
                "credentials": [
                    {"username": "admin", "password": "admin123", "role": "ADMIN"},
                    {"username": "", "password": "dropped-no-username"},
                    {"username": "no-password"},
                    "not-a-dict",
                ],
                "goal": "find authorization bugs",
            }

        def close(self) -> None:
            pass

    monkeypatch.setattr(gui_app, "_build_llm_client", lambda *_a, **_k: _FakeClient())
    response = TestClient(app).post(
        "/api/parse-intent",
        json={
            "message": "pentest this site, admin/admin123",
            "llm_provider": "named:unit-provider",
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["extracted"] is True
    assert body["target"] == "https://demo.example"
    assert body["in_scope"] == "demo.example, api.demo.example"
    assert body["out_of_scope"] == "admin.demo.example"
    assert body["goal"] == "find authorization bugs"
    assert body["credentials"] == [{"username": "admin", "password": "admin123", "role": "admin"}]


def test_parse_intent_defaults_out_of_scope_to_empty_string_when_unmentioned(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _stub_named_provider(monkeypatch)

    class _FakeClient:
        def propose_json(self, prompt: str, *, max_tokens: int = 600) -> dict[str, object]:
            return {"target": "https://demo.example", "in_scope": "", "credentials": [], "goal": ""}

        def close(self) -> None:
            pass

    monkeypatch.setattr(gui_app, "_build_llm_client", lambda *_a, **_k: _FakeClient())
    response = TestClient(app).post(
        "/api/parse-intent",
        json={"message": "pentest this site", "llm_provider": "named:unit-provider"},
    )
    assert response.status_code == 200
    assert response.json()["out_of_scope"] == ""


def test_parse_intent_degrades_on_malformed_llm_reply(monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_named_provider(monkeypatch)

    class _BoomClient:
        def propose_json(self, prompt: str, *, max_tokens: int = 600) -> dict[str, object]:
            raise ValueError("no JSON object in model response")

        def close(self) -> None:
            pass

    monkeypatch.setattr(gui_app, "_build_llm_client", lambda *_a, **_k: _BoomClient())
    response = TestClient(app).post(
        "/api/parse-intent",
        json={"message": "pentest this site", "llm_provider": "named:unit-provider"},
    )
    assert response.status_code == 200
    assert response.json()["extracted"] is False


# === Inline chat-provided identities (/api/scan) ==============================


def test_scan_endpoint_forwards_inline_identities(monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_named_provider(monkeypatch)
    captured: list[object] = []

    async def capturing_scan(*args: object, **_kwargs: object) -> None:
        captured.extend(args)

    monkeypatch.setattr(gui_app, "_run_scan", capturing_scan)
    response = TestClient(app).post(
        "/api/scan",
        json={
            "target": "https://demo.example",
            "in_scope": "demo.example",
            "use_llm": True,
            "llm_provider": "named:unit-provider",
            "identities": [{"username": "admin", "password": "admin123", "role": "admin"}],
        },
    )
    assert response.status_code == 200
    identities_inline = captured[-1]
    assert identities_inline == [{"username": "admin", "password": "admin123", "role": "admin"}]
    _scans.pop(response.json()["scan_id"], None)


def test_scan_endpoint_omits_identities_inline_when_not_a_list(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _stub_named_provider(monkeypatch)
    captured: list[object] = []

    async def capturing_scan(*args: object, **_kwargs: object) -> None:
        captured.extend(args)

    monkeypatch.setattr(gui_app, "_run_scan", capturing_scan)
    response = TestClient(app).post(
        "/api/scan",
        json={
            "target": "https://demo.example",
            "in_scope": "demo.example",
            "use_llm": True,
            "llm_provider": "named:unit-provider",
            "identities": "not-a-list",
        },
    )
    assert response.status_code == 200
    assert captured[-1] is None
    _scans.pop(response.json()["scan_id"], None)


# === No-cache headers on the served frontend (/, /static/app.js) ============
# A GUI file that changes across development iterations must never be served
# from a stale browser cache — that's the exact stale-frontend confusion this
# session hit directly.


def test_index_route_is_never_cached() -> None:
    response = TestClient(app).get("/")
    assert response.headers.get("cache-control") == "no-store"


def test_app_js_route_is_never_cached() -> None:
    response = TestClient(app).get("/static/app.js")
    assert response.status_code == 200
    assert response.headers.get("cache-control") == "no-store"


# === Pause / resume / cancel ================================================
# _ScanControl.is_set() blocks the worker thread while pause_event is set and
# unblocks it the instant cancel_event fires — these tests only exercise the
# HTTP-facing state transitions, not the blocking itself (covered indirectly:
# a scan stuck mid-pause would just never reach a terminal status, which the
# live GUI verification already confirmed against a real running scan).


def _running_scan(scan_id: str) -> _ScanControl:
    control = _ScanControl()
    _scans[scan_id] = {"status": "running", "events": [], "control": control}
    return control


def test_pause_a_running_scan_flips_status_and_sets_the_event() -> None:
    scan_id = "pause-slice"
    control = _running_scan(scan_id)
    try:
        response = TestClient(app).post(f"/api/scan/{scan_id}/pause")
        assert response.status_code == 200
        body = response.json()
        assert body["status"] == "paused"
        assert body["lifecycle"] == "paused"
        assert body["can_resume"] is True
        assert body["can_pause"] is False
        assert control.pause_event.is_set()
    finally:
        _scans.pop(scan_id, None)


def test_resume_a_paused_scan_flips_status_and_clears_the_event() -> None:
    scan_id = "resume-slice"
    control = _running_scan(scan_id)
    _scans[scan_id]["status"] = "paused"
    try:
        control.pause_event.set()
        response = TestClient(app).post(f"/api/scan/{scan_id}/resume")
        assert response.status_code == 200
        body = response.json()
        assert body["status"] == "running"
        assert body["can_pause"] is True
        assert body["can_resume"] is False
        assert not control.pause_event.is_set()
    finally:
        _scans.pop(scan_id, None)


def test_pause_rejected_when_not_running() -> None:
    scan_id = "pause-reject-slice"
    _running_scan(scan_id)
    _scans[scan_id]["status"] = "queued"
    try:
        response = TestClient(app).post(f"/api/scan/{scan_id}/pause")
        assert response.status_code == 409
    finally:
        _scans.pop(scan_id, None)


def test_resume_rejected_when_not_paused() -> None:
    scan_id = "resume-reject-slice"
    _running_scan(scan_id)
    try:
        response = TestClient(app).post(f"/api/scan/{scan_id}/resume")
        assert response.status_code == 409
    finally:
        _scans.pop(scan_id, None)


def test_cancel_still_works_from_a_paused_scan() -> None:
    scan_id = "cancel-from-paused-slice"
    control = _running_scan(scan_id)
    _scans[scan_id]["status"] = "paused"
    control.pause_event.set()
    try:
        response = TestClient(app).post(f"/api/scan/{scan_id}/cancel")
        assert response.status_code == 200
        body = response.json()
        assert body["status"] == "cancelling"
        assert control.cancel_event.is_set()
    finally:
        _scans.pop(scan_id, None)


# === Operator checkpoint ("My additions") ===================================
# _pause_for_operator_checkpoint is the function RequestFirer's first
# state-changing request calls, wired via scan_all_classes's
# operator_checkpoint kwarg. It genuinely blocks (unlike the HTTP-facing
# pause/resume tests above), so these run it on a background thread.


def test_checkpoint_blocks_until_resumed_then_returns_normally() -> None:
    import threading
    import time

    from reachagent.gui.app import _pause_for_operator_checkpoint

    scan_id = "checkpoint-resume-slice"
    control = _running_scan(scan_id)
    events: list = []
    finished = threading.Event()
    raised: list[BaseException] = []

    def _run() -> None:
        try:
            _pause_for_operator_checkpoint(
                scan_id, control, events, "POST", "http://target.test/submit", "anon"
            )
        except BaseException as exc:  # noqa: BLE001 — captured for the assertion below
            raised.append(exc)
        finished.set()

    try:
        thread = threading.Thread(target=_run, daemon=True)
        thread.start()
        # Give the checkpoint a moment to actually block before asserting on it.
        for _ in range(50):
            if control.pause_event.is_set():
                break
            time.sleep(0.02)
        assert control.pause_event.is_set()
        assert _scans[scan_id]["status"] == "paused"
        assert _scans[scan_id]["pending_confirmation"]["method"] == "POST"
        assert not finished.is_set()  # still blocked

        control.pause_event.clear()  # what the /resume endpoint does
        finished.wait(timeout=2.0)
        assert finished.is_set()
        assert raised == []
        assert _scans[scan_id]["pending_confirmation"] is None
        assert any("state-changing request" in str(e.message) for e in events)
    finally:
        _scans.pop(scan_id, None)


def test_checkpoint_raises_when_cancelled_while_blocked() -> None:
    import threading
    import time

    from reachagent.gui.app import _pause_for_operator_checkpoint

    scan_id = "checkpoint-cancel-slice"
    control = _running_scan(scan_id)
    events: list = []
    finished = threading.Event()
    raised: list[BaseException] = []

    def _run() -> None:
        try:
            _pause_for_operator_checkpoint(
                scan_id, control, events, "POST", "http://target.test/submit", "anon"
            )
        except BaseException as exc:  # noqa: BLE001 — captured for the assertion below
            raised.append(exc)
        finished.set()

    try:
        thread = threading.Thread(target=_run, daemon=True)
        thread.start()
        for _ in range(50):
            if control.pause_event.is_set():
                break
            time.sleep(0.02)
        assert control.pause_event.is_set()

        control.cancel_event.set()
        control.pause_event.clear()  # what the /cancel endpoint does
        finished.wait(timeout=2.0)
        assert finished.is_set()
        assert len(raised) == 1
        assert isinstance(raised[0], RuntimeError)
    finally:
        _scans.pop(scan_id, None)


def test_checkpoint_is_a_no_op_with_no_control_attached() -> None:
    from reachagent.gui.app import _pause_for_operator_checkpoint

    events: list = []
    _pause_for_operator_checkpoint(
        "no-control-scan", None, events, "POST", "http://target.test/submit", "anon"
    )
    assert events == []


# === Mid-scan steering (Agentic Coordinator, Phase 3) =======================


def test_steer_queues_a_hint_and_emits_an_event() -> None:
    scan_id = "steer-slice"
    control = _running_scan(scan_id)
    try:
        response = TestClient(app).post(
            f"/api/scan/{scan_id}/steer", json={"message": "focus on the admin login flow"}
        )
        assert response.status_code == 200
        assert response.json() == {"queued": True}
        assert control.pop_steering_hints() == ["focus on the admin login flow"]
        events = _scans[scan_id]["events"]
        assert any("Operator note queued" in e.message for e in events)
    finally:
        _scans.pop(scan_id, None)


def test_steer_works_while_paused_too() -> None:
    scan_id = "steer-paused-slice"
    _running_scan(scan_id)
    _scans[scan_id]["status"] = "paused"
    try:
        response = TestClient(app).post(f"/api/scan/{scan_id}/steer", json={"message": "hint"})
        assert response.status_code == 200
    finally:
        _scans.pop(scan_id, None)


def test_steer_rejected_on_a_finished_scan() -> None:
    scan_id = "steer-finished-slice"
    _running_scan(scan_id)
    _scans[scan_id]["status"] = "done"
    try:
        response = TestClient(app).post(f"/api/scan/{scan_id}/steer", json={"message": "hint"})
        assert response.status_code == 409
    finally:
        _scans.pop(scan_id, None)


def test_steer_rejects_an_empty_message() -> None:
    scan_id = "steer-empty-slice"
    _running_scan(scan_id)
    try:
        response = TestClient(app).post(f"/api/scan/{scan_id}/steer", json={"message": "  "})
        assert response.status_code == 400
    finally:
        _scans.pop(scan_id, None)


# === concurrent_specialists wiring (Build Order 2c) =========================


def test_concurrent_specialists_flag_reaches_scan_all_classes(monkeypatch) -> None:  # noqa: ANN001
    import asyncio
    import sys

    # reachagent.gui's __init__ does `from reachagent.gui.app import app`,
    # which shadows the `app` SUBMODULE attribute on the package with the
    # FastAPI INSTANCE -- `import reachagent.gui.app as x` would silently
    # bind x to that FastAPI object, not the module. sys.modules sidesteps
    # the shadowed attribute and gets the real module.
    app_module = sys.modules["reachagent.gui.app"]

    captured: dict = {}

    def fake_scan_all_classes(**kwargs):  # noqa: ANN001, ANN003
        captured.update(kwargs)
        raise RuntimeError("stop-here-test-only")

    monkeypatch.setattr(app_module, "scan_all_classes", fake_scan_all_classes)

    scan_id = "concurrent-flag-slice"
    _scans[scan_id] = {"status": "queued", "events": [], "control": None}
    try:
        asyncio.run(
            app_module._run_scan_body(
                scan_id,
                "https://target.test",
                "target.test",
                None,
                True,
                20,
                None,
                None,
                None,
                concurrent_specialists=True,
            )
        )
    finally:
        _scans.pop(scan_id, None)

    assert captured.get("concurrent_specialists") is True


def test_opt_str_treats_whitespace_only_as_none() -> None:
    """Adversarial review: _opt_str("   ") used to survive as "" (truthy
    check ran before stripping) -- a real gap for any caller that then does
    a filesystem check on the result, e.g. Path("").is_dir() resolving to
    the server's own working directory instead of correctly refusing."""
    assert gui_app._opt_str("   ") is None
    assert gui_app._opt_str("") is None
    assert gui_app._opt_str(None) is None
    assert gui_app._opt_str("  real-value  ") == "real-value"


def test_repo_path_whitespace_only_is_ignored_not_treated_as_cwd(monkeypatch) -> None:  # noqa: ANN001
    _stub_named_provider(monkeypatch)

    async def noop_scan(*_args: object, **_kwargs: object) -> None:
        return None

    monkeypatch.setattr(gui_app, "_run_scan", noop_scan)
    response = TestClient(app).post(
        "/api/scan",
        json={
            "target": "https://demo.example",
            "in_scope": "demo.example",
            "use_llm": True,
            "llm_provider": "named:unit-provider",
            "repo_path": "   ",
        },
    )
    # Never 400 (the field is simply absent, not an invalid path) and
    # never silently treated as the server's own working directory.
    assert response.status_code == 200
    _scans.pop(response.json()["scan_id"], None)


def test_repo_path_rejected_when_not_an_existing_directory() -> None:
    response = TestClient(app).post(
        "/api/scan",
        json={
            "target": "https://demo.example",
            "in_scope": "demo.example",
            "use_llm": True,
            "repo_path": "/definitely/does/not/exist/anywhere",
        },
    )
    assert response.status_code == 400
    assert response.json()["code"] == "invalid_input"


def test_repo_path_accepted_when_it_is_a_real_directory(monkeypatch, tmp_path) -> None:  # noqa: ANN001
    _stub_named_provider(monkeypatch)

    async def noop_scan(*_args: object, **_kwargs: object) -> None:
        return None

    monkeypatch.setattr(gui_app, "_run_scan", noop_scan)
    response = TestClient(app).post(
        "/api/scan",
        json={
            "target": "https://demo.example",
            "in_scope": "demo.example",
            "use_llm": True,
            "llm_provider": "named:unit-provider",
            "repo_path": str(tmp_path),
        },
    )
    assert response.status_code == 200
    _scans.pop(response.json()["scan_id"], None)


def test_repo_path_wiring_reaches_scan_all_classes(monkeypatch) -> None:  # noqa: ANN001
    import asyncio

    captured: dict = {}

    def fake_scan_all_classes(**kwargs):  # noqa: ANN001, ANN003
        captured.update(kwargs)
        raise RuntimeError("stop-here-test-only")

    monkeypatch.setattr(gui_app, "scan_all_classes", fake_scan_all_classes)

    scan_id = "repo-path-flag-slice"
    _scans[scan_id] = {"status": "queued", "events": [], "control": None}
    try:
        asyncio.run(
            gui_app._run_scan_body(
                scan_id,
                "https://target.test",
                "target.test",
                None,
                True,
                20,
                None,
                None,
                None,
                repo_path="/some/repo",
            )
        )
    finally:
        _scans.pop(scan_id, None)

    assert captured.get("repo_path") == "/some/repo"


def test_repo_path_defaults_to_none(monkeypatch) -> None:  # noqa: ANN001
    import asyncio

    captured: dict = {}

    def fake_scan_all_classes(**kwargs):  # noqa: ANN001, ANN003
        captured.update(kwargs)
        raise RuntimeError("stop-here-test-only")

    monkeypatch.setattr(gui_app, "scan_all_classes", fake_scan_all_classes)

    scan_id = "repo-path-default-slice"
    _scans[scan_id] = {"status": "queued", "events": [], "control": None}
    try:
        asyncio.run(
            gui_app._run_scan_body(
                scan_id, "https://target.test", "target.test", None, True, 20, None, None, None
            )
        )
    finally:
        _scans.pop(scan_id, None)

    assert captured.get("repo_path") is None


def test_concurrent_specialists_defaults_to_false(monkeypatch) -> None:  # noqa: ANN001
    import asyncio
    import sys

    # reachagent.gui's __init__ does `from reachagent.gui.app import app`,
    # which shadows the `app` SUBMODULE attribute on the package with the
    # FastAPI INSTANCE -- `import reachagent.gui.app as x` would silently
    # bind x to that FastAPI object, not the module. sys.modules sidesteps
    # the shadowed attribute and gets the real module.
    app_module = sys.modules["reachagent.gui.app"]

    captured: dict = {}

    def fake_scan_all_classes(**kwargs):  # noqa: ANN001, ANN003
        captured.update(kwargs)
        raise RuntimeError("stop-here-test-only")

    monkeypatch.setattr(app_module, "scan_all_classes", fake_scan_all_classes)

    scan_id = "concurrent-flag-default-slice"
    _scans[scan_id] = {"status": "queued", "events": [], "control": None}
    try:
        asyncio.run(
            app_module._run_scan_body(
                scan_id, "https://target.test", "target.test", None, True, 20, None, None, None
            )
        )
    finally:
        _scans.pop(scan_id, None)

    assert captured.get("concurrent_specialists") is False


class _FakeChatClient:
    """A stand-in LLM client capturing the messages it was handed."""

    def __init__(self, reply: str = "You have 1 confirmed finding so far.") -> None:
        self.reply = reply
        self.seen: list[dict[str, str]] = []
        self.closed = False

    def chat(self, messages: list[dict[str, str]], *, max_tokens: int = 512) -> str:
        self.seen = messages
        return self.reply

    def close(self) -> None:
        self.closed = True


def test_ask_returns_real_llm_answer_and_steers_active_scan(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = _FakeChatClient()
    monkeypatch.setattr(gui_app, "_build_llm_client", lambda *_a, **_k: fake)
    control = _ScanControl()
    scan_id = "ask-real"
    _scans[scan_id] = {
        "target": "http://demo.example",
        "operator_prompt": "full assessment",
        "status": "running",
        "phase": "tools",
        "events": [],
        "findings": [],
        "chat": [],
        "control": control,
        "use_llm": True,
        "llm_provider": "deepseek",
        "named_overrides": None,
    }
    try:
        r = TestClient(app).post(
            f"/api/scan/{scan_id}/ask", json={"message": "what have you found?"}
        )
        assert r.status_code == 200
        body = r.json()
        assert body["answer"] == "You have 1 confirmed finding so far."
        assert body["steered"] is True
        # The message became a real steering hint on the live scan.
        assert control.pop_steering_hints() == ["what have you found?"]
        # Persona + state summary went in as a system message; the transcript is retained.
        assert fake.seen[0]["role"] == "system"
        assert "read-only" in fake.seen[0]["content"]
        assert fake.closed is True
        assert _scans[scan_id]["chat"][-1] == {
            **_scans[scan_id]["chat"][-1],
            "role": "assistant",
            "text": "You have 1 confirmed finding so far.",
        }
    finally:
        _scans.pop(scan_id, None)


def test_ask_fails_open_when_llm_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*_a: object, **_k: object) -> object:
        raise RuntimeError("no provider")

    monkeypatch.setattr(gui_app, "_build_llm_client", boom)
    scan_id = "ask-failopen"
    _scans[scan_id] = {
        "status": "running",
        "phase": "recon",
        "events": [],
        "findings": [],
        "chat": [],
        "control": _ScanControl(),
        "use_llm": True,
        "llm_provider": "deepseek",
        "named_overrides": None,
    }
    try:
        r = TestClient(app).post(f"/api/scan/{scan_id}/ask", json={"message": "hi"})
        assert r.status_code == 200
        # Never a hard error; falls back to a deterministic line.
        assert "steer the next decision point" in r.json()["answer"]
    finally:
        _scans.pop(scan_id, None)


def test_ask_answers_after_completion_without_steering(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _FakeChatClient(reply="That finding was an SQL injection on /login.")
    monkeypatch.setattr(gui_app, "_build_llm_client", lambda *_a, **_k: fake)
    scan_id = "ask-done"
    _scans[scan_id] = {
        "status": "done",
        "phase": "report",
        "events": [],
        "findings": [{"title": "SQLi on /login", "severity": "high"}],
        "chat": [],
        "control": _ScanControl(),
        "use_llm": True,
        "llm_provider": "deepseek",
        "named_overrides": None,
    }
    try:
        r = TestClient(app).post(f"/api/scan/{scan_id}/ask", json={"message": "explain finding 1"})
        assert r.status_code == 200
        assert r.json() == {
            "answer": "That finding was an SQL injection on /login.",
            "steered": False,
        }
    finally:
        _scans.pop(scan_id, None)


def test_ask_requires_a_message() -> None:
    scan_id = "ask-empty"
    _scans[scan_id] = {"status": "running", "chat": [], "control": _ScanControl()}
    try:
        r = TestClient(app).post(f"/api/scan/{scan_id}/ask", json={"message": "   "})
        assert r.status_code == 400
    finally:
        _scans.pop(scan_id, None)


def test_ask_unknown_scan_is_404() -> None:
    r = TestClient(app).post("/api/scan/nope/ask", json={"message": "hi"})
    assert r.status_code == 404


def test_cancel_is_idempotent_and_reports_a_distinct_cancelling_lifecycle() -> None:
    scan_id = "cancel-once"
    _scans[scan_id] = {
        "target": "http://demo.example",
        "status": "running",
        "phase": "recon",
        "events": [],
        "control": _ScanControl(),
        "cancel_requested": False,
    }
    try:
        client = TestClient(app)
        first = client.post(f"/api/scan/{scan_id}/cancel")
        assert first.status_code == 200
        assert first.json()["lifecycle"] == "cancelling"  # distinct, not "running"
        assert "already_cancelling" not in first.json()
        # A second (misclick) cancel is a clean no-op: flagged, and NO duplicate event.
        second = client.post(f"/api/scan/{scan_id}/cancel")
        assert second.status_code == 200
        assert second.json().get("already_cancelling") is True
        cancel_events = [
            e for e in _scans[scan_id]["events"] if "Cancellation requested" in e.message
        ]
        assert len(cancel_events) == 1
    finally:
        _scans.pop(scan_id, None)


def test_scan_snapshot_exposes_suspected_tier_separate_from_findings() -> None:
    from reachagent.graph.nodes import SuspectedFinding

    graph = ReachabilityGraph()
    graph.add_suspected_finding(
        SuspectedFinding(
            vuln_class="sqli",
            endpoint="/login",
            location="user",
            source="signal-gated-tool",
            reason="scanner_claim_unverified",
        )
    )
    scan_id = "suspected-slice"
    _scans[scan_id] = {"graph": graph, "status": "done", "events": [], "findings": []}
    try:
        j = TestClient(app).get(f"/api/scan/{scan_id}").json()
        assert j["findings"] == []
        assert len(j["suspected"]) == 1
        assert j["suspected"][0]["vuln_class"] == "sqli"
        assert j["suspected"][0]["reason"] == "scanner_claim_unverified"
    finally:
        _scans.pop(scan_id, None)


def test_scan_endpoint_passes_aggressive_flag_as_env_override(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """W4: the Aggressive checkbox must reach _run_scan as REACHAGENT_AGGRESSIVE=1, or the
    signal-gate bypass silently never activates."""
    _stub_named_provider(monkeypatch)
    captured: list[object] = []

    async def capturing_scan(*args: object, **_kwargs: object) -> None:
        captured.extend(args)

    monkeypatch.setattr(gui_app, "_run_scan", capturing_scan)
    response = TestClient(app).post(
        "/api/scan",
        json={
            "target": "https://demo.example",
            "in_scope": "demo.example",
            "use_llm": True,
            "llm_provider": "named:unit-provider",
            "aggressive": True,
        },
    )
    assert response.status_code == 200
    env_overrides = captured[-2]
    assert env_overrides["REACHAGENT_AGGRESSIVE"] == "1"
    _scans.pop(response.json()["scan_id"], None)


def test_scan_endpoint_omits_aggressive_flag_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_named_provider(monkeypatch)
    captured: list[object] = []

    async def capturing_scan(*args: object, **_kwargs: object) -> None:
        captured.extend(args)

    monkeypatch.setattr(gui_app, "_run_scan", capturing_scan)
    response = TestClient(app).post(
        "/api/scan",
        json={
            "target": "https://demo.example",
            "in_scope": "demo.example",
            "use_llm": True,
            "llm_provider": "named:unit-provider",
        },
    )
    assert response.status_code == 200
    env_overrides = captured[-2]
    assert env_overrides is None or "REACHAGENT_AGGRESSIVE" not in env_overrides
    _scans.pop(response.json()["scan_id"], None)


def test_save_and_list_provider_round_trips_grunt_model(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,  # noqa: ANN001
) -> None:
    """v2 W6: the optional grunt_model field persists through save -> list, and is
    absent (empty) when not set — never required."""
    monkeypatch.setattr(gui_app, "_providers_path", tmp_path / "providers.json")
    client = TestClient(app)
    r = client.post(
        "/api/providers",
        json={
            "name": "tiered-lab",
            "provider": "openai-compatible",
            "base_url": "https://llm.test/v1",
            "model": "big-model",
            "api_style": "chat_completions",
            "api_key": "secret",
            "grunt_model": "cheap-model",
        },
    )
    assert r.status_code == 200
    provider_id = r.json()["id"]

    listed = client.get("/api/providers").json()["providers"]
    entry = next(p for p in listed if p["id"] == provider_id)
    assert entry["grunt_model"] == "cheap-model"
    assert entry["model"] == "big-model"


def test_save_provider_without_grunt_model_leaves_it_empty(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,  # noqa: ANN001
) -> None:
    monkeypatch.setattr(gui_app, "_providers_path", tmp_path / "providers.json")
    client = TestClient(app)
    r = client.post(
        "/api/providers",
        json={
            "name": "untiered-lab",
            "provider": "openai-compatible",
            "base_url": "https://llm.test/v1",
            "model": "big-model",
            "api_style": "chat_completions",
            "api_key": "secret",
        },
    )
    assert r.status_code == 200
    provider_id = r.json()["id"]
    listed = client.get("/api/providers").json()["providers"]
    entry = next(p for p in listed if p["id"] == provider_id)
    assert entry["grunt_model"] == ""


def test_resolve_named_provider_only_sets_grunt_env_override_when_configured(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,  # noqa: ANN001
) -> None:
    monkeypatch.setattr(gui_app, "_providers_path", tmp_path / "providers.json")
    client = TestClient(app)
    tiered = client.post(
        "/api/providers",
        json={
            "name": "tiered",
            "provider": "openai-compatible",
            "base_url": "https://llm.test/v1",
            "model": "big-model",
            "api_style": "chat_completions",
            "api_key": "secret",
            "grunt_model": "cheap-model",
        },
    ).json()["id"]
    untiered = client.post(
        "/api/providers",
        json={
            "name": "untiered",
            "provider": "openai-compatible",
            "base_url": "https://llm.test/v1",
            "model": "big-model",
            "api_style": "chat_completions",
            "api_key": "secret",
        },
    ).json()["id"]

    _provider, tiered_overrides, err = gui_app._resolve_llm_provider(
        {"llm_provider": f"named:{tiered}"}
    )
    assert err is None
    assert tiered_overrides["REACHAGENT_LLM_GRUNT_MODEL"] == "cheap-model"

    _provider2, untiered_overrides, err2 = gui_app._resolve_llm_provider(
        {"llm_provider": f"named:{untiered}"}
    )
    assert err2 is None
    assert "REACHAGENT_LLM_GRUNT_MODEL" not in untiered_overrides
