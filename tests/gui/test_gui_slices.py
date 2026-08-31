"""Read-only GUI graph slices expose the real stored surface."""

from __future__ import annotations

from importlib import import_module

import pytest
from fastapi.testclient import TestClient

from reachagent.graph.nodes import Endpoint, Host, Parameter, Service
from reachagent.graph.store import ReachabilityGraph
from reachagent.gui.app import _scans, app

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
    assert body["goal"] == "pentest https://demo.example"


def test_parse_intent_extracts_and_normalizes_credentials(monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_named_provider(monkeypatch)

    class _FakeClient:
        def propose_json(self, prompt: str, *, max_tokens: int = 600) -> dict[str, object]:
            return {
                "target": "https://demo.example",
                "in_scope": "demo.example, api.demo.example",
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
    assert body["goal"] == "find authorization bugs"
    assert body["credentials"] == [{"username": "admin", "password": "admin123", "role": "admin"}]


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
