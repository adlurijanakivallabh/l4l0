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
