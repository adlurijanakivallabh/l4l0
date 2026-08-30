"""Static GUI contract checks for the browser smoke workflow."""

from __future__ import annotations

from fastapi.testclient import TestClient

from reachagent.gui.app import app


def test_workspace_contains_real_state_views_and_controls() -> None:
    response = TestClient(app).get("/")
    assert response.status_code == 200
    html = response.text
    for marker in (
        'id="scan-status"',
        'id="cancel-scan"',
        'id="reasoning-stream"',
        'id="surface"',
        'id="findings"',
        'id="report"',
        'id="audit"',
        'id="scan-history"',
        'id="provider-form"',
    ):
        assert marker in html
    assert "No oracle-confirmed findings yet." in html
    assert "Only deterministic oracles can confirm findings" in html


def test_workspace_does_not_embed_reference_names_or_credentials() -> None:
    html = TestClient(app).get("/").text.lower()
    assert "references/" not in html
    assert "github.com/" not in html
    for secret_marker in ("bearer ", "api_key=", "password="):
        assert secret_marker not in html
