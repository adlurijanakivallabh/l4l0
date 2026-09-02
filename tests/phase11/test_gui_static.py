"""Static GUI contract checks for the browser smoke workflow."""

from __future__ import annotations

from fastapi.testclient import TestClient

from reachagent.gui.app import app


def test_workspace_contains_real_state_views_and_controls() -> None:
    response = TestClient(app).get("/")
    assert response.status_code == 200
    html = response.text
    assert "<title>ReachAgent</title>" in html
    # The current chat-first GUI (plan v2): sidebar + landing composer + a conversation view
    # whose work-pane tabs render the same live scan state the backend exposes.
    for marker in (
        'id="sidebar"',
        'id="landing"',
        'id="convo-view"',
        'id="chat-log"',
        'id="chat-input"',
        'id="convo-list"',
        "Execution guardrails",
        'id="cancel-scan"',
        'id="pause-scan"',
        'id="term-feed"',
        'id="findings-list"',
        'id="surface-tree"',
        'id="report-body"',
        'id="tab-terminal"',
        'id="tab-findings"',
        'id="tab-report"',
        'id="tab-audit"',
        'id="provider-form"',
        'id="dl-sarif"',
        'id="dl-evidence"',
        'id="dl-bundle"',
    ):
        assert marker in html
    # The oracle guarantee is stated to the operator in the static shell.
    assert "deterministic oracle" in html


def test_workspace_does_not_embed_reference_names_or_credentials() -> None:
    html = TestClient(app).get("/").text.lower()
    assert "references/" not in html
    assert "github.com/" not in html
    for secret_marker in ("bearer ", "api_key=", "password="):
        assert secret_marker not in html
