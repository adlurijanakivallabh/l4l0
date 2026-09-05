"""Tests for the end-to-end scan integration pass.

Hermetic throughout, with one deliberate exception: a real ModelRouter wraps
a scripted fake Provider (the project's own established pattern, reused from
test_findings_review.py) rather than calling a live LLM, and the runtime
container is monkeypatched to a lightweight fake so no real Docker daemon is
required - only docker_available()'s own guard clause is exercised for real
logic, never a real `docker` subprocess. The one exception is
test_scan_runner_dispatches_a_real_browser_tool_call (@pytest.mark.integration
- this repo's own existing marker for "needs a real browser/external
process," matching test_browser_live.py's own two tests, not @pytest.mark.live
which is reserved for tests needing a live target container): a genuine
headless Chromium session against a real local HTTP server, proving the
browser tool is actually wired into ScanRunner's registry and not just
present in a fake-provider script nothing ever really dispatches.
"""

from __future__ import annotations

import http.server
import json
import threading
from collections.abc import Iterator
from pathlib import Path
from types import SimpleNamespace

import pytest

import lalo.scan as scan_module
from lalo.agent.spawn import merge_finding_nodes
from lalo.core.errors import ConfigError, ContainerError
from lalo.core.model_router import CompletionResponse, ModelRouter
from lalo.graph.model import NodeKind, ReachabilityGraph
from lalo.gui.events import EventLog
from lalo.orchestrator.budget import RunStatus
from lalo.scan import ScanConfig, ScanRunner, _terminal_status

_HIGH_CVSS = {
    "attack_vector": "N",
    "attack_complexity": "L",
    "privileges_required": "N",
    "user_interaction": "N",
    "scope": "U",
    "confidentiality": "H",
    "integrity": "N",
    "availability": "N",
}


# --- _terminal_status: pure mapping ------------------------------------------


def test_terminal_status_maps_finish_reasons_to_completed() -> None:
    assert _terminal_status("finished") is RunStatus.COMPLETED
    assert _terminal_status("max_steps_reserved_turn") is RunStatus.COMPLETED


def test_terminal_status_maps_budget_reasons_to_budget_exhausted() -> None:
    assert _terminal_status("budget_exhausted") is RunStatus.BUDGET_EXHAUSTED
    assert _terminal_status("subagent_reserve_exhausted") is RunStatus.BUDGET_EXHAUSTED


def test_terminal_status_never_claims_completed_for_an_unconfirmed_stop() -> None:
    for reason in (
        "cancelled",
        "provider_failed",
        "no_tool_call",
        "repeating_tool_call_aborted",
        "max_steps",
    ):
        assert _terminal_status(reason) is RunStatus.UNVERIFIED_STOP


# --- guard clauses: no Docker required ---------------------------------------


def test_run_fails_closed_with_no_provider_credentials(tmp_path: Path) -> None:
    config = ScanConfig(
        mission="find a bug", target_specs=["example.com"], run_dir=tmp_path / "run"
    )
    runner = ScanRunner(config, env={})
    with pytest.raises(ConfigError):
        runner.run()


def test_run_refuses_to_start_without_docker(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(scan_module, "docker_available", lambda: False)
    config = ScanConfig(
        mission="find a bug", target_specs=["example.com"], run_dir=tmp_path / "run"
    )
    runner = ScanRunner(config, env={"ANTHROPIC_API_KEY": "sk-test"})
    with pytest.raises(ContainerError):
        runner.run()


# --- full wiring, hermetically ------------------------------------------------


class _ScriptedProvider:
    name = "fake"

    def __init__(self, respond: object) -> None:
        self._respond = respond
        self.calls = 0

    def complete(self, request: object) -> CompletionResponse:
        text = self._respond(self.calls, request.prompt)  # type: ignore[attr-defined]
        self.calls += 1
        return CompletionResponse(text=text, provider="fake", model="fake-model")


class _FakeContainer:
    """Stands in for RuntimeContainer - no real docker daemon required."""

    def __init__(self, config: object = None) -> None:
        self.started = False

    def start(self) -> None:
        self.started = True

    def stop(self) -> None:
        self.started = False

    def exec(self, command: object, *, timeout: float = 120.0) -> SimpleNamespace:
        return SimpleNamespace(exit_code=0, stdout="", stderr="", ok=True, timed_out=False)


def _record_finding_call() -> str:
    return json.dumps(
        {
            "tool": "record_finding",
            "args": {
                "title": "SQLi in search",
                "description": "unsanitized query param",
                "vuln_class": "sql-injection",
                "target": "https://example.com/search",
                "evidence": ["syntax error near 'OR'"],
                "evidence_excerpt": "syntax error near 'OR'",
                "counterevidence": "none found",
                "severity_change_conditions": "would drop if input were parameterized",
                "cvss_breakdown": _HIGH_CVSS,
            },
        }
    )


def _finish_call() -> str:
    return json.dumps({"tool": "finish", "args": {"summary": "found and filed one sqli"}})


def _respond(call_index: int, prompt: str) -> str:
    if "FINDING TO REVIEW" in prompt:
        return '{"verdict": "confirmed", "proof_level": "L3", "reasoning": "grounded"}'
    return _record_finding_call() if call_index == 0 else _finish_call()


def test_scan_runner_wires_every_phase_into_one_completed_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(scan_module, "docker_available", lambda: True)
    monkeypatch.setattr(scan_module, "RuntimeContainer", _FakeContainer)

    router = ModelRouter(
        providers={"fake": _ScriptedProvider(_respond)},
        routes={"reasoning": ("fake",), "review": ("fake",), "triage": ("fake",)},
        default_route=("fake",),
    )
    monkeypatch.setattr(scan_module, "build_router", lambda _settings: router)

    run_dir = tmp_path / "run"
    config = ScanConfig(mission="find a bug", target_specs=["example.com"], run_dir=run_dir)
    outcome = ScanRunner(config, env={"ANTHROPIC_API_KEY": "sk-test"}).run()

    assert outcome.status is RunStatus.COMPLETED
    assert outcome.result.summary == "found and filed one sqli"
    assert outcome.report_paths["markdown"].exists()
    assert "SQLi in search" in outcome.report_paths["markdown"].read_text()
    assert (run_dir / "graph.json").exists()


def test_scan_runner_emits_events_for_a_real_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(scan_module, "docker_available", lambda: True)
    monkeypatch.setattr(scan_module, "RuntimeContainer", _FakeContainer)
    router = ModelRouter(
        providers={"fake": _ScriptedProvider(_respond)},
        routes={"reasoning": ("fake",), "review": ("fake",)},
        default_route=("fake",),
    )
    monkeypatch.setattr(scan_module, "build_router", lambda _settings: router)

    event_log = EventLog()
    config = ScanConfig(
        mission="find a bug", target_specs=["example.com"], run_dir=tmp_path / "run"
    )
    ScanRunner(config, env={"ANTHROPIC_API_KEY": "sk-test"}, event_log=event_log).run()

    _cursor, events = event_log.snapshot()
    categories = [e.category for e in events]
    assert "finding" in categories
    assert any(e.payload.get("event") == "scan_started" for e in events)
    assert any(e.payload.get("event") == "scan_completed" for e in events)


def test_cancel_before_run_stops_on_the_first_step(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """should_stop is checked at the top of every loop iteration - a cancel
    requested before run() ever starts must stop before the first tool call."""
    monkeypatch.setattr(scan_module, "docker_available", lambda: True)
    monkeypatch.setattr(scan_module, "RuntimeContainer", _FakeContainer)
    provider = _ScriptedProvider(_respond)
    router = ModelRouter(
        providers={"fake": provider}, routes={"reasoning": ("fake",)}, default_route=("fake",)
    )
    monkeypatch.setattr(scan_module, "build_router", lambda _settings: router)

    config = ScanConfig(
        mission="find a bug", target_specs=["example.com"], run_dir=tmp_path / "run"
    )
    runner = ScanRunner(config, env={"ANTHROPIC_API_KEY": "sk-test"})
    runner.cancel()
    outcome = runner.run()

    assert outcome.status is RunStatus.UNVERIFIED_STOP
    assert provider.calls == 0


# --- merge_finding_nodes ------------------------------------------------------


def test_merge_finding_nodes_copies_a_childs_finding_onto_the_parent() -> None:
    parent = ReachabilityGraph()
    child = ReachabilityGraph()
    child.add_node("finding-1", NodeKind.FINDING, vuln_class="xss", target="https://x")
    merge_finding_nodes(parent, child, ["finding-1"])
    assert parent.has_node("finding-1")
    assert parent.node("finding-1")["vuln_class"] == "xss"


def test_merge_finding_nodes_never_overwrites_an_existing_parent_node() -> None:
    parent = ReachabilityGraph()
    parent.add_node("finding-1", NodeKind.FINDING, vuln_class="original")
    child = ReachabilityGraph()
    child.add_node("finding-1", NodeKind.FINDING, vuln_class="clobbered")
    merge_finding_nodes(parent, child, ["finding-1"])
    assert parent.node("finding-1")["vuln_class"] == "original"


def test_merge_finding_nodes_skips_an_id_absent_from_the_child() -> None:
    parent = ReachabilityGraph()
    child = ReachabilityGraph()
    merge_finding_nodes(parent, child, ["finding-never-filed"])
    assert not parent.has_node("finding-never-filed")


# --- browser tool wiring: one genuine end-to-end exception to the fake-only rule


class _Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler's own naming convention
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(b"<html><body><p>a real page for a real browser</p></body></html>")

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002 - stdlib signature
        pass


@pytest.fixture
def local_page_server() -> Iterator[str]:
    server = http.server.HTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{server.server_port}/"
    finally:
        server.shutdown()


@pytest.mark.integration
def test_scan_runner_dispatches_a_real_browser_tool_call(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, local_page_server: str
) -> None:
    monkeypatch.setattr(scan_module, "docker_available", lambda: True)
    monkeypatch.setattr(scan_module, "RuntimeContainer", _FakeContainer)

    def respond(call_index: int, prompt: str) -> str:
        if "FINDING TO REVIEW" in prompt:
            return '{"verdict": "confirmed", "proof_level": "L1", "reasoning": "n/a"}'
        if call_index == 0:
            return json.dumps(
                {"tool": "browser", "args": {"action": "navigate", "url": local_page_server}}
            )
        return json.dumps({"tool": "finish", "args": {"summary": "used the real browser"}})

    router = ModelRouter(
        providers={"fake": _ScriptedProvider(respond)},
        routes={"reasoning": ("fake",), "review": ("fake",)},
        default_route=("fake",),
    )
    monkeypatch.setattr(scan_module, "build_router", lambda _settings: router)

    config = ScanConfig(
        mission="check the page", target_specs=["127.0.0.1"], run_dir=tmp_path / "run"
    )
    outcome = ScanRunner(config, env={"ANTHROPIC_API_KEY": "sk-test"}).run()

    assert outcome.status is RunStatus.COMPLETED
    assert outcome.result.summary == "used the real browser"
    transcript = outcome.result.transcript
    browser_call = next(entry for entry in transcript if entry["tool"] == "browser")
    assert "a real page for a real browser" in browser_call["observation"]
