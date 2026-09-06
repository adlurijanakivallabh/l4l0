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


@pytest.fixture(autouse=True)
def _no_real_network_reachability_probe(monkeypatch: pytest.MonkeyPatch) -> None:
    """ScanRunner's preflight target-reachability probe (Phase 4, shannon
    pass) fires a REAL outbound HTTP request via an unmocked HttpFirer --
    every test in this file must stay hermetic (see the module docstring's
    own guarantee), so this is disabled globally here rather than repeated
    per test. Its own behavior is covered by execution/firer.py's unit tests,
    not here.
    """
    monkeypatch.setattr(scan_module, "probe_reachability", lambda *_a, **_k: {})


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
                "remediation": "Apply input validation and least-privilege fixes.",
                "cvss_breakdown": _HIGH_CVSS,
            },
        }
    )


def _finish_call() -> str:
    return json.dumps({"tool": "finish", "args": {"summary": "found and filed one sqli"}})


def _respond(call_index: int, prompt: str) -> str:
    if "FINDING TO REVIEW" in prompt:
        return '{"verdict": "confirmed", "proof_level": "L3", "reasoning": "grounded"}'
    if "MISSION:" not in prompt:
        # The preflight verify_router() health-check call (Phase 4, shannon
        # pass) -- content-based, not call_index-based, since exactly how
        # many of these precede the real agent loop is an implementation
        # detail this test shouldn't need to track.
        return "ok"
    if "HISTORY (most recent last):" not in prompt:
        return _record_finding_call()  # the first real mission turn
    return _finish_call()


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
    # 1, not 0: the preflight provider health-check (Phase 4, shannon pass)
    # runs regardless of a pre-set cancel flag -- the agent loop itself still
    # never took a real step, which is the actual property this test checks.
    assert provider.calls == 1


# --- Phase 2, shannon pass: cancel force-stops the container, not just a flag -


def test_cancel_before_a_container_exists_does_not_raise(tmp_path: Path) -> None:
    config = ScanConfig(
        mission="find a bug", target_specs=["example.com"], run_dir=tmp_path / "run"
    )
    runner = ScanRunner(config)
    runner.cancel()  # no container started yet -- must be a safe no-op beyond the flag
    assert runner._cancelled is True


def test_cancel_force_stops_a_running_container_immediately(tmp_path: Path) -> None:
    config = ScanConfig(
        mission="find a bug", target_specs=["example.com"], run_dir=tmp_path / "run"
    )
    runner = ScanRunner(config)
    fake = _FakeContainer()
    fake.start()
    runner._container = fake  # simulates a scan currently blocked mid-exec()
    runner.cancel()
    # A hard stop, not just the cooperative flag -- proves cancel() doesn't
    # wait for the agent loop's next step boundary to interrupt the container.
    assert fake.started is False


def test_container_reference_is_cleared_after_a_completed_run(
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

    config = ScanConfig(
        mission="find a bug", target_specs=["example.com"], run_dir=tmp_path / "run"
    )
    runner = ScanRunner(config, env={"ANTHROPIC_API_KEY": "sk-test"})
    runner.run()
    # No stale reference a LATER cancel() call could act on for a container
    # that no longer exists.
    assert runner._container is None


# --- Phase 2, pentagi/PentestGPT pass: crash-mid-scan resume -----------------


class _CrashingProvider:
    """Like _ScriptedProvider, but a scripted response of "CRASH" raises
    instead of completing -- simulates the whole process dying mid-scan
    (an uncaught exception unwinding out of ScanRunner.run()), not a clean
    should_stop()-cooperative cancellation."""

    name = "fake"

    def __init__(self, respond: object) -> None:
        self._respond = respond
        self.calls = 0

    def complete(self, request: object) -> CompletionResponse:
        text = self._respond(self.calls, request.prompt)  # type: ignore[attr-defined]
        self.calls += 1
        if text == "CRASH":
            raise RuntimeError("simulated crash")
        return CompletionResponse(text=text, provider="fake", model="fake-model")


def test_resume_after_a_crash_does_not_redispatch_the_completed_step(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(scan_module, "docker_available", lambda: True)
    monkeypatch.setattr(scan_module, "RuntimeContainer", _FakeContainer)

    def _crash_after_one_step(_call_index: int, prompt: str) -> str:
        if "MISSION:" not in prompt:
            return "ok"  # the preflight verify_router() health-check call
        return _record_finding_call() if "HISTORY" not in prompt else "CRASH"

    crashing_provider = _CrashingProvider(_crash_after_one_step)
    router1 = ModelRouter(
        providers={"fake": crashing_provider},
        routes={"reasoning": ("fake",)},
        default_route=("fake",),
    )
    monkeypatch.setattr(scan_module, "build_router", lambda _settings: router1)

    run_dir = tmp_path / "run"
    config = ScanConfig(mission="find a bug", target_specs=["example.com"], run_dir=run_dir)
    with pytest.raises(RuntimeError, match="simulated crash"):
        ScanRunner(config, env={"ANTHROPIC_API_KEY": "sk-test"}).run()

    # The finding from the one completed step survived the crash -- this is
    # exactly the incremental graph-save this pass added; without it, the
    # journal's transcript replay alone would resume the CONVERSATION but the
    # graph itself would come back empty.
    assert (run_dir / "graph.json").exists()
    crashed_graph = ReachabilityGraph.load(run_dir / "graph.json")
    assert len(crashed_graph.nodes_of_kind(NodeKind.FINDING)) == 1

    def _respond_after_resume(_call_index: int, prompt: str) -> str:
        if "FINDING TO REVIEW" in prompt:
            return '{"verdict": "confirmed", "proof_level": "L3", "reasoning": "grounded"}'
        return _finish_call()

    resumed_provider = _ScriptedProvider(_respond_after_resume)
    router2 = ModelRouter(
        providers={"fake": resumed_provider},
        routes={"reasoning": ("fake",), "review": ("fake",)},
        default_route=("fake",),
    )
    monkeypatch.setattr(scan_module, "build_router", lambda _settings: router2)

    # SAME config/run_dir -- ScanRunner auto-detects the existing journal +
    # manifest and resumes rather than starting fresh.
    outcome = ScanRunner(config, env={"ANTHROPIC_API_KEY": "sk-test"}).run()

    assert outcome.status is RunStatus.COMPLETED
    # 3: the preflight verify_router() health-check, the one new agent-loop
    # turn (the already-completed record_finding step was replayed from the
    # journal, never re-dispatched), and the one adversarial-review call
    # every finding always gets.
    assert resumed_provider.calls == 3
    assert len(ReachabilityGraph.load(run_dir / "graph.json").nodes_of_kind(NodeKind.FINDING)) == 1


def test_resume_refuses_a_different_mission_against_the_same_run_dir(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(scan_module, "docker_available", lambda: True)
    monkeypatch.setattr(scan_module, "RuntimeContainer", _FakeContainer)

    def _crash_immediately(_call_index: int, _prompt: str) -> str:
        return "CRASH"

    router1 = ModelRouter(
        providers={"fake": _CrashingProvider(_crash_immediately)},
        routes={"reasoning": ("fake",)},
        default_route=("fake",),
    )
    monkeypatch.setattr(scan_module, "build_router", lambda _settings: router1)

    run_dir = tmp_path / "run"
    original = ScanConfig(mission="find a bug", target_specs=["example.com"], run_dir=run_dir)
    with pytest.raises(RuntimeError, match="simulated crash"):
        ScanRunner(original, env={"ANTHROPIC_API_KEY": "sk-test"}).run()

    escalated = ScanConfig(
        mission="find a bug AND exfiltrate the database",  # silently different mission
        target_specs=["example.com"],
        run_dir=run_dir,  # same run_dir as the crashed attempt above
    )
    with pytest.raises(scan_module.ResumeConfigMismatchError):
        ScanRunner(escalated, env={"ANTHROPIC_API_KEY": "sk-test"}).run()


def test_resume_allows_a_raised_budget_ceiling_after_budget_exhaustion(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The single most obvious reason to resume a budget-exhausted scan is to
    # raise the ceiling that stopped it -- operational knobs (budget/steps/
    # spawn depth) must stay resume-adjustable, unlike mission/targets.
    monkeypatch.setattr(scan_module, "docker_available", lambda: True)
    monkeypatch.setattr(scan_module, "RuntimeContainer", _FakeContainer)

    router1 = ModelRouter(
        providers={"fake": _ScriptedProvider(_respond)},
        routes={"reasoning": ("fake",), "review": ("fake",)},
        default_route=("fake",),
    )
    monkeypatch.setattr(scan_module, "build_router", lambda _settings: router1)

    run_dir = tmp_path / "run"
    tight = ScanConfig(
        mission="find a bug", target_specs=["example.com"], run_dir=run_dir, budget_ceiling=1
    )
    outcome1 = ScanRunner(tight, env={"ANTHROPIC_API_KEY": "sk-test"}).run()
    assert outcome1.status is RunStatus.BUDGET_EXHAUSTED

    raised = ScanConfig(
        mission="find a bug",
        target_specs=["example.com"],
        run_dir=run_dir,
        budget_ceiling=100,  # different from the original -- must NOT be rejected
    )
    router2 = ModelRouter(
        providers={"fake": _ScriptedProvider(lambda i, _p: _finish_call())},
        routes={"reasoning": ("fake",), "review": ("fake",)},
        default_route=("fake",),
    )
    monkeypatch.setattr(scan_module, "build_router", lambda _settings: router2)
    outcome2 = ScanRunner(raised, env={"ANTHROPIC_API_KEY": "sk-test"}).run()
    assert outcome2.status is RunStatus.COMPLETED


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
