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
import stat
import threading
import time
from collections.abc import Callable, Iterator
from pathlib import Path
from types import SimpleNamespace

import pytest

import lalo.scan as scan_module
from lalo.agent.spawn import merge_finding_nodes
from lalo.agent.tools import FunctionTool, ToolResult
from lalo.core.errors import ConfigError, ContainerError, LoginFailedError, TargetUnreachableError
from lalo.core.model_router import CompletionResponse, ModelRouter
from lalo.core.usage import load_usage
from lalo.graph.model import NodeKind, ReachabilityGraph
from lalo.gui.events import EventLog
from lalo.identity.credentials import Credential, CredentialKind, Identity
from lalo.identity.login import LoginScheme, SessionSource
from lalo.integrations.mcp_client import MCPServerConfig
from lalo.orchestrator.budget import RunStatus
from lalo.orchestrator.journal import DurableJournal
from lalo.scan import (
    ScanConfig,
    ScanRunner,
    _diff_by_agent,
    _filter_tools,
    _ShellChunkCoalescer,
    _terminal_status,
    load_run_events,
    read_resume_manifest,
)


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


def test_diff_by_agent_handles_an_agent_present_in_only_one_snapshot() -> None:
    """An agent gone by "after" (unlikely in practice) or absent from
    "before" (the common case: a child spawned mid-run) must diff against a
    plain 0 baseline on the missing side, never raise a KeyError."""
    before = {
        "agent-1": {"requests": 3.0, "input_tokens": 100.0, "output_tokens": 20.0, "cost_usd": 0.1}
    }
    after = {
        "agent-1": {"requests": 5.0, "input_tokens": 150.0, "output_tokens": 30.0, "cost_usd": 0.2},
        "agent-2": {"requests": 2.0, "input_tokens": 40.0, "output_tokens": 10.0, "cost_usd": 0.05},
    }
    diff = _diff_by_agent(before, after)
    assert diff["agent-1"] == {
        "requests": 2.0,
        "input_tokens": 50.0,
        "output_tokens": 10.0,
        "cost_usd": pytest.approx(0.1),
    }
    # agent-2 has no "before" entry at all -- diffs against an implicit 0.
    assert diff["agent-2"] == {
        "requests": 2.0,
        "input_tokens": 40.0,
        "output_tokens": 10.0,
        "cost_usd": 0.05,
    }


# --- _ShellChunkCoalescer: pure unit ------------------------------------------


def test_shell_chunk_coalescer_passes_start_and_end_through_immediately() -> None:
    emitted: list[dict[str, object]] = []
    coalesce = _ShellChunkCoalescer(emitted.append)

    coalesce({"event": "start", "command_id": "c1", "command": "ls"})
    coalesce({"event": "end", "command_id": "c1", "exit_code": 0})

    assert emitted == [
        {"event": "start", "command_id": "c1", "command": "ls"},
        {"event": "end", "command_id": "c1", "exit_code": 0},
    ]


def test_shell_chunk_coalescer_merges_many_small_chunks_into_far_fewer_emits() -> None:
    emitted: list[dict[str, object]] = []
    coalesce = _ShellChunkCoalescer(emitted.append, threshold=100)

    coalesce({"event": "start", "command_id": "c1", "command": "feroxbuster"})
    for i in range(50):
        coalesce({"event": "chunk", "command_id": "c1", "stream": "stdout", "text": f"line {i}\n"})
    coalesce({"event": "end", "command_id": "c1", "exit_code": 0})

    chunk_events = [e for e in emitted if e["event"] == "chunk"]
    # 50 lines of ~7-8 chars each is ~375 chars total -- with a 100-char
    # threshold that's a handful of flushes, nowhere near 50 individual events.
    assert 1 <= len(chunk_events) < 10


def test_shell_chunk_coalescer_never_merges_stdout_and_stderr() -> None:
    emitted: list[dict[str, object]] = []
    coalesce = _ShellChunkCoalescer(emitted.append, threshold=1000)

    coalesce({"event": "start", "command_id": "c1", "command": "nmap"})
    coalesce({"event": "chunk", "command_id": "c1", "stream": "stdout", "text": "out-a\n"})
    coalesce({"event": "chunk", "command_id": "c1", "stream": "stderr", "text": "err-a\n"})
    coalesce({"event": "chunk", "command_id": "c1", "stream": "stdout", "text": "out-b\n"})
    coalesce({"event": "end", "command_id": "c1", "exit_code": 0})

    chunk_events = [e for e in emitted if e["event"] == "chunk"]
    by_stream = {e["stream"]: e["text"] for e in chunk_events}
    assert by_stream == {"stdout": "out-a\nout-b\n", "stderr": "err-a\n"}


def test_shell_chunk_coalescer_preserves_full_text_and_order_per_stream() -> None:
    emitted: list[dict[str, object]] = []
    coalesce = _ShellChunkCoalescer(emitted.append, threshold=20)

    coalesce({"event": "start", "command_id": "c1", "command": "gobuster"})
    expected = "".join(f"line-{i}\n" for i in range(30))
    for i in range(30):
        coalesce({"event": "chunk", "command_id": "c1", "stream": "stdout", "text": f"line-{i}\n"})
    coalesce({"event": "end", "command_id": "c1", "exit_code": 0})

    chunk_events = [e for e in emitted if e["event"] == "chunk" and e["stream"] == "stdout"]
    assert len(chunk_events) > 1  # actually coalesced, not a no-op passthrough
    assert "".join(str(e["text"]) for e in chunk_events) == expected


def test_shell_chunk_coalescer_flushes_pending_chunks_before_end_event() -> None:
    emitted: list[dict[str, object]] = []
    coalesce = _ShellChunkCoalescer(emitted.append, threshold=1000)

    coalesce({"event": "start", "command_id": "c1", "command": "id"})
    coalesce({"event": "chunk", "command_id": "c1", "stream": "stdout", "text": "uid=0\n"})
    coalesce({"event": "end", "command_id": "c1", "exit_code": 0})

    # The buffered chunk (well under the threshold) must still land, and
    # strictly before the "end" event -- never dropped, never reordered.
    events_order = [(e["event"], e.get("stream")) for e in emitted]
    assert events_order == [
        ("start", None),
        ("chunk", "stdout"),
        ("end", None),
    ]
    assert next(e for e in emitted if e["event"] == "chunk")["text"] == "uid=0\n"


def test_shell_chunk_coalescer_keeps_two_commands_independent() -> None:
    emitted: list[dict[str, object]] = []
    coalesce = _ShellChunkCoalescer(emitted.append, threshold=1000)

    coalesce({"event": "start", "command_id": "c1", "command": "id"})
    coalesce({"event": "chunk", "command_id": "c1", "stream": "stdout", "text": "c1-out\n"})
    coalesce({"event": "end", "command_id": "c1", "exit_code": 0})
    coalesce({"event": "start", "command_id": "c2", "command": "whoami"})
    coalesce({"event": "chunk", "command_id": "c2", "stream": "stdout", "text": "c2-out\n"})
    coalesce({"event": "end", "command_id": "c2", "exit_code": 0})

    chunk_events = [e for e in emitted if e["event"] == "chunk"]
    assert [e["command_id"] for e in chunk_events] == ["c1", "c2"]
    assert [e["text"] for e in chunk_events] == ["c1-out\n", "c2-out\n"]


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


def _tool(name: str) -> FunctionTool:
    return FunctionTool(name=name, description="", func=lambda args: ToolResult(observation=""))


def test_filter_tools_with_no_tool_names_includes_everything() -> None:
    tools = [_tool("record_finding"), _tool("recall"), _tool("http")]
    assert _filter_tools(tools, None) is tools


def test_filter_tools_with_a_tool_names_filter_only_includes_those_tools() -> None:
    tools = [_tool("record_finding"), _tool("recall"), _tool("http")]
    filtered = _filter_tools(tools, frozenset({"record_finding", "recall"}))
    assert {t.name for t in filtered} == {"record_finding", "recall"}


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

    def exec_streaming(
        self, command: object, on_chunk, *, timeout: float = 120.0
    ) -> SimpleNamespace:
        on_chunk("stdout", "")
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
        # The preflight verify_router() health-check call (Phase 4, a studied
        # reference agent's own pass) -- content-based, not call_index-based, since exactly how
        # many of these precede the real agent loop is an implementation
        # detail this test shouldn't need to track.
        return "ok"
    if "HISTORY (most recent last):" not in prompt:
        return _record_finding_call()  # the first real mission turn
    return _finish_call()


def _respond_run_command_then_finish(call_index: int, prompt: str) -> str:
    if "MISSION:" not in prompt:
        return "ok"
    if "HISTORY (most recent last):" not in prompt:
        return json.dumps({"tool": "run_command", "args": {"command": "ls"}})
    return _finish_call()


def _record_finding_call_for(target: str) -> str:
    return json.dumps(
        {
            "tool": "record_finding",
            "args": {
                "title": f"SQLi on {target}",
                "description": "unsanitized query param",
                "vuln_class": "sql-injection",
                "target": target,
                "evidence": ["syntax error near 'OR'"],
                "evidence_excerpt": "syntax error near 'OR'",
                "counterevidence": "none found",
                "severity_change_conditions": "would drop if input were parameterized",
                "remediation": "Apply input validation and least-privilege fixes.",
                "cvss_breakdown": _HIGH_CVSS,
            },
        }
    )


def _spawn_agents_call() -> str:
    return json.dumps(
        {
            "tool": "spawn_agents",
            "args": {
                "tasks": [
                    {"name": "Child A", "task": "CHILD-A-TASK: test host a.example.com"},
                    {"name": "Child B", "task": "CHILD-B-TASK: test host b.example.com"},
                ]
            },
        }
    )


def _respond_with_a_parallel_spawn(call_index: int, prompt: str) -> str:
    if "FINDING TO REVIEW" in prompt:
        return '{"verdict": "confirmed", "proof_level": "L3", "reasoning": "grounded"}'
    if "MISSION:" not in prompt:
        return "ok"  # the preflight verify_router() health-check call
    if "CHILD-A-TASK" in prompt:
        if "HISTORY (most recent last):" not in prompt:
            return _record_finding_call_for("https://a.example.com/search")
        return _finish_call()
    if "CHILD-B-TASK" in prompt:
        if "HISTORY (most recent last):" not in prompt:
            return _record_finding_call_for("https://b.example.com/search")
        return _finish_call()
    # the root's own mission turns
    if "HISTORY (most recent last):" not in prompt:
        return _spawn_agents_call()
    return _finish_call()


def test_scan_runner_dispatches_spawn_agents_and_merges_both_childrens_findings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(scan_module, "docker_available", lambda: True)
    monkeypatch.setattr(scan_module, "RuntimeContainer", _FakeContainer)
    router = ModelRouter(
        providers={"fake": _ScriptedProvider(_respond_with_a_parallel_spawn)},
        routes={"reasoning": ("fake",), "review": ("fake",)},
        default_route=("fake",),
    )
    monkeypatch.setattr(scan_module, "build_router", lambda _settings: router)

    config = ScanConfig(
        mission="find bugs across both hosts",
        target_specs=["a.example.com", "b.example.com"],
        run_dir=tmp_path / "run",
    )
    outcome = ScanRunner(config, env={"ANTHROPIC_API_KEY": "sk-test"}).run()

    assert outcome.status is RunStatus.COMPLETED
    graph = ReachabilityGraph.load(tmp_path / "run" / "graph.json")
    finding_ids = graph.nodes_of_kind(NodeKind.FINDING)
    targets = {graph.node(fid).get("target") for fid in finding_ids}
    assert targets == {"https://a.example.com/search", "https://b.example.com/search"}


_LEAKED_AWS_KEY = "AKIAABCDEFGHIJKLMNOP"


def _record_finding_call_with_a_secret() -> str:
    return json.dumps(
        {
            "tool": "record_finding",
            "args": {
                "title": "Leaked AWS key via SSRF",
                "description": "metadata endpoint reachable",
                "vuln_class": "ssrf",
                "target": "https://example.com/fetch",
                "evidence": [f"response body: aws_key={_LEAKED_AWS_KEY}"],
                "evidence_excerpt": f"aws_key={_LEAKED_AWS_KEY}",
                "counterevidence": "none found",
                "severity_change_conditions": "none",
                "remediation": "rotate the key and block metadata access",
                "cvss_breakdown": _HIGH_CVSS,
            },
        }
    )


def _respond_secret_finding(call_index: int, prompt: str) -> str:
    if "MISSION:" not in prompt:
        return "ok"
    if "HISTORY (most recent last):" not in prompt:
        return _record_finding_call_with_a_secret()
    return _finish_call()


def test_scan_runner_leaves_a_captured_secret_unredacted_by_default(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Closes an explicit, informed operator request: ScanConfig.redact_findings
    defaults to False, so a captured secret appears verbatim in the
    delivered report - not the old, conservative default."""
    monkeypatch.setattr(scan_module, "docker_available", lambda: True)
    monkeypatch.setattr(scan_module, "RuntimeContainer", _FakeContainer)
    router = ModelRouter(
        providers={"fake": _ScriptedProvider(_respond_secret_finding)},
        routes={"reasoning": ("fake",), "review": ("fake",)},
        default_route=("fake",),
    )
    monkeypatch.setattr(scan_module, "build_router", lambda _settings: router)

    config = ScanConfig(
        mission="find a bug", target_specs=["example.com"], run_dir=tmp_path / "run"
    )
    outcome = ScanRunner(config, env={"ANTHROPIC_API_KEY": "sk-test"}).run()

    report_json = json.loads(outcome.report_paths["json"].read_text())
    evidence = report_json["findings"][0]["evidence"][0]
    assert _LEAKED_AWS_KEY in evidence


def test_scan_runner_still_redacts_when_redact_findings_is_explicitly_true(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(scan_module, "docker_available", lambda: True)
    monkeypatch.setattr(scan_module, "RuntimeContainer", _FakeContainer)
    router = ModelRouter(
        providers={"fake": _ScriptedProvider(_respond_secret_finding)},
        routes={"reasoning": ("fake",), "review": ("fake",)},
        default_route=("fake",),
    )
    monkeypatch.setattr(scan_module, "build_router", lambda _settings: router)

    config = ScanConfig(
        mission="find a bug",
        target_specs=["example.com"],
        run_dir=tmp_path / "run",
        redact_findings=True,
    )
    outcome = ScanRunner(config, env={"ANTHROPIC_API_KEY": "sk-test"}).run()

    report_json = json.loads(outcome.report_paths["json"].read_text())
    evidence = report_json["findings"][0]["evidence"][0]
    assert _LEAKED_AWS_KEY not in evidence


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
    assert "**Scan Status:** completed" in outcome.report_paths["markdown"].read_text()
    assert json.loads(outcome.report_paths["json"].read_text())["status"] == "completed"
    assert (run_dir / "graph.json").exists()

    trace_path = run_dir / "trace.json"
    trace = json.loads(trace_path.read_text())
    assert any(s["name"] == "agent_step" for s in trace["spans"])
    assert trace["counters"].get("tool_calls", 0) > 0
    # A span's own attributes can carry the same confidential engagement/
    # target data the graph and report files do - same owner-only guarantee.
    assert stat.S_IMODE(trace_path.stat().st_mode) == 0o600


def test_scan_runner_threads_real_engagement_scope_and_model_into_the_report(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """End-to-end: the real write_report() call site in _run_inside must
    build ReportMetadata from the SAME engagement.describe() already
    computed for the agent prompt, and from the resolved provider chain -
    never a second, independently-guessed value. Deliberately does NOT set
    usage_path, to prove engagement/model metadata appears even when the
    operator never opted into usage tracking (unlike ReportUsage, which is
    absent here on purpose)."""
    monkeypatch.setattr(scan_module, "docker_available", lambda: True)
    monkeypatch.setattr(scan_module, "RuntimeContainer", _FakeContainer)
    router = ModelRouter(
        providers={"fake": _ScriptedProvider(_respond)},
        routes={"reasoning": ("fake",), "review": ("fake",), "triage": ("fake",)},
        default_route=("fake",),
    )
    monkeypatch.setattr(scan_module, "build_router", lambda _settings: router)

    config = ScanConfig(
        mission="find a bug", target_specs=["example.com"], run_dir=tmp_path / "run"
    )
    outcome = ScanRunner(config, env={"ANTHROPIC_API_KEY": "sk-test"}).run()

    report_json = json.loads(outcome.report_paths["json"].read_text())
    assert report_json["engagement"] == {
        "engagement_scope": "- example.com",
        "model_provider": "anthropic:claude-sonnet-5",
    }
    markdown = outcome.report_paths["markdown"].read_text()
    assert "**Model / Provider:** anthropic:claude-sonnet-5" in markdown
    assert "- example.com" in markdown


def test_scan_runner_emits_a_trace_summary_on_the_completed_event(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Closes a real gap an audit found: Tracer's own spans/counters were
    collected, logged at debug level, and then discarded - nothing anywhere
    ever surfaced them, during or after a run."""
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
    completed = next(e for e in events if e.payload.get("event") == "scan_completed")
    summary = completed.payload["trace_summary"]
    assert "agent_step" in summary["spans"]
    assert summary["spans"]["agent_step"]["count"] >= 1
    assert summary["counters"].get("tool_calls", 0) > 0


def test_scan_runner_emits_wall_clock_seconds_alongside_summed_span_durations(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """wall_clock_seconds is the interval-union across spans, distinct from
    summing every span's own duration - a spawn_agents fan-out's concurrent
    spans overlap in real time, so a plain sum overcounts wall-clock elapsed."""
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
    completed = next(e for e in events if e.payload.get("event") == "scan_completed")
    summary = completed.payload["trace_summary"]
    assert isinstance(summary["wall_clock_seconds"], float)
    assert summary["wall_clock_seconds"] >= 0.0


def test_scan_runner_emits_shell_events_for_a_real_run_command_call(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(scan_module, "docker_available", lambda: True)
    monkeypatch.setattr(scan_module, "RuntimeContainer", _FakeContainer)
    router = ModelRouter(
        providers={"fake": _ScriptedProvider(_respond_run_command_then_finish)},
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
    shell_events = [e for e in events if e.category == "shell"]
    assert any(e.payload.get("event") == "start" for e in shell_events)
    assert any(
        e.payload.get("event") == "end" and e.payload.get("exit_code") == 0 for e in shell_events
    )


def test_scan_runner_enable_second_opinion_review_runs_a_second_review_call(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(scan_module, "docker_available", lambda: True)
    monkeypatch.setattr(scan_module, "RuntimeContainer", _FakeContainer)
    provider = _ScriptedProvider(_respond)
    router = ModelRouter(
        providers={"fake": provider},
        routes={"reasoning": ("fake",), "review": ("fake",)},
        default_route=("fake",),
    )
    monkeypatch.setattr(scan_module, "build_router", lambda _settings: router)

    run_dir = tmp_path / "run"
    config = ScanConfig(
        mission="find a bug",
        target_specs=["example.com"],
        run_dir=run_dir,
        enable_second_opinion_review=True,
    )
    ScanRunner(config, env={"ANTHROPIC_API_KEY": "sk-test"}).run()

    graph = ReachabilityGraph.load(run_dir / "graph.json")
    finding_id = graph.nodes_of_kind(NodeKind.FINDING)[0]
    assert "second_opinion_verdict" in graph.node(finding_id)


def test_scan_runner_injects_rules_of_engagement_into_the_system_prompt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(scan_module, "docker_available", lambda: True)
    monkeypatch.setattr(scan_module, "RuntimeContainer", _FakeContainer)

    seen_systems: list[str] = []

    class _CapturingProvider:
        name = "fake"

        def complete(self, request: object) -> CompletionResponse:
            seen_systems.append(getattr(request, "system", None) or "")
            return CompletionResponse(
                text=_respond(0, request.prompt),  # type: ignore[attr-defined]
                provider="fake",
                model="fake-model",
            )

    router = ModelRouter(
        providers={"fake": _CapturingProvider()},
        routes={"reasoning": ("fake",), "review": ("fake",)},
        default_route=("fake",),
    )
    monkeypatch.setattr(scan_module, "build_router", lambda _settings: router)

    config = ScanConfig(
        mission="find a bug",
        target_specs=["example.com"],
        run_dir=tmp_path / "run",
        rules_of_engagement="no destructive testing; do not touch /admin",
    )
    ScanRunner(config, env={"ANTHROPIC_API_KEY": "sk-test"}).run()

    assert any("no destructive testing; do not touch /admin" in s for s in seen_systems)


def test_scan_runner_defaults_rules_of_engagement_to_a_stated_none(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(scan_module, "docker_available", lambda: True)
    monkeypatch.setattr(scan_module, "RuntimeContainer", _FakeContainer)

    seen_systems: list[str] = []

    class _CapturingProvider:
        name = "fake"

        def complete(self, request: object) -> CompletionResponse:
            seen_systems.append(getattr(request, "system", None) or "")
            return CompletionResponse(
                text=_respond(0, request.prompt),  # type: ignore[attr-defined]
                provider="fake",
                model="fake-model",
            )

    router = ModelRouter(
        providers={"fake": _CapturingProvider()},
        routes={"reasoning": ("fake",), "review": ("fake",)},
        default_route=("fake",),
    )
    monkeypatch.setattr(scan_module, "build_router", lambda _settings: router)

    config = ScanConfig(
        mission="find a bug", target_specs=["example.com"], run_dir=tmp_path / "run"
    )
    ScanRunner(config, env={"ANTHROPIC_API_KEY": "sk-test"}).run()

    assert any(
        "none specified beyond the engagement scope and mission above" in s for s in seen_systems
    )


def test_scan_runner_applies_exclude_target_specs_end_to_end(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The exclude carve-out (execution/target.py) actually reaches the live
    ScopeGuard a real scan's http tool fires through, not just the unit-level
    Engagement it was added to."""
    monkeypatch.setattr(scan_module, "docker_available", lambda: True)
    monkeypatch.setattr(scan_module, "RuntimeContainer", _FakeContainer)

    def respond(_call_index: int, prompt: str) -> str:
        if "MISSION:" not in prompt:
            return "ok"
        if "HISTORY (most recent last):" not in prompt:
            return json.dumps({"tool": "http", "args": {"url": "https://excluded.example.com/"}})
        return _finish_call()

    router = ModelRouter(
        providers={"fake": _ScriptedProvider(respond)},
        routes={"reasoning": ("fake",), "review": ("fake",)},
        default_route=("fake",),
    )
    monkeypatch.setattr(scan_module, "build_router", lambda _settings: router)

    config = ScanConfig(
        mission="test the excluded host",
        target_specs=["*.example.com"],
        exclude_target_specs=["excluded.example.com"],
        run_dir=tmp_path / "run",
    )
    outcome = ScanRunner(config, env={"ANTHROPIC_API_KEY": "sk-test"}).run()

    http_call = next(e for e in outcome.result.transcript if e["tool"] == "http")
    assert "not fired" in http_call["observation"]
    assert "out_of_engagement" in http_call["observation"]


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
    completed = next(e for e in events if e.payload.get("event") == "scan_completed")
    assert set(completed.payload["report_paths"]) == {
        "markdown",
        "json",
        "sarif",
        "csv",
        "pdf",
        "docx",
    }
    # usage_path was never configured on this ScanConfig -- usage_delta must be
    # absent, never a fabricated zero.
    assert "usage_delta" not in completed.payload


def test_scan_runner_emits_usage_delta_when_usage_path_is_configured(
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
        mission="find a bug",
        target_specs=["example.com"],
        run_dir=tmp_path / "run",
        usage_path=tmp_path / "usage.json",
    )
    ScanRunner(config, env={"ANTHROPIC_API_KEY": "sk-test"}, event_log=event_log).run()

    _cursor, events = event_log.snapshot()
    completed = next(e for e in events if e.payload.get("event") == "scan_completed")
    usage_delta = completed.payload["usage_delta"]
    assert set(usage_delta) == {"requests", "input_tokens", "output_tokens", "by_agent"}
    # The scripted provider's completions carry no real usage figures, so the
    # token deltas are honestly 0 -- but real completions did happen this run,
    # so the request count must reflect that, not also default to 0.
    assert usage_delta["requests"] > 0
    # AgentCoordinator hands out ids as "agent-N" starting from 1 - the root
    # agent registered by ScanRunner.run() is always the first one.
    assert usage_delta["by_agent"]["agent-1"]["requests"] > 0
    assert set(usage_delta["by_agent"]) == {"agent-1"}  # a single-agent scan; no children spawned
    # A multi-agent variant proving real per-child attribution lives below as
    # test_scan_runner_emits_usage_delta_by_agent_for_a_sequentially_spawned_child,
    # using the sequential spawn_agent path (single in-thread child, no
    # concurrent writers). A PARALLEL spawn_agents variant was tried first and
    # was flaky: two children's AgentLoops run on real OS threads and both
    # call record_usage against the SAME usage_path concurrently, which
    # core/usage.py's own module docstring already documents as a deliberately
    # unlocked read-modify-write ("a real but low-probability edge case, not
    # worth the complexity of process-level file locking") - that race is real
    # for the parallel path, but does not apply to the sequential one below.


def _spawn_agent_call() -> str:
    # The SINGULAR spawn tool (build_spawn_tools/_spawn in agent/spawn.py)
    # takes {"name": str, "task": str} and runs the child to completion
    # synchronously, in-thread, before returning - unlike spawn_agents'
    # {"tasks": [...]} (build_parallel_spawn_tool), which fans out over a
    # ThreadPoolExecutor. No concurrent record_usage writers here.
    return json.dumps(
        {
            "tool": "spawn_agent",
            "args": {"name": "Child C", "task": "CHILD-C-TASK: test host c.example.com"},
        }
    )


def _respond_with_a_sequential_spawn(call_index: int, prompt: str) -> str:
    if "FINDING TO REVIEW" in prompt:
        return '{"verdict": "confirmed", "proof_level": "L3", "reasoning": "grounded"}'
    if "MISSION:" not in prompt:
        return "ok"  # the preflight verify_router() health-check call
    if "CHILD-C-TASK" in prompt:
        # The spawned child does a little real work (files a finding, one
        # real completion) before finishing (a second real completion) - both
        # attributed to the child's own distinct agent_id.
        if "HISTORY (most recent last):" not in prompt:
            return _record_finding_call_for("https://c.example.com/search")
        return _finish_call()
    # the root's own mission turns
    if "HISTORY (most recent last):" not in prompt:
        return _spawn_agent_call()
    return _finish_call()


def test_scan_runner_emits_usage_delta_by_agent_for_a_sequentially_spawned_child(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The single-agent test above proves the diffing mechanism but can't
    prove real per-child attribution end-to-end (only one agent_id ever
    exists in that run). A single sequential spawn_agent call - unlike
    spawn_agents' parallel fan-out - runs its child to completion on the SAME
    thread before the root resumes, so there is zero concurrent-write
    exposure to record_usage's unlocked read-modify-write: this proves the
    root's and the spawned child's distinct agent_ids both actually flow
    through to usage_delta["by_agent"], without the parallel path's race.
    """
    monkeypatch.setattr(scan_module, "docker_available", lambda: True)
    monkeypatch.setattr(scan_module, "RuntimeContainer", _FakeContainer)
    router = ModelRouter(
        providers={"fake": _ScriptedProvider(_respond_with_a_sequential_spawn)},
        routes={"reasoning": ("fake",), "review": ("fake",)},
        default_route=("fake",),
    )
    monkeypatch.setattr(scan_module, "build_router", lambda _settings: router)

    event_log = EventLog()
    config = ScanConfig(
        mission="find a bug, spawning one child for a focused subtask",
        target_specs=["c.example.com"],
        run_dir=tmp_path / "run",
        usage_path=tmp_path / "usage.json",
    )
    ScanRunner(config, env={"ANTHROPIC_API_KEY": "sk-test"}, event_log=event_log).run()

    _cursor, events = event_log.snapshot()
    completed = next(e for e in events if e.payload.get("event") == "scan_completed")
    by_agent = completed.payload["usage_delta"]["by_agent"]
    # agent-1 is the root; agent-2 is the one sequentially spawned child.
    assert set(by_agent) == {"agent-1", "agent-2"}
    assert by_agent["agent-1"]["requests"] >= 1
    assert by_agent["agent-2"]["requests"] >= 1


def test_scan_runner_emits_agent_events_for_a_spawned_childs_lifecycle(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The GUI's own "Agents" sidebar count and per-agent status line
    (app.js's "agent" websocket category) had a full frontend handler but
    nothing ever emitted that category - the counter silently read 0 even
    with real children running. This proves a spawned child's running/
    completed transition actually reaches the event log now.
    """
    monkeypatch.setattr(scan_module, "docker_available", lambda: True)
    monkeypatch.setattr(scan_module, "RuntimeContainer", _FakeContainer)
    router = ModelRouter(
        providers={"fake": _ScriptedProvider(_respond_with_a_sequential_spawn)},
        routes={"reasoning": ("fake",), "review": ("fake",)},
        default_route=("fake",),
    )
    monkeypatch.setattr(scan_module, "build_router", lambda _settings: router)

    event_log = EventLog()
    config = ScanConfig(
        mission="find a bug, spawning one child for a focused subtask",
        target_specs=["c.example.com"],
        run_dir=tmp_path / "run",
        usage_path=tmp_path / "usage.json",
    )
    ScanRunner(config, env={"ANTHROPIC_API_KEY": "sk-test"}, event_log=event_log).run()

    _cursor, events = event_log.snapshot()
    agent_events = [e for e in events if e.category == "agent"]
    assert [e.payload["status"] for e in agent_events] == ["running", "completed"]
    assert all(e.payload["agent_id"] == "agent-2" for e in agent_events)
    assert agent_events[0].payload["name"] == "Child C"
    assert agent_events[0].payload["task"] == "CHILD-C-TASK: test host c.example.com"


def test_scan_runner_still_emits_a_failed_agent_event_when_a_child_raises(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """_run_child's terminal "agent" event was only ever reached if
    child_loop.run() returned normally - if it raised (a real, anticipated
    path: agent/spawn.py's own _spawn wraps exactly this call in its own
    except Exception, with a comment saying so), the child's GUI status
    line got stuck showing "running" forever even though the coordinator
    itself correctly marked the node failed. The overall scan still
    completes normally (spawn_agent's own crash handling lets the root
    continue) - only the missing terminal GUI event is what this proves
    is now fixed.
    """
    monkeypatch.setattr(scan_module, "docker_available", lambda: True)
    monkeypatch.setattr(scan_module, "RuntimeContainer", _FakeContainer)

    def _respond_with_a_crashing_child(call_index: int, prompt: str) -> str:
        if "MISSION:" not in prompt:
            return "ok"
        if prompt.startswith("MISSION:\nCHILD-C-TASK"):
            raise RuntimeError("simulated child crash")
        if "HISTORY (most recent last):" not in prompt:
            return _spawn_agent_call()
        return _finish_call()

    router = ModelRouter(
        providers={"fake": _ScriptedProvider(_respond_with_a_crashing_child)},
        routes={"reasoning": ("fake",), "review": ("fake",)},
        default_route=("fake",),
    )
    monkeypatch.setattr(scan_module, "build_router", lambda _settings: router)

    event_log = EventLog()
    config = ScanConfig(
        mission="find a bug, spawning one child for a focused subtask",
        target_specs=["c.example.com"],
        run_dir=tmp_path / "run",
        usage_path=tmp_path / "usage.json",
    )
    outcome = ScanRunner(config, env={"ANTHROPIC_API_KEY": "sk-test"}, event_log=event_log).run()
    assert outcome.status is RunStatus.COMPLETED  # the root recovers; only the child crashed

    _cursor, events = event_log.snapshot()
    agent_events = [e for e in events if e.category == "agent"]
    assert [e.payload["status"] for e in agent_events] == ["running", "failed"]
    assert all(e.payload["agent_id"] == "agent-2" for e in agent_events)


def test_run_child_journals_a_spawned_breadcrumb_before_running_and_a_finished_one_after(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(scan_module, "docker_available", lambda: True)
    monkeypatch.setattr(scan_module, "RuntimeContainer", _FakeContainer)
    router = ModelRouter(
        providers={"fake": _ScriptedProvider(_respond_with_a_sequential_spawn)},
        routes={"reasoning": ("fake",), "review": ("fake",)},
        default_route=("fake",),
    )
    monkeypatch.setattr(scan_module, "build_router", lambda _settings: router)

    run_dir = tmp_path / "run"
    config = ScanConfig(
        mission="find a bug, spawning one child for a focused subtask",
        target_specs=["c.example.com"],
        run_dir=run_dir,
        usage_path=tmp_path / "usage.json",
    )
    ScanRunner(config, env={"ANTHROPIC_API_KEY": "sk-test"}).run()

    journal = DurableJournal(run_dir / "journal.jsonl")
    assert journal.has("agent-2:spawned")
    spawned = journal.get("agent-2:spawned")
    assert spawned["name"] == "Child C"
    assert spawned["task"] == "CHILD-C-TASK: test host c.example.com"
    assert spawned["parent_id"] == "agent-1"
    assert spawned["depth"] == 1
    assert spawned["role"] == "full"
    assert journal.has("agent-2:finished")


def _spawn_source_reviewer_call() -> str:
    return json.dumps(
        {
            "tool": "spawn_agent",
            "args": {
                "name": "Source Reviewer",
                "task": "SOURCE-REVIEW-TASK: read the repo for injection sinks",
                "role": "source_reviewer",
            },
        }
    )


def _respond_with_a_source_reviewer_spawn(
    captured_child_prompts: list[str],
) -> Callable[[int, str], str]:
    def _respond(call_index: int, prompt: str) -> str:
        if "MISSION:" not in prompt:
            return "ok"  # the preflight verify_router() health-check call
        # Anchored on the MISSION line itself (not a bare substring check):
        # the root's OWN history recap of its spawn_agent call echoes the
        # child's task text verbatim, so a bare "SOURCE-REVIEW-TASK in
        # prompt" check would misfire on the root's own later turn too.
        if prompt.startswith("MISSION:\nSOURCE-REVIEW-TASK"):
            captured_child_prompts.append(prompt)
            return _finish_call()
        # the root's own turns
        if "HISTORY (most recent last):" not in prompt:
            return _spawn_source_reviewer_call()
        return _finish_call()

    return _respond


def test_a_source_reviewer_child_gets_a_confined_toolset(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(scan_module, "docker_available", lambda: True)
    monkeypatch.setattr(scan_module, "RuntimeContainer", _FakeContainer)
    captured_child_prompts: list[str] = []
    router = ModelRouter(
        providers={
            "fake": _ScriptedProvider(_respond_with_a_source_reviewer_spawn(captured_child_prompts))
        },
        routes={"reasoning": ("fake",), "review": ("fake",)},
        default_route=("fake",),
    )
    monkeypatch.setattr(scan_module, "build_router", lambda _settings: router)

    config = ScanConfig(
        mission="find a bug, spawning a source reviewer",
        target_specs=["c.example.com"],
        run_dir=tmp_path / "run",
        usage_path=tmp_path / "usage.json",
    )
    ScanRunner(config, env={"ANTHROPIC_API_KEY": "sk-test"}).run()

    assert len(captured_child_prompts) == 1
    child_prompt = captured_child_prompts[0]
    assert "run_command" in child_prompt
    assert "record_finding" in child_prompt
    assert "recall" in child_prompt
    assert "http:" not in child_prompt  # the http tool's own name-colon form in the tool list
    assert "spawn_agent:" not in child_prompt


def _respond_with_a_sequentially_spawned_child_running_a_command(
    call_index: int, prompt: str
) -> str:
    if "MISSION:" not in prompt:
        return "ok"  # the preflight verify_router() health-check call
    if "CHILD-C-TASK" in prompt:
        if "HISTORY (most recent last):" not in prompt:
            return json.dumps({"tool": "run_command", "args": {"command": "whoami"}})
        return _finish_call()
    # the root's own mission turns
    if "HISTORY (most recent last):" not in prompt:
        return _spawn_agent_call()
    return _finish_call()


def test_scan_runner_persists_a_spawned_childs_tool_observation_in_the_event_log(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The actual gap this closes (not just a root-only proof): before, the
    full {tool, args, observation, ok} shape only ever reached the root's own
    local transcript/journal (at the time, a spawned child's own AgentLoop
    was always constructed with journal=None -- children are journaled too
    now, under their own agent_key, but that's a separate, later fix), so a
    child's own "tool_result" event carried only {tool, ok} - its observation
    was visible nowhere durable. AgentLoop._emit is the identical code path
    for every agent regardless of role, so this proves the fix for a REAL
    spawned child (agent-2), not just the root (agent-1)."""
    monkeypatch.setattr(scan_module, "docker_available", lambda: True)
    monkeypatch.setattr(scan_module, "RuntimeContainer", _FakeContainer)
    router = ModelRouter(
        providers={
            "fake": _ScriptedProvider(_respond_with_a_sequentially_spawned_child_running_a_command)
        },
        routes={"reasoning": ("fake",), "review": ("fake",)},
        default_route=("fake",),
    )
    monkeypatch.setattr(scan_module, "build_router", lambda _settings: router)

    event_log = EventLog()
    config = ScanConfig(
        mission="find a bug, spawning one child for a focused subtask",
        target_specs=["c.example.com"],
        run_dir=tmp_path / "run",
    )
    ScanRunner(config, env={"ANTHROPIC_API_KEY": "sk-test"}, event_log=event_log).run()

    _cursor, events = event_log.snapshot()
    tool_result_events = [
        e for e in events if e.category == "log" and e.payload.get("event") == "tool_result"
    ]
    child_result = next(e for e in tool_result_events if e.payload.get("tool") == "run_command")
    assert child_result.payload["agent_id"] == "agent-2"  # the spawned child, not the root
    observation = child_result.payload.get("observation")
    assert isinstance(observation, str) and observation


def test_scan_runner_journals_a_spawned_childs_own_steps(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Before this fix, child_loop.run(task) never passed journal=/agent_key=,
    so only the root's own steps were durably resumable - a spawned child
    still mid-execution at crash time silently restarted from scratch. Reuses
    the same fixture as the test above (a sequential spawn whose child runs
    one real run_command call) to prove the child's own step now lands in the
    SAME journal file under its own agent_id ("agent-2"), alongside the root's
    pre-existing "root:0", "root:1", ... entries.
    """
    monkeypatch.setattr(scan_module, "docker_available", lambda: True)
    monkeypatch.setattr(scan_module, "RuntimeContainer", _FakeContainer)
    router = ModelRouter(
        providers={
            "fake": _ScriptedProvider(_respond_with_a_sequentially_spawned_child_running_a_command)
        },
        routes={"reasoning": ("fake",), "review": ("fake",)},
        default_route=("fake",),
    )
    monkeypatch.setattr(scan_module, "build_router", lambda _settings: router)

    run_dir = tmp_path / "run"
    event_log = EventLog()
    config = ScanConfig(
        mission="find a bug, spawning one child for a focused subtask",
        target_specs=["c.example.com"],
        run_dir=run_dir,
    )
    ScanRunner(config, env={"ANTHROPIC_API_KEY": "sk-test"}, event_log=event_log).run()

    journal = DurableJournal(run_dir / "journal.jsonl")
    assert journal.has("root:0")  # pre-existing behavior: the root's own step
    # The new requirement: the spawned child's own step must ALSO be present,
    # under its own agent_id ("agent-2" - agent-1 is the root).
    assert journal.has("agent-2:0")


def test_scan_runner_estimates_cost_when_a_pricing_table_is_configured(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Closes a real gap: record_usage's own pricing_table parameter was
    fully built and tested but never actually passed from the one real call
    site - every live run left UsageStats.total_cost_usd permanently at 0.0,
    and the delivered report had no cost/token figures at all."""
    monkeypatch.setattr(scan_module, "docker_available", lambda: True)
    monkeypatch.setattr(scan_module, "RuntimeContainer", _FakeContainer)

    class _TokenReportingProvider:
        name = "fake"
        calls = 0

        def complete(self, request: object) -> CompletionResponse:
            text = _respond(self.calls, request.prompt)  # type: ignore[attr-defined]
            self.calls += 1
            return CompletionResponse(
                text=text,
                provider="fake",
                model="fake-model",
                input_tokens=1000,
                output_tokens=100,
            )

    router = ModelRouter(
        providers={"fake": _TokenReportingProvider()},
        routes={"reasoning": ("fake",), "review": ("fake",)},
        default_route=("fake",),
    )
    monkeypatch.setattr(scan_module, "build_router", lambda _settings: router)

    run_dir = tmp_path / "run"
    config = ScanConfig(
        mission="find a bug",
        target_specs=["example.com"],
        run_dir=run_dir,
        usage_path=tmp_path / "usage.json",
        pricing_table={"fake-model": (1.0, 2.0)},  # $1/$2 per million input/output tokens
    )
    outcome = ScanRunner(config, env={"ANTHROPIC_API_KEY": "sk-test"}).run()

    report_json = json.loads(outcome.report_paths["json"].read_text())
    assert report_json["usage"]["total_cost_usd"] > 0
    assert report_json["usage"]["total_input_tokens"] > 0
    assert "est. cost $" in outcome.report_paths["markdown"].read_text()


def test_scan_runner_report_usage_is_unknown_cost_with_no_pricing_table(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """total_cost_usd must read as unknown (None/absent), never a fabricated
    $0.00, when the operator never configured a pricing table."""
    monkeypatch.setattr(scan_module, "docker_available", lambda: True)
    monkeypatch.setattr(scan_module, "RuntimeContainer", _FakeContainer)
    router = ModelRouter(
        providers={"fake": _ScriptedProvider(_respond)},
        routes={"reasoning": ("fake",), "review": ("fake",)},
        default_route=("fake",),
    )
    monkeypatch.setattr(scan_module, "build_router", lambda _settings: router)

    config = ScanConfig(
        mission="find a bug",
        target_specs=["example.com"],
        run_dir=tmp_path / "run",
        usage_path=tmp_path / "usage.json",
    )
    outcome = ScanRunner(config, env={"ANTHROPIC_API_KEY": "sk-test"}).run()

    report_json = json.loads(outcome.report_paths["json"].read_text())
    assert report_json["usage"]["total_cost_usd"] is None
    assert "cost" not in outcome.report_paths["markdown"].read_text().lower()


def test_scan_runner_durably_persists_events_even_with_no_live_event_log(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """EventLog is process-lifetime, not run-scoped, and a caller can run a
    scan with no event_log attached at all (event_log=None) - durable
    narration must not depend on either."""
    monkeypatch.setattr(scan_module, "docker_available", lambda: True)
    monkeypatch.setattr(scan_module, "RuntimeContainer", _FakeContainer)
    router = ModelRouter(
        providers={"fake": _ScriptedProvider(_respond)},
        routes={"reasoning": ("fake",), "review": ("fake",)},
        default_route=("fake",),
    )
    monkeypatch.setattr(scan_module, "build_router", lambda _settings: router)

    run_dir = tmp_path / "run"
    config = ScanConfig(mission="find a bug", target_specs=["example.com"], run_dir=run_dir)
    ScanRunner(config, env={"ANTHROPIC_API_KEY": "sk-test"}).run()  # no event_log passed

    events_path = run_dir / "events.jsonl"
    assert events_path.exists()
    replay = load_run_events(run_dir)
    _cursor, events = replay.snapshot()
    assert any(e.payload.get("event") == "scan_started" for e in events)
    assert any(e.category == "finding" for e in events)


def test_load_run_events_on_a_missing_file_is_an_empty_log(tmp_path: Path) -> None:
    replay = load_run_events(tmp_path / "no-such-run")
    cursor, events = replay.snapshot()
    assert cursor == 0
    assert events == []


def test_load_run_events_skips_a_torn_final_line_from_a_crash(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    (run_dir / "events.jsonl").write_text(
        '{"category": "status", "payload": {"event": "scan_started"}}\n'
        '{"category": "log", "payload": {"tex',  # torn mid-write, no trailing newline
        encoding="utf-8",
    )
    replay = load_run_events(run_dir)
    _cursor, events = replay.snapshot()
    assert len(events) == 1
    assert events[0].payload == {"event": "scan_started"}


def test_read_resume_manifest_on_a_run_that_never_started_is_none(tmp_path: Path) -> None:
    assert read_resume_manifest(tmp_path / "never-started") is None


def test_read_resume_manifest_returns_the_locked_engagement_fields(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    (run_dir / "resume_manifest.json").write_text(
        '{"mission": "find a bug", "target_specs": ["example.com"], '
        '"exclude_target_specs": ["admin.example.com"], '
        '"rules_of_engagement": "no destructive testing", "egress_lock": true}',
        encoding="utf-8",
    )
    manifest = read_resume_manifest(run_dir)
    assert manifest == {
        "mission": "find a bug",
        "target_specs": ["example.com"],
        "exclude_target_specs": ["admin.example.com"],
        "rules_of_engagement": "no destructive testing",
        "egress_lock": True,
    }


def test_scan_runner_attributes_usage_to_the_root_agent_id(
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

    usage_path = tmp_path / "usage.json"
    config = ScanConfig(
        mission="find a bug",
        target_specs=["example.com"],
        run_dir=tmp_path / "run",
        usage_path=usage_path,
    )
    ScanRunner(config, env={"ANTHROPIC_API_KEY": "sk-test"}).run()

    stats = load_usage(usage_path)
    # AgentCoordinator hands out ids as "agent-N" starting from 1 - the root
    # agent registered by ScanRunner.run() is always the first one.
    assert stats.by_agent["agent-1"]["requests"] > 0


def test_scan_runner_defaults_to_advisory_only_for_an_unreachable_target(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(scan_module, "docker_available", lambda: True)
    monkeypatch.setattr(scan_module, "RuntimeContainer", _FakeContainer)
    monkeypatch.setattr(
        scan_module,
        "probe_reachability",
        lambda *_a, **_k: {"example.com": (False, "connection refused")},
    )
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
    outcome = ScanRunner(config, env={"ANTHROPIC_API_KEY": "sk-test"}, event_log=event_log).run()

    assert outcome.status is RunStatus.COMPLETED  # never blocked by an advisory-only signal
    _cursor, events = event_log.snapshot()
    assert any(e.payload.get("event") == "target_unreachable_preflight" for e in events)


def test_scan_runner_hard_stops_on_an_unreachable_target_when_opted_in(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(scan_module, "docker_available", lambda: True)
    monkeypatch.setattr(scan_module, "RuntimeContainer", _FakeContainer)
    monkeypatch.setattr(
        scan_module,
        "probe_reachability",
        lambda *_a, **_k: {"example.com": (False, "connection refused")},
    )
    router = ModelRouter(
        providers={"fake": _ScriptedProvider(_respond)},
        routes={"reasoning": ("fake",), "review": ("fake",)},
        default_route=("fake",),
    )
    monkeypatch.setattr(scan_module, "build_router", lambda _settings: router)

    config = ScanConfig(
        mission="find a bug",
        target_specs=["example.com"],
        run_dir=tmp_path / "run",
        fail_on_unreachable_targets=True,
    )
    with pytest.raises(TargetUnreachableError, match="example.com"):
        ScanRunner(config, env={"ANTHROPIC_API_KEY": "sk-test"}).run()


def test_scan_runner_defaults_to_advisory_only_for_a_broken_login_preflight(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A COOKIE-source scheme with no login_url is a real, hermetic
    (no-network) LoginFailedError - see identity/login.py's own login()."""
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
        mission="find a bug",
        target_specs=["example.com"],
        run_dir=tmp_path / "run",
        identities={"alice": Identity("alice", "alice", Credential(CredentialKind.PASSWORD, "x"))},
        login_schemes={"broken": LoginScheme()},
        login_preflight_pairs=[("alice", "broken")],
    )
    outcome = ScanRunner(config, env={"ANTHROPIC_API_KEY": "sk-test"}, event_log=event_log).run()

    assert outcome.status is RunStatus.COMPLETED  # never blocked by an advisory-only signal
    _cursor, events = event_log.snapshot()
    failed = [e for e in events if e.payload.get("event") == "login_preflight_failed"]
    assert len(failed) == 1
    assert failed[0].payload["identity_id"] == "alice"
    assert failed[0].payload["scheme"] == "broken"


def test_scan_runner_hard_stops_on_a_broken_login_preflight_when_opted_in(
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
        mission="find a bug",
        target_specs=["example.com"],
        run_dir=tmp_path / "run",
        identities={"alice": Identity("alice", "alice", Credential(CredentialKind.PASSWORD, "x"))},
        login_schemes={"broken": LoginScheme()},
        login_preflight_pairs=[("alice", "broken")],
        fail_on_broken_login=True,
    )
    with pytest.raises(LoginFailedError, match="alice/broken"):
        ScanRunner(config, env={"ANTHROPIC_API_KEY": "sk-test"}).run()


def test_scan_runner_login_preflight_succeeds_for_a_header_scheme(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A HEADER-source scheme needs no network call at all (login.py's own
    login() short-circuits before ever touching the firer) - proves the
    success path, not just the failure path above."""
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
        mission="find a bug",
        target_specs=["example.com"],
        run_dir=tmp_path / "run",
        identities={
            "alice": Identity("alice", "alice", Credential(CredentialKind.API_KEY, "sk-abc"))
        },
        login_schemes={
            "api_key": LoginScheme(session_source=SessionSource.HEADER, session_field="X-Api-Key")
        },
        login_preflight_pairs=[("alice", "api_key")],
    )
    outcome = ScanRunner(config, env={"ANTHROPIC_API_KEY": "sk-test"}, event_log=event_log).run()

    assert outcome.status is RunStatus.COMPLETED
    _cursor, events = event_log.snapshot()
    assert not any(e.payload.get("event") == "login_preflight_failed" for e in events)


def test_scan_runner_login_preflight_reports_an_unknown_identity_or_scheme(
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
        mission="find a bug",
        target_specs=["example.com"],
        run_dir=tmp_path / "run",
        login_preflight_pairs=[("nobody", "nothing")],
    )
    ScanRunner(config, env={"ANTHROPIC_API_KEY": "sk-test"}, event_log=event_log).run()

    _cursor, events = event_log.snapshot()
    failed = [e for e in events if e.payload.get("event") == "login_preflight_failed"]
    assert len(failed) == 1
    assert "unknown identity" in str(failed[0].payload["reason"])


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


def test_max_duration_s_kills_a_run_and_reports_wall_clock_exceeded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A wall-clock kill goes through the exact same should_stop()/cancelled
    path as a manual stop - it must still be reported honestly as its own
    RunStatus, not folded into the ambiguous UNVERIFIED_STOP a plain cancel
    gets."""
    monkeypatch.setattr(scan_module, "docker_available", lambda: True)
    monkeypatch.setattr(scan_module, "RuntimeContainer", _FakeContainer)
    provider = _ScriptedProvider(_respond)
    router = ModelRouter(
        providers={"fake": provider}, routes={"reasoning": ("fake",)}, default_route=("fake",)
    )
    monkeypatch.setattr(scan_module, "build_router", lambda _settings: router)

    config = ScanConfig(
        mission="find a bug",
        target_specs=["example.com"],
        run_dir=tmp_path / "run",
        max_duration_s=0.0,  # already "exceeded" the instant the clock starts
    )
    outcome = ScanRunner(config, env={"ANTHROPIC_API_KEY": "sk-test"}).run()

    assert outcome.status is RunStatus.WALL_CLOCK_EXCEEDED


def test_max_duration_s_defaults_to_no_wall_clock_limit(
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
    assert config.max_duration_s is None
    outcome = ScanRunner(config, env={"ANTHROPIC_API_KEY": "sk-test"}).run()
    assert outcome.status is RunStatus.COMPLETED


def test_should_stop_does_not_trigger_before_max_duration_s_elapses(tmp_path: Path) -> None:
    config = ScanConfig(
        mission="m",
        target_specs=["example.com"],
        run_dir=tmp_path / "run",
        max_duration_s=3600.0,
    )
    runner = ScanRunner(config, env={"ANTHROPIC_API_KEY": "sk-test"})
    runner._start_time = time.monotonic()  # simulate run() having just started
    assert runner._should_stop() is False
    assert runner._wall_clock_exceeded is False


def test_should_stop_is_false_before_run_has_ever_started(tmp_path: Path) -> None:
    """_start_time is None until run() sets it - max_duration_s must never
    be checked against a run that hasn't actually begun yet."""
    config = ScanConfig(
        mission="m",
        target_specs=["example.com"],
        run_dir=tmp_path / "run",
        max_duration_s=0.0,
    )
    runner = ScanRunner(config, env={"ANTHROPIC_API_KEY": "sk-test"})
    assert runner._start_time is None
    assert runner._should_stop() is False


# --- live operator steering: closes a real dead-on-arrival wire (POST /steer
# already logged these, nothing ever read them back into a running agent) ---


def test_pending_steering_with_no_event_log_is_empty(tmp_path: Path) -> None:
    config = ScanConfig(mission="m", target_specs=["example.com"], run_dir=tmp_path / "run")
    runner = ScanRunner(config, env={"ANTHROPIC_API_KEY": "sk-test"})
    assert runner._pending_steering() == []


def test_pending_steering_returns_every_steering_message_in_order(tmp_path: Path) -> None:
    config = ScanConfig(mission="m", target_specs=["example.com"], run_dir=tmp_path / "run")
    event_log = EventLog()
    runner = ScanRunner(config, env={"ANTHROPIC_API_KEY": "sk-test"}, event_log=event_log)
    event_log.append("steering", {"text": "focus on the API endpoints"})
    event_log.append("status", {"event": "scan_started"})  # non-steering, must be ignored
    event_log.append("steering", {"text": "check the admin panel"})
    assert runner._pending_steering() == ["focus on the API endpoints", "check the admin panel"]


def test_pending_steering_is_non_consuming(tmp_path: Path) -> None:
    """Multiple concurrently-running agents (spawn_agents children) each
    call this independently - a consuming cursor would mean only whichever
    one reads first ever sees a given message."""
    config = ScanConfig(mission="m", target_specs=["example.com"], run_dir=tmp_path / "run")
    event_log = EventLog()
    runner = ScanRunner(config, env={"ANTHROPIC_API_KEY": "sk-test"}, event_log=event_log)
    event_log.append("steering", {"text": "focus on the API endpoints"})
    first_read = runner._pending_steering()
    second_read = runner._pending_steering()
    assert first_read == second_read == ["focus on the API endpoints"]


def test_scan_runner_wires_live_steering_into_the_agents_prompt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(scan_module, "docker_available", lambda: True)
    monkeypatch.setattr(scan_module, "RuntimeContainer", _FakeContainer)

    seen_prompts: list[str] = []

    class _RecordingProvider:
        name = "fake"

        def complete(self, request: object) -> CompletionResponse:
            seen_prompts.append(request.prompt)  # type: ignore[attr-defined]
            return CompletionResponse(
                text=_respond(len(seen_prompts) - 1, request.prompt),  # type: ignore[attr-defined]
                provider="fake",
                model="fake-model",
            )

    router = ModelRouter(
        providers={"fake": _RecordingProvider()},
        routes={"reasoning": ("fake",), "review": ("fake",)},
        default_route=("fake",),
    )
    monkeypatch.setattr(scan_module, "build_router", lambda _settings: router)

    event_log = EventLog()
    event_log.append("steering", {"text": "focus on the API endpoints"})
    config = ScanConfig(
        mission="find a bug", target_specs=["example.com"], run_dir=tmp_path / "run"
    )
    ScanRunner(config, env={"ANTHROPIC_API_KEY": "sk-test"}, event_log=event_log).run()

    mission_prompts = [p for p in seen_prompts if "MISSION:" in p]
    assert mission_prompts  # sanity: the agent actually ran real steps
    assert all("focus on the API endpoints" in p for p in mission_prompts)


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


def test_find_orphaned_children_returns_a_spawned_with_no_matching_finished(
    tmp_path: Path,
) -> None:
    journal = DurableJournal(tmp_path / "journal.jsonl")
    journal.record(
        "agent-2:spawned",
        {"name": "n", "task": "t", "parent_id": "agent-1", "depth": 1, "role": "full"},
    )
    orphans = scan_module._find_orphaned_children(journal)  # noqa: SLF001
    assert [child_id for child_id, _ in orphans] == ["agent-2"]


def test_find_orphaned_children_excludes_one_with_a_matching_finished(tmp_path: Path) -> None:
    journal = DurableJournal(tmp_path / "journal.jsonl")
    journal.record(
        "agent-2:spawned",
        {"name": "n", "task": "t", "parent_id": "agent-1", "depth": 1, "role": "full"},
    )
    journal.record("agent-2:finished", {"stop_reason": "finished", "summary": "done"})
    assert scan_module._find_orphaned_children(journal) == []  # noqa: SLF001


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


def test_resuming_an_already_finished_run_adopts_the_report_with_no_new_llm_work(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A run that already finished cleanly and wrote a verified report must
    be a pure no-op on resume: no fresh mission turn just to hear the model
    say "done" again, and no full re-run of the confidence/adversarial-review
    pass (a real, avoidable LLM call per already-reviewed finding) plus a
    report rewrite, all to reach the exact same conclusion a second time.
    """
    monkeypatch.setattr(scan_module, "docker_available", lambda: True)
    monkeypatch.setattr(scan_module, "RuntimeContainer", _FakeContainer)

    router1 = ModelRouter(
        providers={"fake": _ScriptedProvider(_respond)},
        routes={"reasoning": ("fake",), "review": ("fake",)},
        default_route=("fake",),
    )
    monkeypatch.setattr(scan_module, "build_router", lambda _settings: router1)

    run_dir = tmp_path / "run"
    config = ScanConfig(mission="find a bug", target_specs=["example.com"], run_dir=run_dir)
    outcome1 = ScanRunner(config, env={"ANTHROPIC_API_KEY": "sk-test"}).run()
    assert outcome1.status is RunStatus.COMPLETED
    original_markdown = outcome1.report_paths["markdown"].read_text()
    original_manifest = (run_dir / "report_manifest.json").read_text()

    def _fail_on_anything_but_the_preflight_healthcheck(_call_index: int, prompt: str) -> str:
        if "FINDING TO REVIEW" in prompt:
            raise AssertionError(
                "adversarial review must not re-run for an already-reviewed "
                "finding on a no-new-work resume"
            )
        if "MISSION:" in prompt:
            raise AssertionError(
                "the model must not be asked for a new mission turn on a "
                "resume of an already cleanly-finished run"
            )
        return "ok"  # only the preflight verify_router() health-check call

    router2 = ModelRouter(
        providers={"fake": _ScriptedProvider(_fail_on_anything_but_the_preflight_healthcheck)},
        routes={"reasoning": ("fake",), "review": ("fake",)},
        default_route=("fake",),
    )
    monkeypatch.setattr(scan_module, "build_router", lambda _settings: router2)

    # SAME config/run_dir -- ScanRunner auto-detects the existing, already-
    # finished journal + manifest and must adopt the standing report rather
    # than regenerate it.
    outcome2 = ScanRunner(config, env={"ANTHROPIC_API_KEY": "sk-test"}).run()

    assert outcome2.status is RunStatus.COMPLETED
    assert outcome2.report_paths["markdown"].read_text() == original_markdown
    assert (run_dir / "report_manifest.json").read_text() == original_manifest
    events = load_run_events(run_dir).snapshot()[1]
    assert any(
        e.category == "status" and e.payload.get("event") == "report_adopted" for e in events
    )


def test_resume_reseeds_the_spawn_counter_so_a_second_child_gets_a_fresh_agent_id(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Regression test for a bug this task's own per-child journaling wiring
    turned into an active corruption path: AgentCoordinator's child-id
    counter starts fresh at 0 on every process start, and AgentLoop.run()'s
    resume-replay loop reconstructs already-journaled steps straight from
    the journal without ever calling coordinator.spawn() again -- so if the
    root already completed one spawn (Child C, fully journaled under
    "agent-2") before crashing, and needs to dispatch a genuinely NEW second
    spawn after resuming, an under-seeded counter would mint "agent-2" a
    second time. Since child_loop.run() now passes agent_key=child_id, that
    collision would silently splice Child C's own already-journaled history
    into the unrelated second child's brand-new transcript.
    """
    monkeypatch.setattr(scan_module, "docker_available", lambda: True)
    monkeypatch.setattr(scan_module, "RuntimeContainer", _FakeContainer)

    def _crash_before_the_second_spawn(_call_index: int, prompt: str) -> str:
        if "FINDING TO REVIEW" in prompt:
            return '{"verdict": "confirmed", "proof_level": "L3", "reasoning": "grounded"}'
        if "MISSION:" not in prompt:
            return "ok"  # the preflight verify_router() health-check call
        if prompt.startswith("MISSION:\nCHILD-C-TASK"):
            # Child C runs to completion -- both of its own steps land in the
            # journal under "agent-2" before the crash below. Anchored on the
            # MISSION line itself (not a bare substring check) -- the root's
            # OWN history recap of its spawn_agent call echoes the child's
            # task text verbatim, so a bare "CHILD-C-TASK" in prompt check
            # would misfire on the root's own later turns too.
            if "HISTORY (most recent last):" not in prompt:
                return _record_finding_call_for("https://c.example.com/search")
            return _finish_call()
        # root's own turns: step 0 spawns Child C (fully completes, fully
        # journaled); step 1 crashes before ever attempting the second spawn.
        if "HISTORY (most recent last):" not in prompt:
            return _spawn_agent_call()
        return "CRASH"

    crashing_provider = _CrashingProvider(_crash_before_the_second_spawn)
    router1 = ModelRouter(
        providers={"fake": crashing_provider},
        routes={"reasoning": ("fake",), "review": ("fake",)},
        default_route=("fake",),
    )
    monkeypatch.setattr(scan_module, "build_router", lambda _settings: router1)

    run_dir = tmp_path / "run"
    config = ScanConfig(
        mission="find a bug, spawning two children", target_specs=["example.com"], run_dir=run_dir
    )
    with pytest.raises(RuntimeError, match="simulated crash"):
        ScanRunner(config, env={"ANTHROPIC_API_KEY": "sk-test"}).run()

    crashed_journal = DurableJournal(run_dir / "journal.jsonl")
    assert crashed_journal.has("root:0")
    # Child C's own record_finding step landed under "agent-2" -- its "finish"
    # turn never journals at all (AgentLoop.run() returns straight from the
    # "finish" branch without ever calling journal.run_once for it, mirroring
    # the root's own never-journaled "finish" step), so "agent-2:0" alone is
    # the complete set of pre-crash journal entries for this child.
    assert crashed_journal.has("agent-2:0")

    def _respond_after_resume(_call_index: int, prompt: str) -> str:
        if "FINDING TO REVIEW" in prompt:
            return '{"verdict": "confirmed", "proof_level": "L3", "reasoning": "grounded"}'
        if prompt.startswith("MISSION:\nCHILD-D-TASK"):
            if "HISTORY (most recent last):" not in prompt:
                return _record_finding_call_for("https://d.example.com/search")
            return _finish_call()
        # root's own turns. Resume already replays root:0 (the Child C spawn)
        # straight into history, so "HISTORY (most recent last):" is present
        # from root's very first LIVE turn onward here -- "Child D" appearing
        # in that history is what actually distinguishes "already spawned the
        # second child, now finish" from "haven't yet".
        if "Child D" in prompt:
            return _finish_call()
        return json.dumps(
            {
                "tool": "spawn_agent",
                "args": {"name": "Child D", "task": "CHILD-D-TASK: test host d.example.com"},
            }
        )

    resumed_provider = _ScriptedProvider(_respond_after_resume)
    router2 = ModelRouter(
        providers={"fake": resumed_provider},
        routes={"reasoning": ("fake",), "review": ("fake",)},
        default_route=("fake",),
    )
    monkeypatch.setattr(scan_module, "build_router", lambda _settings: router2)

    event_log = EventLog()
    # SAME config/run_dir -- ScanRunner auto-detects the existing journal +
    # manifest and resumes rather than starting fresh.
    outcome = ScanRunner(config, env={"ANTHROPIC_API_KEY": "sk-test"}, event_log=event_log).run()
    assert outcome.status is RunStatus.COMPLETED

    final_journal = DurableJournal(run_dir / "journal.jsonl")
    # The second child must get a genuinely new id -- never the already-used
    # "agent-2" a pre-fix, under-seeded counter would have reminted.
    assert final_journal.has("agent-3:0")

    _cursor, events = event_log.snapshot()
    child_d_finding = next(
        e
        for e in events
        if e.category == "log"
        and e.payload.get("event") == "tool_call"
        and e.payload.get("tool") == "record_finding"
        and e.payload.get("args", {}).get("target") == "https://d.example.com/search"
    )
    assert child_d_finding.payload["agent_id"] == "agent-3"  # not the reused "agent-2"
    # No unrelated history was spliced in: agent-3 never replayed anything --
    # a "resumed" event only fires when start_step > 0 (AgentLoop.run()'s own
    # resume-replay loop), which would only happen if agent-3 collided with
    # an id the journal already had entries for.
    assert not any(
        e.payload.get("agent_id") == "agent-3" and e.payload.get("event") == "resumed"
        for e in events
    )


def test_a_crashed_mid_child_scan_can_be_resumed_under_the_same_agent_id(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(scan_module, "docker_available", lambda: True)
    monkeypatch.setattr(scan_module, "RuntimeContainer", _FakeContainer)

    def _crash_mid_child(call_index: int, prompt: str) -> str:
        if "MISSION:" not in prompt:
            return "ok"  # the preflight verify_router() health-check call
        if prompt.startswith("MISSION:\nCHILD-C-TASK"):
            # The child's very first turn - simulate an unrecoverable process
            # kill while child_loop.run() is still in progress. Deliberately
            # a BaseException, NOT a plain Exception: agent/spawn.py's own
            # _spawn wraps its run_child(...) call in "except Exception as
            # exc" (comment: "a crashed child must still reach a terminal
            # status") specifically so an ordinary child failure never takes
            # the whole scan down - an ordinary RuntimeError here would be
            # caught right there and the scan would finish normally, proving
            # nothing about orphan detection. Only something outside
            # Exception's hierarchy models a real, uncatchable process death.
            raise BaseException("simulated crash mid-child")  # noqa: TRY002, BLE001
        if "HISTORY (most recent last):" not in prompt:
            return _spawn_agent_call()
        return "CRASH"  # unreachable: root never gets a second turn before the crash

    router1 = ModelRouter(
        providers={"fake": _ScriptedProvider(_crash_mid_child)},
        routes={"reasoning": ("fake",), "review": ("fake",)},
        default_route=("fake",),
    )
    monkeypatch.setattr(scan_module, "build_router", lambda _settings: router1)

    run_dir = tmp_path / "run"
    config = ScanConfig(
        mission="find a bug, spawning one child", target_specs=["c.example.com"], run_dir=run_dir
    )
    with pytest.raises(BaseException, match="simulated crash mid-child"):  # noqa: PT011
        ScanRunner(config, env={"ANTHROPIC_API_KEY": "sk-test"}).run()

    crashed_journal = DurableJournal(run_dir / "journal.jsonl")
    assert crashed_journal.has("agent-2:spawned")
    assert not crashed_journal.has("agent-2:finished")

    def _respond_after_resume(call_index: int, prompt: str) -> str:
        if "FINDING TO REVIEW" in prompt:
            return '{"verdict": "confirmed", "proof_level": "L3", "reasoning": "grounded"}'
        if prompt.startswith("MISSION:\nCHILD-C-TASK"):
            if "HISTORY (most recent last):" not in prompt:
                return _record_finding_call_for("https://c.example.com/search")
            return _finish_call()
        # The root's OWN turns after resume. "root:0" (the crashed spawn
        # step) was never journaled - the crash happened before that whole
        # tool dispatch (spawn + run the child to completion) ever
        # returned, and a step only gets journaled once its dispatch
        # returns - so the root's first LIVE turn here has NO history at
        # all, exactly like a fresh run's very first turn. It must
        # explicitly resume the orphan (a real agent would call
        # view_agent_graph first and see agent-2 as [orphaned]; this
        # scripted turn already "knows" to resume it). Its SECOND turn
        # (now WITH history, since the successful resume just journaled
        # "root:0") finishes.
        if "HISTORY (most recent last):" not in prompt:
            return json.dumps({"tool": "spawn_agent", "args": {"resume_agent_id": "agent-2"}})
        return _finish_call()

    resumed_provider = _ScriptedProvider(_respond_after_resume)
    router2 = ModelRouter(
        providers={"fake": resumed_provider},
        routes={"reasoning": ("fake",), "review": ("fake",)},
        default_route=("fake",),
    )
    monkeypatch.setattr(scan_module, "build_router", lambda _settings: router2)

    outcome = ScanRunner(config, env={"ANTHROPIC_API_KEY": "sk-test"}).run()
    assert outcome.status is RunStatus.COMPLETED

    final_journal = DurableJournal(run_dir / "journal.jsonl")
    # The SAME id as before the crash - never a fresh "agent-3".
    assert final_journal.has("agent-2:0")
    assert final_journal.has("agent-2:finished")


def test_resume_manifest_without_the_exclude_field_still_resumes(tmp_path: Path) -> None:
    """A manifest written before exclude_target_specs existed has no such key
    in its persisted JSON - resuming against it must not raise, and must
    treat the omission as "no exclusions were ever declared", not a mismatch."""
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    old_manifest = {"mission": "find a bug", "target_specs": ["example.com"], "egress_lock": False}
    scan_module._manifest_path(run_dir).write_text(json.dumps(old_manifest), encoding="utf-8")  # noqa: SLF001

    config = ScanConfig(mission="find a bug", target_specs=["example.com"], run_dir=run_dir)
    scan_module._load_or_write_manifest(config)  # noqa: SLF001 - must not raise


def test_resume_manifest_without_rules_of_engagement_still_resumes(tmp_path: Path) -> None:
    """Same backward-compatibility guarantee as the exclude_target_specs
    manifest field: a manifest written before rules_of_engagement existed
    has no such key - resuming must treat that as "" (never specified),
    not a mismatch."""
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    old_manifest = {"mission": "find a bug", "target_specs": ["example.com"], "egress_lock": False}
    scan_module._manifest_path(run_dir).write_text(json.dumps(old_manifest), encoding="utf-8")  # noqa: SLF001

    config = ScanConfig(mission="find a bug", target_specs=["example.com"], run_dir=run_dir)
    scan_module._load_or_write_manifest(config)  # noqa: SLF001 - must not raise


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
        # ScanRunner.run()'s own preflight (Phase 4) calls verify_router()
        # before the agent loop ever starts, which fires exactly this literal
        # completion against this same scripted provider - consuming
        # call_index 0 for every provider the router has (one, here) before
        # the loop's own first real decision. Matched by prompt content, not
        # position, so this stays correct regardless of how many preflight
        # calls precede the loop.
        if prompt == "reply with exactly: ok":
            return "ok"
        if "FINDING TO REVIEW" in prompt:
            return '{"verdict": "confirmed", "proof_level": "L1", "reasoning": "n/a"}'
        if call_index == 1:
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


def test_scan_runner_dispatches_a_configured_mcp_connection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A real bug this closes: MCPServerConfig/build_mcp_tool (Phase 15) were
    fully built and unit-tested but ScanConfig had no field for an operator
    to actually configure a connection, so no mcp_<name> tool was ever
    present in a live scan's registry - it existed only in its own test file.
    Stubs build_mcp_tool itself (protocol round-trip is already exhaustively
    covered by test_integrations_mcp_client.py) purely to prove the
    config -> tool-list wiring path this bug was in.
    """
    monkeypatch.setattr(scan_module, "docker_available", lambda: True)
    monkeypatch.setattr(scan_module, "RuntimeContainer", _FakeContainer)

    def _fake_build_mcp_tool(config: object) -> object:
        return FunctionTool(
            name=f"mcp_{config.name}",  # type: ignore[attr-defined]
            description="fake MCP connection tool",
            func=lambda _args: ToolResult(observation="mcp connection reachable", ok=True),
        )

    monkeypatch.setattr(scan_module, "build_mcp_tool", _fake_build_mcp_tool)

    def respond(call_index: int, prompt: str) -> str:
        if "FINDING TO REVIEW" in prompt:
            return '{"verdict": "confirmed", "proof_level": "L1", "reasoning": "n/a"}'
        if "MISSION:" not in prompt:
            return "ok"
        if "HISTORY (most recent last):" not in prompt:
            return json.dumps({"tool": "mcp_burp", "args": {"tool": "list_requests"}})
        return json.dumps({"tool": "finish", "args": {"summary": "used the mcp connection"}})

    router = ModelRouter(
        providers={"fake": _ScriptedProvider(respond)},
        routes={"reasoning": ("fake",), "review": ("fake",)},
        default_route=("fake",),
    )
    monkeypatch.setattr(scan_module, "build_router", lambda _settings: router)

    config = ScanConfig(
        mission="use the burp connection",
        target_specs=["example.com"],
        run_dir=tmp_path / "run",
        mcp_connections={
            "burp": MCPServerConfig(
                name="burp",
                transport="http",
                credential_env_var="BURP_MCP_TOKEN",
                allowed_tools={"list_requests": "read"},
                url="https://burp.local/mcp",
            )
        },
    )
    outcome = ScanRunner(config, env={"ANTHROPIC_API_KEY": "sk-test"}).run()

    assert outcome.status is RunStatus.COMPLETED
    assert outcome.result.summary == "used the mcp connection"
    transcript = outcome.result.transcript
    mcp_call = next(entry for entry in transcript if entry["tool"] == "mcp_burp")
    assert mcp_call["observation"] == "mcp connection reachable"
