"""Focused Phase 8 checks for signal-gated external adapter hardening."""

from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from reachagent.execution import AuditLog, ScopeGuard
from reachagent.graph.nodes import Endpoint, FindingStatus, Host, Parameter, SinkType
from reachagent.graph.store import ReachabilityGraph
from reachagent.oracles import OracleMechanism
from reachagent.oracles.base import OracleVerdict
from reachagent.recon.signal_dispatch import run_signal_tools
from reachagent.recon.signal_tuning import _validate_selection
from reachagent.recon.tools import (
    SignalGatedOutcome,
    SignalGatedToolRunner,
    SqlmapRunner,
    reconfirm_candidate,
)
from reachagent.recon.tools.dalfox import DalfoxRunner
from reachagent.recon.tools.nuclei import NucleiRunner
from reachagent.tools.candidate import Candidate, ResponseSignal

_TARGET = "target.test"


def _scope() -> ScopeGuard:
    return ScopeGuard.from_hosts([_TARGET])


def _graph_with_signal() -> ReachabilityGraph:
    graph = ReachabilityGraph()
    endpoint = graph.add_endpoint(Endpoint(method="GET", path="/search"))
    graph.add_parameter(
        endpoint,
        Parameter(name="q", location="query", inferred_sink_type=SinkType.HTML_REFLECTION),
    )
    graph.add_host(Host(address=_TARGET, technology="nginx"))
    return graph


def _candidate(endpoint: str = "https://target.test/search?q=1") -> Candidate:
    return Candidate(
        identity="fixture-tool",
        endpoint_node=endpoint,
        param_node="q",
        vuln_class="xss_reflected",
        suggested_oracle=OracleMechanism.EXECUTION_CONFIRMATION,
        payload_ref=None,
        signal=ResponseSignal(status_code=200, body_length=10, elapsed_seconds=0.1),
        notes=("claim token=do-not-leak",),
    )


@dataclass
class _FixtureRunner(SignalGatedToolRunner):
    name = "fixture-tool"
    binary = "fixture-tool"

    def has_signal(self, target: str) -> bool:
        return True

    def command(self, target: str, output_path: str) -> list[str]:
        return [self.binary, "--target", target, "--output", output_path]

    def parse(self, target: str, raw_output: str) -> tuple[Candidate, ...]:
        return (_candidate(),)


def test_claims_are_sanitized_scoped_and_bounded() -> None:
    runner = _FixtureRunner(graph=_graph_with_signal(), scope=_scope())
    result = runner.ingest("https://target.test/search?token=secret", "fixture")
    assert result.outcome is SignalGatedOutcome.EMITTED_CANDIDATES
    assert result.candidates[0].notes == ("claim token=<redacted>",)
    assert "%3Credacted%3E" not in result.candidates[0].endpoint_node

    class OutOfScopeRunner(_FixtureRunner):
        def parse(self, target: str, raw_output: str) -> tuple[Candidate, ...]:
            return (_candidate("https://evil.test/search?q=1"),)

    refused = OutOfScopeRunner(graph=_graph_with_signal(), scope=_scope()).ingest(
        _TARGET, "fixture"
    )
    assert refused.candidates == ()
    assert refused.metadata.dropped_candidates == 1
    assert refused.metadata.partial_output is True


def test_live_result_exposes_safe_execution_metadata_and_strips_query_from_audit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import shutil as _shutil
    import subprocess as _subprocess

    class Completed:
        returncode = 3
        stdout = '{"template-id":"xss-check","matched-at":"https://target.test/search?q=1"}'

    monkeypatch.setattr(_shutil, "which", lambda _binary: "/usr/bin/fixture-tool")
    monkeypatch.setattr(_subprocess, "run", lambda *_args, **_kwargs: Completed())
    audit = AuditLog()
    runner = NucleiRunner(graph=_graph_with_signal(), scope=_scope(), audit=audit)
    result = runner.run(
        "https://target.test/search?token=secret",
        "missing-output.jsonl",
        environ={"REACHAGENT_RECON_LIVE": "1"},
    )
    assert result.metadata.exit_code == 3
    assert result.metadata.command_policy == "argv:shell=false"
    assert result.metadata.output_chars > 0
    assert result.candidates
    assert "?token=secret" not in audit.entries[-1].target
    assert "output_chars=" in audit.entries[-1].outcome
    assert "partial_output=" in audit.entries[-1].outcome


def test_live_disabled_is_forced_off_by_dispatch(monkeypatch: pytest.MonkeyPatch) -> None:
    observed: list[dict[str, str] | None] = []

    def fake_run(
        self: object,
        target: str,
        output_path: str,
        *,
        environ: dict[str, str] | None = None,
    ) -> Any:
        observed.append(environ)
        return type(
            "Result",
            (),
            {
                "outcome": SignalGatedOutcome.SKIPPED_NOT_LIVE,
                "candidates": (),
                "metadata": type("Meta", (), {"as_dict": lambda _self: {}})(),
            },
        )()

    monkeypatch.setattr(SqlmapRunner, "run", fake_run)
    events: list[tuple[tuple[object, ...], dict[str, object]]] = []
    result = run_signal_tools(
        tool_names=("sqlmap",),
        graph=_graph_with_signal(),
        scope=_scope(),
        audit=AuditLog(),
        target=_TARGET,
        emit=lambda *args, **kwargs: events.append((args, kwargs)),
        live_recon=False,
    )
    assert len(result) == 1
    assert observed == [{}]
    assert events and events[0][1]["claims_are_unverified"] is True


def test_dispatch_hands_every_claim_to_injected_reconfirmation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate = _candidate()

    def fake_run(
        self: object,
        target: str,
        output_path: str,
        *,
        environ: dict[str, str] | None = None,
    ) -> object:
        return type(
            "Result",
            (),
            {
                "outcome": SignalGatedOutcome.EMITTED_CANDIDATES,
                "candidates": (candidate, candidate),
                "metadata": type("Meta", (), {"as_dict": lambda _self: {}})(),
            },
        )()

    monkeypatch.setattr(SqlmapRunner, "run", fake_run)
    seen: list[Candidate] = []
    run_signal_tools(
        tool_names=("sqlmap",),
        graph=_graph_with_signal(),
        scope=_scope(),
        audit=AuditLog(),
        target=_TARGET,
        emit=lambda *_args, **_kwargs: None,
        live_recon=False,
        reconfirm=seen.append,
    )
    assert seen == [candidate, candidate]


def test_reconfirmation_rejects_forged_verdict_type_and_mismatched_mechanism() -> None:
    graph = _graph_with_signal()
    candidate = _candidate()
    writes: list[object] = []

    class FakeViolation:
        is_violation = True

    assert (
        reconfirm_candidate(
            candidate,
            object(),
            run_oracle=lambda *_args: FakeViolation(),
            write_finding=lambda *args: writes.append(args),
            graph=graph,
            finding_factory=lambda *_args: object(),
        )
        is None
    )
    assert writes == []

    mismatched = OracleVerdict(
        mechanism=OracleMechanism.DIFFERENTIAL,
        status=FindingStatus.CONFIRMED_VIOLATION,
        evidence_ref="phase8/mismatch",
    )
    assert (
        reconfirm_candidate(
            candidate,
            object(),
            run_oracle=lambda *_args: mismatched,
            write_finding=lambda *args: writes.append(args),
            graph=graph,
            finding_factory=lambda *_args: object(),
        )
        is None
    )
    assert writes == []


def test_signal_tool_selection_is_strictly_allowlisted() -> None:
    assert _validate_selection({"selected_tools": ["sqlmap"], "rationale": "sink"}) is not None
    assert _validate_selection({"selected_tools": [None, "sqlmap"]}) is None
    assert _validate_selection({"selected_tools": ["sqlmap"], "status": "confirmed"}) is None
    assert _validate_selection({"selected_tools": ["sqlmap"], "rationale": 42}) is None


def test_all_six_adapters_have_no_validator_import_and_emit_no_findings() -> None:
    import reachagent.recon.tools.commix as commix
    import reachagent.recon.tools.dalfox as dalfox
    import reachagent.recon.tools.jwt_tool as jwt_tool
    import reachagent.recon.tools.nikto as nikto
    import reachagent.recon.tools.nuclei as nuclei
    import reachagent.recon.tools.sqlmap as sqlmap

    modules = (commix, dalfox, jwt_tool, nikto, nuclei, sqlmap)
    for module in modules:
        assert module.__file__ is not None
        tree = ast.parse(Path(module.__file__).read_text(encoding="utf-8"))
        imports = [
            ast.unparse(node)
            for node in ast.walk(tree)
            if isinstance(node, (ast.Import, ast.ImportFrom))
        ]
        assert not any("validator" in text or "write_finding" in text for text in imports)

    graph = _graph_with_signal()
    result = DalfoxRunner(graph=graph, scope=_scope()).ingest(
        _TARGET, '{"url":"https://target.test/search?q=1","payload":"<svg>"}'
    )
    assert result.candidates and graph.findings() == []


def test_timeout_is_audited_as_an_error(monkeypatch: pytest.MonkeyPatch) -> None:
    import shutil as _shutil
    import subprocess as _subprocess

    monkeypatch.setattr(_shutil, "which", lambda _binary: "/usr/bin/fixture-tool")

    def timeout(*_args: object, **_kwargs: object) -> Any:
        raise _subprocess.TimeoutExpired("fixture-tool", 300)

    monkeypatch.setattr(_subprocess, "run", timeout)
    audit = AuditLog()
    result = NucleiRunner(graph=_graph_with_signal(), scope=_scope(), audit=audit).run(
        _TARGET, "out", environ={"REACHAGENT_RECON_LIVE": "1"}
    )
    assert result.outcome is SignalGatedOutcome.ERRORED
    assert audit.entries[-1].outcome.startswith("errored")
