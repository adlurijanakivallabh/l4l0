"""Phase 4 control-loop gates: bounded state, resume, cancellation, and authority."""

from __future__ import annotations

import ast
import time
from pathlib import Path

import pytest

from reachagent.graph.nodes import Endpoint, Host, Parameter, SinkType
from reachagent.graph.store import ReachabilityGraph
from reachagent.identity.store import Credential, IdentityStore
from reachagent.scan.agentic_loop import (
    AdaptiveControlLoop,
    AdaptiveControlState,
    IdleTimeout,
    LoopDetected,
    PhaseDecision,
    ScanCancelled,
    build_phase_snapshot,
    reassess_after_phase,
)


def _graph() -> ReachabilityGraph:
    graph = ReachabilityGraph()
    graph.add_host(Host(address="target.test", hostname="target.test", technology="nginx"))
    endpoint = graph.add_endpoint(Endpoint(method="GET", path="/items"))
    parameter = graph.add_parameter(endpoint, Parameter(name="id", location="query"))
    graph.set_parameter_sink_type(parameter, SinkType.SQL)
    return graph


class _Advisor:
    def __init__(self, response: dict[str, object]) -> None:
        self.response = response
        self.calls = 0
        self.last_summary = ""
        self.last_operator_prompt = ""

    def advise(
        self,
        completed_phase: str,
        phase_summary: str,
        remaining_phases: tuple[str, ...],
        operator_prompt: str,
    ) -> dict[str, object]:
        self.calls += 1
        self.last_summary = phase_summary
        self.last_operator_prompt = operator_prompt
        return self.response


def test_snapshot_is_bounded_and_redacts_identity_material() -> None:
    identities = IdentityStore()
    identities.add(Credential("owner", "alice", "password-value", "user"))
    identities.open_session("owner", "bearer-value", cookies={"sid": "cookie-value"})
    snapshot = build_phase_snapshot(
        _graph(),
        "endpoints",
        identities=identities,
        failed_payloads=({"payload_ref": "sqli/test", "error": "transport timeout"},),
    )
    encoded = snapshot.prompt_text()
    assert "bearer-value" not in encoded
    assert "cookie-value" not in encoded
    assert "password-value" not in encoded
    assert snapshot.auth_state["owner"]["has_token"] is True
    assert snapshot.auth_state["owner"]["cookie_names"] == ["sid"]
    assert snapshot.digest and len(snapshot.digest) == 24
    assert snapshot.deltas == {}


def test_control_decision_changes_next_action_and_resumes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("REACHAGENT_AGENTIC_LOOP", "1")
    path = tmp_path / "control.json"
    advisor = _Advisor(
        {
            "action": "skip",
            "rationale": "no verification signal",
            "hint": "",
            "target_phase": "verification",
        }
    )
    state = AdaptiveControlState(checkpoint_path=str(path))
    state.mark_phase("recon")
    loop = AdaptiveControlLoop(state, advisor=advisor)
    _snapshot, decision = loop.after_phase(_graph(), "endpoints")
    assert decision is not None and decision.action == "skip"
    assert "verification" in state.skipped
    assert state.remaining == ("payloads", "report")
    restored = AdaptiveControlState.load(path)
    assert restored.skipped == ["verification"]
    assert restored.revision == state.revision
    assert "parameters" in advisor.last_summary


class _FakeSteeringControl:
    """Mirrors gui/app.py's _ScanControl steering-hint surface, duck-typed."""

    def __init__(self, hints: list[str]) -> None:
        self._hints = hints

    def is_set(self) -> bool:
        return False

    def pop_steering_hints(self) -> list[str]:
        hints, self._hints = self._hints, []
        return hints


def test_mid_scan_steering_hint_reaches_the_next_advisor_call(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("REACHAGENT_AGENTIC_LOOP", "1")
    advisor = _Advisor({"action": "continue", "rationale": "", "hint": "", "target_phase": None})
    state = AdaptiveControlState(checkpoint_path=str(tmp_path / "control.json"))
    control_token = _FakeSteeringControl(["focus on the admin login flow"])
    loop = AdaptiveControlLoop(state, advisor=advisor, cancel=control_token)
    loop.after_phase(_graph(), "recon")
    assert "Operator note: focus on the admin login flow" in advisor.last_operator_prompt
    # Drained exactly once -- a second decision point must not replay it.
    loop.after_phase(_graph(), "endpoints")
    assert "Operator note" not in advisor.last_operator_prompt


def test_no_pending_hints_leaves_operator_prompt_unchanged(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("REACHAGENT_AGENTIC_LOOP", "1")
    advisor = _Advisor({"action": "continue", "rationale": "", "hint": "", "target_phase": None})
    state = AdaptiveControlState(checkpoint_path=str(tmp_path / "control.json"))
    loop = AdaptiveControlLoop(
        state,
        advisor=advisor,
        operator_prompt="read-only API scan",
        cancel=_FakeSteeringControl([]),
    )
    loop.after_phase(_graph(), "recon")
    assert advisor.last_operator_prompt == "read-only API scan"


def test_revisit_is_bounded_and_repeated_decision_is_rejected() -> None:
    state = AdaptiveControlState(max_revisits=1)
    decision = PhaseDecision("revisit", "recheck", "surface", "recon")
    state.mark_phase("recon")
    state.apply("recon", decision)
    with pytest.raises(LoopDetected):
        state.apply("recon", decision)


def test_cancellation_and_idle_timeout_fail_closed() -> None:
    state = AdaptiveControlState(idle_timeout=0.001)
    with pytest.raises(ScanCancelled):
        state.check(lambda: True)
    state.cancelled = False
    time.sleep(0.01)
    with pytest.raises(IdleTimeout):
        state.check()


def test_malicious_model_fields_cannot_enter_control_decision(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("REACHAGENT_AGENTIC_LOOP", "1")
    advisor = _Advisor(
        {
            "action": "continue",
            "rationale": "ok",
            "hint": "",
            "finding": {"status": "confirmed_violation"},
        }
    )
    assert reassess_after_phase(_graph(), "recon", ("endpoints",), client=advisor) is None


def test_control_module_has_no_oracle_or_finding_mutation_import() -> None:
    source = Path("src/reachagent/scan/agentic_loop.py").read_text(encoding="utf-8")
    assert "from reachagent.tools import validator" not in source
    assert "run_oracle" not in source
    assert "write_finding" not in source
    tree = ast.parse(source)
    called = {
        node.func.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
    }
    assert not called.intersection({"add_finding", "set_can_call", "run_oracle", "write_finding"})
