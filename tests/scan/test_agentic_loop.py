"""Agentic-loop reassessment layer - hermetic tests (no network).

Covers: decision validation, phase summaries, skip semantics, bounded
reassessments, and that a failing LLM never stalls the scan. No flag gating
to cover (v4 R3 removed it) — a configured client is used unconditionally.
"""

from __future__ import annotations

from reachagent.graph.nodes import Endpoint, Host, Parameter, SinkType
from reachagent.graph.store import ReachabilityGraph
from reachagent.scan.agentic_loop import (
    MAX_REASSESSMENTS,
    REVISITABLE_PHASES,
    build_phase_summary,
    reassess_after_phase,
    validate_decision,
)

_TARGET = "target.test"


def _graph() -> ReachabilityGraph:
    g = ReachabilityGraph()
    g.add_host(Host(address=_TARGET, hostname=_TARGET, source="test", technology="nginx"))
    ep_login = g.add_endpoint(Endpoint(method="POST", path="/login"))
    pn = g.add_parameter(ep_login, Parameter(name="username", location="body"))
    g.set_parameter_sink_type(pn, SinkType.SQL)
    return g


class FakeAdvisor:
    def __init__(self, action: str, rationale: str = "r", hint: str = "") -> None:
        self._action = action
        self._rationale = rationale
        self._hint = hint

    def advise(
        self,
        completed_phase: str,
        phase_summary: str,
        remaining_phases: tuple[str, ...],
        operator_prompt: str,
    ) -> dict[str, object]:
        return {
            "action": self._action,
            "rationale": self._rationale,
            "hint": self._hint,
        }


class TestValidateDecision:
    def test_valid_actions(self) -> None:
        for action in ("continue", "skip", "revise"):
            d = validate_decision({"action": action})
            assert d is not None and d.action == action

    def test_case_normalized(self) -> None:
        d = validate_decision({"action": "SKIP"})
        assert d is not None and d.action == "skip"

    def test_unknown_action_refused(self) -> None:
        assert validate_decision({"action": "explode"}) is None

    def test_missing_action_refused(self) -> None:
        assert validate_decision({}) is None

    def test_hint_and_rationale_clamped(self) -> None:
        d = validate_decision({"action": "revise", "rationale": "r" * 999, "hint": "h" * 999})
        assert d is not None
        assert len(d.rationale) <= 300
        assert len(d.hint) <= 200


class TestPhaseSummaries:
    def test_recon_summary_counts_graph_facts(self) -> None:
        summary = build_phase_summary(_graph(), "recon")
        assert "hosts=1" in summary
        assert "endpoints=1" in summary
        assert "nginx" in summary

    def test_endpoints_summary_shows_sinks(self) -> None:
        summary = build_phase_summary(_graph(), "endpoints")
        assert "parameters-with-sinks=1" in summary
        assert "sql" in summary

    def test_payloads_summary_shows_findings(self) -> None:
        summary = build_phase_summary(_graph(), "payloads")
        assert "confirmed-findings=0" in summary


class TestReassessAfterPhase:
    def test_engaged_by_default_no_flag_needed(self) -> None:
        """v4 R3: no REACHAGENT_AGENTIC_LOOP gate — a configured client is used
        unconditionally, not only when an env flag also happens to be set."""
        d = reassess_after_phase(
            _graph(),
            "endpoints",
            ("payloads", "verification"),
            client=FakeAdvisor("skip", "no verification preconditions"),
        )
        assert d is not None and d.action == "skip"

    def test_non_revisitable_phase_refused(self) -> None:
        # "plan" is fixed — never reassessed.
        assert (
            reassess_after_phase(_graph(), "plan", ("recon",), client=FakeAdvisor("skip")) is None
        )

    def test_no_remaining_phases_returns_none(self) -> None:
        assert (
            reassess_after_phase(_graph(), "payloads", (), client=FakeAdvisor("continue")) is None
        )

    def test_failing_advisor_returns_none(self) -> None:
        class Broken:
            def advise(self, *a: object) -> dict[str, object]:
                raise RuntimeError("LLM down")

        d = reassess_after_phase(
            _graph(),
            "recon",
            ("endpoints",),
            client=Broken(),  # type: ignore[arg-type]
        )
        assert d is None  # scan continues as planned, never stalls


class TestBounded:
    def test_revisitable_phases_are_fixed(self) -> None:
        """Only these phases may be reassessed; plan/report are deterministic."""
        assert REVISITABLE_PHASES == ("recon", "endpoints", "payloads", "verification")

    def test_max_reassessments_is_bounded(self) -> None:
        assert MAX_REASSESSMENTS == 8  # a failing LLM cannot stall the scan
