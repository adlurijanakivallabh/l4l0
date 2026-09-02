"""Unit tests for scan/entrypoint.py::_maybe_escalate_nmap_depth (v3 V2).

Tests the glue function directly (a fake runner, no real subprocess/graph
plumbing) rather than driving all of scan_target's live-recon path — the
depth-escalation DECISION itself is already covered end to end by
tests/recon/test_depth_escalation.py; this file covers only the new wiring:
env save/restore around the follow-up pass, and fail-open on any error.
"""

from __future__ import annotations

import os

import pytest

from reachagent.graph.nodes import Host
from reachagent.graph.store import ReachabilityGraph
from reachagent.scan.entrypoint import _maybe_escalate_nmap_depth


def _graph_with_host() -> ReachabilityGraph:
    g = ReachabilityGraph()
    g.add_host(Host(address="target.test", hostname="target.test", source="nmap", technology="nginx"))
    return g


class _FakeRunner:
    def __init__(self, nodes: tuple[str, ...] = (), *, raises: bool = False) -> None:
        self.calls: list[dict[str, object]] = []
        self._nodes = nodes
        self._raises = raises

    def run(self, target: str, *, environ: dict[str, str] | None = None):  # noqa: ANN001
        self.calls.append({"target": target, "environ": environ})
        if self._raises:
            raise RuntimeError("spawn failed")

        class _Result:
            nodes = self._nodes

        return _Result()


class _EscalatingTuner:
    def propose(self, surface_summary: str, operator_prompt: str) -> dict[str, object]:
        return {"widen_ports": True, "script_category": "vuln", "rationale": "odd port"}


def test_off_by_default_never_calls_the_runner_again(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("REACHAGENT_RECON_DEPTH_TUNING", raising=False)
    runner = _FakeRunner()
    result = _maybe_escalate_nmap_depth(
        runner, "target.test", _graph_with_host(), operator_prompt=None, live_recon=True
    )
    assert result == ()
    assert runner.calls == []


def test_escalation_reruns_the_runner_with_the_chosen_env_and_restores_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("REACHAGENT_RECON_DEPTH_TUNING", "1")
    monkeypatch.delenv("REACHAGENT_NMAP_WIDEN_PORTS", raising=False)
    monkeypatch.delenv("REACHAGENT_NMAP_SCRIPT_CATEGORY", raising=False)
    monkeypatch.setattr(
        "reachagent.recon.depth_escalation.OpenAIDepthEscalationClient",
        lambda: _EscalatingTuner(),
    )
    runner = _FakeRunner(nodes=("host:target.test",))

    result = _maybe_escalate_nmap_depth(
        runner, "target.test", _graph_with_host(), operator_prompt=None, live_recon=True
    )

    assert result == ("host:target.test",)
    assert len(runner.calls) == 1
    assert runner.calls[0]["environ"] == {"REACHAGENT_RECON_LIVE": "1"}
    # The escalation env vars must be restored to their pre-call state (unset)
    # once the follow-up pass completes — a global env mutation must not leak
    # into whatever recon step runs next.
    assert "REACHAGENT_NMAP_WIDEN_PORTS" not in os.environ
    assert "REACHAGENT_NMAP_SCRIPT_CATEGORY" not in os.environ


def test_a_failed_follow_up_pass_still_restores_env_and_returns_empty(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("REACHAGENT_RECON_DEPTH_TUNING", "1")
    monkeypatch.delenv("REACHAGENT_NMAP_WIDEN_PORTS", raising=False)
    monkeypatch.setattr(
        "reachagent.recon.depth_escalation.OpenAIDepthEscalationClient",
        lambda: _EscalatingTuner(),
    )
    runner = _FakeRunner(raises=True)

    result = _maybe_escalate_nmap_depth(
        runner, "target.test", _graph_with_host(), operator_prompt=None, live_recon=True
    )

    assert result == ()
    assert "REACHAGENT_NMAP_WIDEN_PORTS" not in os.environ


def test_operator_env_floor_is_restored_not_wiped(monkeypatch: pytest.MonkeyPatch) -> None:
    """If the operator's own manual selection already set the env var, that
    prior value must survive the escalation's temporary override — restore
    means "back to what it was," not "unset"."""
    monkeypatch.setenv("REACHAGENT_RECON_DEPTH_TUNING", "1")
    monkeypatch.setenv("REACHAGENT_NMAP_WIDEN_PORTS", "1")  # operator's own floor
    monkeypatch.delenv("REACHAGENT_NMAP_SCRIPT_CATEGORY", raising=False)
    monkeypatch.setattr(
        "reachagent.recon.depth_escalation.OpenAIDepthEscalationClient",
        lambda: _EscalatingTuner(),
    )
    runner = _FakeRunner(nodes=("host:target.test",))

    _maybe_escalate_nmap_depth(
        runner, "target.test", _graph_with_host(), operator_prompt=None, live_recon=True
    )

    assert os.environ.get("REACHAGENT_NMAP_WIDEN_PORTS") == "1"
    assert "REACHAGENT_NMAP_SCRIPT_CATEGORY" not in os.environ
