"""Unit tests for scan/entrypoint.py::_maybe_escalate_wordlist (v3 V2 follow-up).

Mirrors tests/scan/test_nmap_depth_escalation_wiring.py's own shape: tests
the glue function directly (a fake runner, no real subprocess/graph
plumbing) — the escalation DECISION itself is already covered end to end by
tests/recon/test_wordlist_escalation.py; this file covers only the new
wiring: env save/restore around the follow-up pass, and fail-open on any
error.
"""

from __future__ import annotations

import os

import pytest

from reachagent.graph.nodes import Host
from reachagent.graph.store import ReachabilityGraph
from reachagent.scan.entrypoint import _maybe_escalate_wordlist


def _graph_with_host() -> ReachabilityGraph:
    g = ReachabilityGraph()
    g.add_host(
        Host(address="target.test", hostname="target.test", source="nmap", technology="wordpress")
    )
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
        return {"size": "large", "tech": "wordpress", "rationale": "wp detected"}


def test_off_by_default_never_calls_the_runner_again(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("REACHAGENT_WORDLIST_DEPTH_TUNING", raising=False)
    runner = _FakeRunner()
    result = _maybe_escalate_wordlist(
        runner, "target.test", _graph_with_host(), operator_prompt=None, live_recon=True
    )
    assert result == ()
    assert runner.calls == []


def test_escalation_reruns_the_runner_with_the_chosen_env_and_restores_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("REACHAGENT_WORDLIST_DEPTH_TUNING", "1")
    monkeypatch.delenv("REACHAGENT_WORDLIST_SIZE", raising=False)
    monkeypatch.delenv("REACHAGENT_WORDLIST_TECH", raising=False)
    monkeypatch.setattr(
        "reachagent.recon.wordlist_escalation.OpenAIWordlistEscalationClient",
        lambda: _EscalatingTuner(),
    )
    runner = _FakeRunner(nodes=("endpoint:target.test/wp-admin",))

    result = _maybe_escalate_wordlist(
        runner, "target.test", _graph_with_host(), operator_prompt=None, live_recon=True
    )

    assert result == ("endpoint:target.test/wp-admin",)
    assert len(runner.calls) == 1
    assert runner.calls[0]["environ"] == {"REACHAGENT_RECON_LIVE": "1"}
    # The escalation env vars must be restored to their pre-call state (unset)
    # once the follow-up pass completes — a global env mutation must not leak
    # into whatever recon step runs next.
    assert "REACHAGENT_WORDLIST_SIZE" not in os.environ
    assert "REACHAGENT_WORDLIST_TECH" not in os.environ


def test_a_failed_follow_up_pass_still_restores_env_and_returns_empty(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("REACHAGENT_WORDLIST_DEPTH_TUNING", "1")
    monkeypatch.delenv("REACHAGENT_WORDLIST_SIZE", raising=False)
    monkeypatch.setattr(
        "reachagent.recon.wordlist_escalation.OpenAIWordlistEscalationClient",
        lambda: _EscalatingTuner(),
    )
    runner = _FakeRunner(raises=True)

    result = _maybe_escalate_wordlist(
        runner, "target.test", _graph_with_host(), operator_prompt=None, live_recon=True
    )

    assert result == ()
    assert "REACHAGENT_WORDLIST_SIZE" not in os.environ


def test_operator_env_floor_is_restored_not_wiped(monkeypatch: pytest.MonkeyPatch) -> None:
    """If the operator's own manual selection already set the env var, that
    prior value must survive the escalation's temporary override — restore
    means "back to what it was," not "unset"."""
    monkeypatch.setenv("REACHAGENT_WORDLIST_DEPTH_TUNING", "1")
    monkeypatch.setenv("REACHAGENT_WORDLIST_SIZE", "small")  # operator's own floor
    monkeypatch.delenv("REACHAGENT_WORDLIST_TECH", raising=False)
    monkeypatch.setattr(
        "reachagent.recon.wordlist_escalation.OpenAIWordlistEscalationClient",
        lambda: _EscalatingTuner(),
    )
    runner = _FakeRunner(nodes=("endpoint:target.test/wp-admin",))

    _maybe_escalate_wordlist(
        runner, "target.test", _graph_with_host(), operator_prompt=None, live_recon=True
    )

    assert os.environ.get("REACHAGENT_WORDLIST_SIZE") == "small"
    assert "REACHAGENT_WORDLIST_TECH" not in os.environ
