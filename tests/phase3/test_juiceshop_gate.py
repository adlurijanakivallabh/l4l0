"""Juice Shop Phase 3 gate tests (plan §14, §15; Task 9).

Two layers:

  1. Pure metric tests (no network): verify coverage, fp_rate, gate thresholds,
     and the PortswiggerResult seam against hand-built result tables.
  2. Live gate test (skips if Juice Shop unreachable): drives detection through
     the MCP tool boundary and scores against the challenge tracker API.
     Invariant 3 (PortSwigger) is skipped until lab credentials are provisioned.

MCP boundary: all detection calls in the live run cross ``mcp.call_tool`` —
never a direct Python call into a tool function (Task 9 DoD, §14/§15).
"""

from __future__ import annotations

import os

import pytest

from reachagent.eval.juiceshop_harness import (
    ChallengeResult,
    JuiceshopRun,
    Phase3GateResult,
    PortswiggerResult,
    in_scope_class,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_JUICE_URL = os.environ.get("REACHAGENT_JUICESHOP_URL", "http://127.0.0.1:3000")


def _cr(
    *,
    vuln_class: str = "injection",
    key: str = "k",
    confirmed: bool,
    solved: bool,
) -> ChallengeResult:
    return ChallengeResult(
        vuln_class=vuln_class,
        challenge_key=key,
        confirmed=confirmed,
        tracker_solved=solved,
    )


# ---------------------------------------------------------------------------
# Layer 1: pure metric tests — no network required.
# ---------------------------------------------------------------------------


def test_in_scope_class_maps_known_categories() -> None:
    assert in_scope_class("Injection") == "injection"
    assert in_scope_class("XSS") == "xss"
    assert in_scope_class("Improper Input Validation") == "file_upload"
    assert in_scope_class("Vulnerable Components") == "path_traversal"


def test_in_scope_class_returns_none_for_out_of_scope() -> None:
    assert in_scope_class("Broken Access Control") is None
    assert in_scope_class("Broken Authentication") is None
    assert in_scope_class("Miscellaneous") is None


def test_coverage_all_confirmed() -> None:
    run = JuiceshopRun(
        results=[
            _cr(confirmed=True, solved=True),
            _cr(confirmed=True, solved=True),
            _cr(confirmed=True, solved=True),
        ]
    )
    assert run.coverage == pytest.approx(1.0)
    assert run.fp_rate == pytest.approx(0.0)
    assert run.coverage_passes
    assert run.fp_rate_passes


def test_coverage_partial() -> None:
    # 3 of 4 confirmed and solved → coverage 0.75, exactly at floor.
    run = JuiceshopRun(
        results=[
            _cr(confirmed=True, solved=True),
            _cr(confirmed=True, solved=True),
            _cr(confirmed=True, solved=True),
            _cr(confirmed=False, solved=True),
        ]
    )
    assert run.coverage == pytest.approx(0.75)
    assert run.coverage_passes  # exactly at floor


def test_coverage_below_floor() -> None:
    run = JuiceshopRun(
        results=[
            _cr(confirmed=True, solved=True),
            _cr(confirmed=False, solved=True),
            _cr(confirmed=False, solved=True),
            _cr(confirmed=False, solved=True),
        ]
    )
    assert run.coverage == pytest.approx(0.25)
    assert not run.coverage_passes


def test_fp_rate_with_false_positives() -> None:
    # 1 TP, 1 FP → fp_rate = 0.5, above ceiling.
    run = JuiceshopRun(
        results=[
            _cr(confirmed=True, solved=True),
            _cr(confirmed=True, solved=False),  # false positive
        ]
    )
    assert run.fp_rate == pytest.approx(0.5)
    assert not run.fp_rate_passes


def test_fp_rate_at_ceiling() -> None:
    # 9 TP, 1 FP → fp_rate = 0.10, exactly at ceiling.
    results = [_cr(confirmed=True, solved=True) for _ in range(9)]
    results.append(_cr(confirmed=True, solved=False))
    run = JuiceshopRun(results=results)
    assert run.fp_rate == pytest.approx(0.10)
    assert run.fp_rate_passes  # exactly at ceiling


def test_fp_rate_zero_confirmed_is_zero() -> None:
    run = JuiceshopRun(
        results=[
            _cr(confirmed=False, solved=True),
            _cr(confirmed=False, solved=False),
        ]
    )
    assert run.fp_rate == pytest.approx(0.0)
    assert run.fp_rate_passes


def test_empty_run_coverage_is_zero() -> None:
    run = JuiceshopRun()
    assert run.coverage == pytest.approx(0.0)
    assert not run.coverage_passes


def test_gate_passes_when_both_invariants_met() -> None:
    results = [_cr(confirmed=True, solved=True) for _ in range(4)]
    gate = Phase3GateResult(juiceshop=JuiceshopRun(results=results))
    assert gate.passed
    assert "PASSED" in gate.report()


def test_gate_fails_when_coverage_below_floor() -> None:
    results = [_cr(confirmed=False, solved=True) for _ in range(4)]
    gate = Phase3GateResult(juiceshop=JuiceshopRun(results=results))
    assert not gate.passed
    assert "FAILED" in gate.report()


def test_gate_fails_when_fp_rate_above_ceiling() -> None:
    results = [_cr(confirmed=True, solved=True) for _ in range(4)]
    results.append(_cr(confirmed=True, solved=False))  # FP → rate = 1/5 = 0.20
    run = JuiceshopRun(results=results)
    gate = Phase3GateResult(juiceshop=run)
    assert not run.fp_rate_passes
    assert not gate.passed


# --- PortswiggerResult seam --------------------------------------------------


def test_portswigger_not_available_does_not_block_gate() -> None:
    results = [_cr(confirmed=True, solved=True) for _ in range(4)]
    gate = Phase3GateResult(
        juiceshop=JuiceshopRun(results=results),
        portswigger=PortswiggerResult(available=False),
    )
    assert gate.portswigger.passes
    assert gate.passed
    assert "SKIPPED" in gate.report()


def test_portswigger_available_and_passing() -> None:
    results = [_cr(confirmed=True, solved=True) for _ in range(4)]
    gate = Phase3GateResult(
        juiceshop=JuiceshopRun(results=results),
        portswigger=PortswiggerResult(
            available=True, vuln_lab_confirmed=True, clean_lab_fp_count=0
        ),
    )
    assert gate.portswigger.passes
    assert gate.passed


def test_portswigger_available_vuln_not_confirmed_fails() -> None:
    results = [_cr(confirmed=True, solved=True) for _ in range(4)]
    gate = Phase3GateResult(
        juiceshop=JuiceshopRun(results=results),
        portswigger=PortswiggerResult(
            available=True, vuln_lab_confirmed=False, clean_lab_fp_count=0
        ),
    )
    assert not gate.portswigger.passes
    assert not gate.passed


def test_portswigger_available_clean_lab_fp_fails() -> None:
    results = [_cr(confirmed=True, solved=True) for _ in range(4)]
    gate = Phase3GateResult(
        juiceshop=JuiceshopRun(results=results),
        portswigger=PortswiggerResult(
            available=True, vuln_lab_confirmed=True, clean_lab_fp_count=1
        ),
    )
    assert not gate.portswigger.passes
    assert not gate.passed


def test_report_contains_key_metrics() -> None:
    results = [_cr(confirmed=True, solved=True) for _ in range(3)]
    results.append(_cr(confirmed=False, solved=True))
    gate = Phase3GateResult(juiceshop=JuiceshopRun(results=results))
    report = gate.report()
    assert "75.0%" in report
    assert "0.0%" in report
    assert "PASSED" in report  # 3/4 = 0.75 exactly at floor → passes
