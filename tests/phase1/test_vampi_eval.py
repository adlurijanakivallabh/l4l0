"""VAmPI evaluation harness — the Phase 1 numeric gate (plan §14, §15; Task 9).

Two layers of assertion:

  1. **Pure metric tests** (no network): exercise ``precision_recall`` and the
     gate thresholds against hand-built truth tables, so the scoring logic — the
     part that decides pass/fail — is verified deterministically and always runs.
  2. **Live gate test** (needs both VAmPI toggles): drives the full pipeline
     through the MCP tools against ``vulnerable=1`` and ``vulnerable=0`` instances
     and asserts the §14/§15 gate — ≥90% precision, ≥80% recall on, zero findings
     off. Skips cleanly when the instances aren't reachable, so the suite stays
     green on a machine without VAmPI while remaining the reproducible gate the
     DoD requires when they are up.

The live URLs come from ``REACHAGENT_VAMPI_ON`` / ``REACHAGENT_VAMPI_OFF``
(defaulting to the local :5000 / :5002 containers).
"""

from __future__ import annotations

import os

import httpx
import pytest

from reachagent.eval.harness import (
    GateResult,
    Outcome,
    ScenarioResult,
    ToggleRun,
    evaluate,
    precision_recall,
)

# -- Layer 1: pure scoring logic (always runs, no network) ----------------


def _scn(vuln_class: str, *, confirmed: bool, expected: bool) -> ScenarioResult:
    outcome = Outcome.CONFIRMED if confirmed else Outcome.DETECTION_MISS
    return ScenarioResult(vuln_class=vuln_class, outcome=outcome, expected=expected)


def test_precision_recall_all_correct() -> None:
    scenarios = [
        _scn("bola", confirmed=True, expected=True),
        _scn("idor", confirmed=True, expected=True),
        _scn("mass_assignment", confirmed=True, expected=True),
    ]
    assert precision_recall(scenarios) == (1.0, 1.0)


def test_precision_penalises_a_false_positive() -> None:
    # 2 true positives, 1 false positive → precision 2/3, recall 1.0 (nothing missed).
    scenarios = [
        _scn("bola", confirmed=True, expected=True),
        _scn("idor", confirmed=True, expected=True),
        _scn("mass_assignment", confirmed=True, expected=False),
    ]
    precision, recall = precision_recall(scenarios)
    assert precision == pytest.approx(2 / 3)
    assert recall == 1.0


def test_recall_penalises_a_false_negative() -> None:
    # 2 true positives, 1 missed → recall 2/3, precision 1.0 (no false positives).
    scenarios = [
        _scn("bola", confirmed=True, expected=True),
        _scn("idor", confirmed=True, expected=True),
        _scn("mass_assignment", confirmed=False, expected=True),
    ]
    precision, recall = precision_recall(scenarios)
    assert precision == 1.0
    assert recall == pytest.approx(2 / 3)


def test_empty_confirmed_is_perfect_precision() -> None:
    # The toggle-off shape: nothing expected, nothing confirmed → both vacuously 1.0.
    scenarios = [
        _scn("bola", confirmed=False, expected=False),
        _scn("idor", confirmed=False, expected=False),
        _scn("mass_assignment", confirmed=False, expected=False),
    ]
    assert precision_recall(scenarios) == (1.0, 1.0)


def test_gate_passes_on_perfect_on_and_clean_off() -> None:
    on = ToggleRun(
        toggle_on=True,
        scenarios=[
            _scn("bola", confirmed=True, expected=True),
            _scn("idor", confirmed=True, expected=True),
            _scn("mass_assignment", confirmed=True, expected=True),
        ],
    )
    off = ToggleRun(
        toggle_on=False,
        scenarios=[
            _scn("bola", confirmed=False, expected=False),
            _scn("idor", confirmed=False, expected=False),
            _scn("mass_assignment", confirmed=False, expected=False),
        ],
    )
    gate = GateResult(on_run=on, off_run=off)
    assert gate.on_passes
    assert gate.off_passes
    assert gate.passed


def test_gate_fails_if_any_off_finding_is_confirmed() -> None:
    # A single false positive on the secure toggle fails the gate outright — the
    # "zero confirmed findings with the toggle off" half of §14/§15.
    on = ToggleRun(
        toggle_on=True,
        scenarios=[_scn("bola", confirmed=True, expected=True)],
    )
    off = ToggleRun(
        toggle_on=False,
        scenarios=[_scn("bola", confirmed=True, expected=False)],
    )
    gate = GateResult(on_run=on, off_run=off)
    assert gate.off_run.confirmed_count == 1
    assert not gate.off_passes
    assert not gate.passed


def test_gate_fails_below_recall_threshold() -> None:
    # 1 of 3 real vulns confirmed → recall 0.33, below the 0.80 floor.
    on = ToggleRun(
        toggle_on=True,
        scenarios=[
            _scn("bola", confirmed=True, expected=True),
            _scn("idor", confirmed=False, expected=True),
            _scn("mass_assignment", confirmed=False, expected=True),
        ],
    )
    off = ToggleRun(toggle_on=False, scenarios=[])
    gate = GateResult(on_run=on, off_run=off)
    assert not gate.on_passes
    assert not gate.passed


# -- Setup-failure vs. detection-miss distinction -------------------------


def _setup_failed(vuln_class: str, *, expected: bool) -> ScenarioResult:
    return ScenarioResult(
        vuln_class=vuln_class,
        outcome=Outcome.SETUP_FAILED,
        expected=expected,
        detail="setup failed: missing tokens",
    )


def test_healthy_run_computes_precision_recall_identically_to_before() -> None:
    # Regression guard for the outcome-category change: when every setup succeeds
    # (no SETUP_FAILED — environment_ok holds), a detection miss is still a plain
    # false negative and the metrics come out exactly as the pre-change formula
    # tp/(tp+fn) would give. 2 confirmed of 3 real vulns → precision 1.0, recall 2/3;
    # the added branch must not perturb the numbers on the healthy path.
    on = ToggleRun(
        toggle_on=True,
        scenarios=[
            _scn("bola", confirmed=True, expected=True),
            _scn("idor", confirmed=True, expected=True),
            _scn("mass_assignment", confirmed=False, expected=True),  # genuine miss
        ],
    )
    off = ToggleRun(
        toggle_on=False,
        scenarios=[_scn(c, confirmed=False, expected=False) for c in ("bola", "idor")],
    )
    gate = GateResult(on_run=on, off_run=off)

    assert gate.environment_ok  # all setups succeeded — the healthy path
    assert gate.setup_failures == 0
    # Identical to the pre-change math: tp=2, fn=1, fp=0.
    assert gate.on_run.precision == 1.0
    assert gate.on_run.recall == pytest.approx(2 / 3)
    # And the verdict is a real numeric FAIL (recall below 0.80), not NOT MEASURABLE.
    assert not gate.passed
    assert "NOT MEASURABLE" not in gate.report()


def test_setup_failure_is_not_a_false_negative() -> None:
    # A class whose setup failed never ran detection, so it must not count against
    # recall — otherwise a seed flake reads exactly like a detection regression.
    s = _setup_failed("bola", expected=True)
    assert not s.confirmed
    assert s.setup_failed
    assert not s.is_false_negative  # the crux: excluded from the recall denominator


def test_setup_failure_excluded_from_recall_but_detection_miss_counted() -> None:
    # Owner-only VAmPI seed state: bola setup-failed (no victim token), idor missed,
    # mass_assignment confirmed. Recall scores only the two classes that ran: 1/2.
    scenarios = [
        _setup_failed("bola", expected=True),
        _scn("mass_assignment", confirmed=True, expected=True),
        _scn("idor", confirmed=False, expected=True),
    ]
    precision, recall = precision_recall(scenarios)
    assert precision == 1.0
    assert recall == pytest.approx(1 / 2)


def test_gate_is_not_measurable_when_setup_fails() -> None:
    # Even if the classes that *did* run all pass, a setup failure makes the gate
    # un-measurable — it must not silently report PASSED on a flaky environment.
    on = ToggleRun(
        toggle_on=True,
        scenarios=[
            _setup_failed("bola", expected=True),
            _scn("mass_assignment", confirmed=True, expected=True),
            _scn("idor", confirmed=True, expected=True),
        ],
    )
    off = ToggleRun(toggle_on=False, scenarios=[])
    gate = GateResult(on_run=on, off_run=off)
    assert gate.on_passes  # the measured classes clear the thresholds...
    assert not gate.environment_ok  # ...but the environment did not hold up
    assert gate.setup_failures == 1
    assert not gate.passed
    assert "NOT MEASURABLE" in gate.report()


def test_gate_measurable_and_passing_reports_passed() -> None:
    on = ToggleRun(
        toggle_on=True,
        scenarios=[
            _scn(c, confirmed=True, expected=True) for c in ("bola", "idor", "mass_assignment")
        ],
    )
    off = ToggleRun(toggle_on=False, scenarios=[])
    gate = GateResult(on_run=on, off_run=off)
    assert gate.environment_ok
    assert gate.passed
    assert "PASSED" in gate.report()


# -- Layer 2: live gate against both VAmPI toggles (skips if unreachable) --

_ON_URL = os.environ.get("REACHAGENT_VAMPI_ON", "http://127.0.0.1:5000")
_OFF_URL = os.environ.get("REACHAGENT_VAMPI_OFF", "http://127.0.0.1:5002")


def _reachable(url: str, *, want_vuln: int) -> bool:
    """True iff ``url`` answers and reports the expected ``vulnerable`` flag."""
    try:
        resp = httpx.get(url, timeout=2.0)
    except httpx.HTTPError:
        return False
    if resp.status_code != 200:
        return False
    try:
        return int(resp.json().get("vulnerable", -1)) == want_vuln
    except (ValueError, TypeError):
        return False


_both_toggles_up = _reachable(_ON_URL, want_vuln=1) and _reachable(_OFF_URL, want_vuln=0)


@pytest.mark.skipif(
    not _both_toggles_up,
    reason=f"needs VAmPI vulnerable=1 at {_ON_URL} and vulnerable=0 at {_OFF_URL}",
)
def test_live_vampi_phase1_gate() -> None:
    result = evaluate(on_base_url=_ON_URL, off_base_url=_OFF_URL)
    # Emit the measured numbers so the reproducible run is visible in test output.
    print("\n" + result.report())

    # Toggle ON: meets the §14/§15 precision/recall thresholds.
    assert result.on_run.precision >= 0.90
    assert result.on_run.recall >= 0.80
    # Toggle OFF: exactly zero confirmed findings.
    assert result.off_run.confirmed_count == 0
    # The composite gate verdict.
    assert result.passed
