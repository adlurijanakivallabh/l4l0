"""NoSQL injection detection tests (plan §7, §9; Phase 3 Task 3).

Covers the Task 3 DoD:
  * AUTH_BYPASS expectation added to DiffExpectation — refused→granted confirms,
    refused→refused confirms_denied, anything else inconclusive.
  * Auth-bypass sub-case: operator injection differential oracle, same mechanism
    as BOLA/mass-assignment (DIFFERENTIAL), new expectation only.
  * Blind-extraction sub-case: timing_statistical harness reused with
    operator-based boolean conditions — no new oracle family.
  * Auth-bypass first, timing fallback only when bypass not confirmed.
  * Confirmed bypass sets bypass_identity_hint for derived_credential spawn (§8).
  * Clean-target full-chain test: both stages walked end-to-end, no false confirm.
"""

from __future__ import annotations

import pytest

from reachagent.detection.oracle_gateway import OracleOutcome, OracleRunner, registry_runner
from reachagent.nosql.detector import (
    AuthBypassProbe,
    NoSqliProber,
    NoSqliResult,
    TimingProbe,
    detect_nosqli,
)
from reachagent.oracles import OracleMechanism
from reachagent.oracles.base import OracleVerdict
from reachagent.oracles.differential import Observation
from tests._oracle_test_support import CONFIRMS, INCONCLUSIVE

# Stable baseline for timing tests (10 trials, sub-second, low jitter).
_STABLE_BASELINE = (100.0, 105.0, 98.0, 102.0, 101.0, 99.0, 103.0, 100.0, 104.0, 97.0)
_DELAYED_PROBE = tuple(5000.0 + i for i in range(10))


# === oracle_runner fakes (v3 — see tests/_oracle_test_support.py) =============
#
# decide() is gone; confirmation is now an LLM judgment, not something a
# hermetic test can re-derive deterministically. These tests assert on
# DETECTOR WIRING (does detect_nosqli correctly relay a fixed verdict per
# stage into .confirmed/.mechanism/.attempted), not on judgment itself.
# detect_nosqli's two stages (auth-bypass, timing) share one oracle_runner
# slot on NoSqliProber, so — unlike fixed_oracle_runner's single fixed status
# — this fake routes by mechanism, letting a test fix bypass and timing to
# different verdicts in the same run (e.g. "bypass denies, timing confirms").


def _oracle_runner_by_mechanism(
    *, differential: object = INCONCLUSIVE, timing: object = INCONCLUSIVE
) -> OracleRunner:
    def _runner(mechanism: OracleMechanism, evidence: object) -> OracleOutcome:
        status = differential if mechanism is OracleMechanism.DIFFERENTIAL else timing
        ref = str(getattr(evidence, "evidence_ref", "") or "")
        verdict = OracleVerdict(
            mechanism=mechanism, status=status, evidence_ref=ref, reason="test-fixed-verdict"
        )
        return OracleOutcome(verdict)

    return _runner


# === _prober factory ==========================================================


def _prober(
    *,
    bypass: AuthBypassProbe,
    timing: TimingProbe,
    trace: list[str],
    oracle_runner: OracleRunner = registry_runner,
) -> NoSqliProber:
    def fire_auth_bypass() -> AuthBypassProbe:
        trace.append("fire_bypass")
        return bypass

    def fire_timing() -> TimingProbe:
        trace.append("fire_timing")
        return timing

    return NoSqliProber(
        fire_auth_bypass=fire_auth_bypass, fire_timing=fire_timing, oracle_runner=oracle_runner
    )


def _bypass_probe(*, granted: bool) -> AuthBypassProbe:
    """Auth-bypass probe pair: baseline always refused; probe granted or refused."""
    return AuthBypassProbe(
        baseline=Observation("benign", 401, "unauthorized"),
        probe=Observation("injected", 200 if granted else 401, "ok" if granted else "no"),
    )


# === detect_nosqli ordering and confirmation ==================================


def test_bypass_confirms_and_timing_never_fired() -> None:
    # Auth-bypass confirms → detector returns without firing timing.
    trace: list[str] = []
    prober = _prober(
        bypass=_bypass_probe(granted=True),
        timing=TimingProbe(_DELAYED_PROBE, _STABLE_BASELINE),
        trace=trace,
        oracle_runner=_oracle_runner_by_mechanism(differential=CONFIRMS),
    )
    result = detect_nosqli(prober, evidence_ref="nosql/login")
    assert result.confirmed
    assert result.mechanism is OracleMechanism.DIFFERENTIAL
    assert result.attempted == (OracleMechanism.DIFFERENTIAL,)
    assert "fire_bypass" in trace
    assert "fire_timing" not in trace  # timing genuinely not reached


def test_bypass_attempted_first_then_timing_when_no_bypass() -> None:
    # Bypass not confirmed → timing fallback reached. Order in trace proves bypass first.
    trace: list[str] = []
    prober = _prober(
        bypass=_bypass_probe(granted=False),
        timing=TimingProbe(_DELAYED_PROBE, _STABLE_BASELINE),
        trace=trace,
        oracle_runner=_oracle_runner_by_mechanism(differential=INCONCLUSIVE, timing=CONFIRMS),
    )
    result = detect_nosqli(prober)
    assert result.confirmed
    assert result.mechanism is OracleMechanism.TIMING_STATISTICAL
    assert result.attempted == (OracleMechanism.DIFFERENTIAL, OracleMechanism.TIMING_STATISTICAL)
    assert trace == ["fire_bypass", "fire_timing"]


def test_bypass_confirmed_sets_identity_hint() -> None:
    # A confirmed bypass must carry bypass_identity_hint so the caller can spawn
    # a synthetic Identity and write a derived_credential edge (§8).
    trace: list[str] = []
    prober = _prober(
        bypass=_bypass_probe(granted=True),
        timing=TimingProbe(_STABLE_BASELINE, _STABLE_BASELINE),
        trace=trace,
        oracle_runner=_oracle_runner_by_mechanism(differential=CONFIRMS),
    )
    result = detect_nosqli(prober, bypass_identity_hint="nosqli-admin")
    assert result.confirmed
    assert result.bypass_identity_hint == "nosqli-admin"


def test_bypass_not_confirmed_has_no_identity_hint() -> None:
    # No bypass → no identity hint (nothing to spawn).
    trace: list[str] = []
    prober = _prober(
        bypass=_bypass_probe(granted=False),
        timing=TimingProbe(_STABLE_BASELINE, _STABLE_BASELINE),
        trace=trace,
    )
    result = detect_nosqli(prober)
    assert not result.confirmed
    assert result.bypass_identity_hint == ""


def test_timing_confirms_when_bypass_not_confirmed() -> None:
    trace: list[str] = []
    prober = _prober(
        bypass=_bypass_probe(granted=False),
        timing=TimingProbe(_DELAYED_PROBE, _STABLE_BASELINE),
        trace=trace,
        oracle_runner=_oracle_runner_by_mechanism(differential=INCONCLUSIVE, timing=CONFIRMS),
    )
    result = detect_nosqli(prober)
    assert result.confirmed
    assert result.mechanism is OracleMechanism.TIMING_STATISTICAL


# === THE clean-target full-chain test =========================================


def test_clean_target_stays_inconclusive_through_full_ordering() -> None:
    # A genuinely non-vulnerable target: bypass probe is refused (no grant),
    # timing shows probe == baseline (no delay). Both stages walked end-to-end
    # with no false confirmed_violation in the stage-handoff logic.
    # Not each stage inconclusive in isolation — the full chain, one run.
    trace: list[str] = []
    prober = _prober(
        bypass=_bypass_probe(granted=False),  # injection also refused — no bypass
        timing=TimingProbe(_STABLE_BASELINE, _STABLE_BASELINE),  # no delay
        trace=trace,
    )
    result = detect_nosqli(prober, evidence_ref="nosql/clean-target")
    assert not result.confirmed
    assert result.mechanism is None
    # Both stages genuinely walked, in order, and neither confirmed.
    assert result.attempted == (
        OracleMechanism.DIFFERENTIAL,
        OracleMechanism.TIMING_STATISTICAL,
    )
    assert trace == ["fire_bypass", "fire_timing"]


# === result shape =============================================================


def test_result_carries_evidence_ref() -> None:
    trace: list[str] = []
    prober = _prober(
        bypass=_bypass_probe(granted=True),
        timing=TimingProbe(_STABLE_BASELINE, _STABLE_BASELINE),
        trace=trace,
    )
    result = detect_nosqli(prober, evidence_ref="nosql/ref-check")
    assert result.evidence_ref == "nosql/ref-check"


def test_nosqli_result_is_frozen() -> None:
    r = NoSqliResult(confirmed=False, mechanism=None)
    with pytest.raises((AttributeError, TypeError)):
        r.confirmed = True  # type: ignore[misc]
