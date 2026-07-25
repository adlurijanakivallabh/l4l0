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

from reachagent.graph.nodes import FindingStatus
from reachagent.nosql.detector import (
    AuthBypassProbe,
    NoSqliProber,
    NoSqliResult,
    TimingProbe,
    detect_nosqli,
)
from reachagent.oracles import OracleMechanism
from reachagent.oracles.differential import (
    DiffAxis,
    DifferentialEvidence,
    DiffExpectation,
    Observation,
    decide,
)

# Stable baseline for timing tests (10 trials, sub-second, low jitter).
_STABLE_BASELINE = (100.0, 105.0, 98.0, 102.0, 101.0, 99.0, 103.0, 100.0, 104.0, 97.0)
_DELAYED_PROBE = tuple(5000.0 + i for i in range(10))


# === AUTH_BYPASS expectation (DiffExpectation) ================================


def test_auth_bypass_refused_then_granted_is_violation() -> None:
    # Baseline: benign credential, correctly refused (401).
    # Probe: operator-injected variant, granted (200).
    # Refused→granted is the bypass signal.
    ev = DifferentialEvidence(
        axis=DiffAxis.CROSS_CONDITION,
        expectation=DiffExpectation.AUTH_BYPASS,
        baseline=Observation("benign", 401, "unauthorized"),
        probe=Observation("injected", 200, '{"token":"abc"}'),
        evidence_ref="nosql/auth-bypass/login",
    )
    assert decide(ev) is FindingStatus.CONFIRMED_VIOLATION


def test_auth_bypass_refused_then_refused_is_confirmed_denied() -> None:
    # Injection was also refused — authentication held. Confirmed fact.
    ev = DifferentialEvidence(
        axis=DiffAxis.CROSS_CONDITION,
        expectation=DiffExpectation.AUTH_BYPASS,
        baseline=Observation("benign", 401, "unauthorized"),
        probe=Observation("injected", 403, "forbidden"),
        evidence_ref="nosql/auth-bypass/login",
    )
    assert decide(ev) is FindingStatus.CONFIRMED_DENIED


def test_auth_bypass_baseline_not_refused_is_inconclusive() -> None:
    # Baseline was granted — can't prove a bypass without a refused reference.
    ev = DifferentialEvidence(
        axis=DiffAxis.CROSS_CONDITION,
        expectation=DiffExpectation.AUTH_BYPASS,
        baseline=Observation("benign", 200, "ok"),
        probe=Observation("injected", 200, "ok"),
        evidence_ref="nosql/auth-bypass/login",
    )
    assert decide(ev) is FindingStatus.INCONCLUSIVE


def test_auth_bypass_baseline_refused_probe_error_is_inconclusive() -> None:
    # Baseline refused, probe returned 500 — ambiguous, no clean verdict.
    ev = DifferentialEvidence(
        axis=DiffAxis.CROSS_CONDITION,
        expectation=DiffExpectation.AUTH_BYPASS,
        baseline=Observation("benign", 401, "unauthorized"),
        probe=Observation("injected", 500, "internal error"),
        evidence_ref="nosql/auth-bypass/login",
    )
    assert decide(ev) is FindingStatus.INCONCLUSIVE


def test_auth_bypass_body_equivalence_not_required() -> None:
    # A fresh session returns a different token than the refused attempt.
    # Body-equivalence must NOT be the signal — refused→granted is enough.
    ev = DifferentialEvidence(
        axis=DiffAxis.CROSS_CONDITION,
        expectation=DiffExpectation.AUTH_BYPASS,
        baseline=Observation("benign", 401, "unauthorized"),
        probe=Observation("injected", 200, '{"token":"completely-different-value"}'),
        evidence_ref="nosql/auth-bypass/login",
    )
    assert decide(ev) is FindingStatus.CONFIRMED_VIOLATION


def test_auth_bypass_decision_is_deterministic() -> None:
    ev = DifferentialEvidence(
        axis=DiffAxis.CROSS_CONDITION,
        expectation=DiffExpectation.AUTH_BYPASS,
        baseline=Observation("benign", 401, "unauthorized"),
        probe=Observation("injected", 200, '{"token":"abc"}'),
        evidence_ref="nosql/auth-bypass/login",
    )
    verdicts = {decide(ev) for _ in range(50)}
    assert verdicts == {FindingStatus.CONFIRMED_VIOLATION}


# === _prober factory ==========================================================


def _prober(
    *,
    bypass: AuthBypassProbe,
    timing: TimingProbe,
    trace: list[str],
) -> NoSqliProber:
    def fire_auth_bypass() -> AuthBypassProbe:
        trace.append("fire_bypass")
        return bypass

    def fire_timing() -> TimingProbe:
        trace.append("fire_timing")
        return timing

    return NoSqliProber(fire_auth_bypass=fire_auth_bypass, fire_timing=fire_timing)


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
