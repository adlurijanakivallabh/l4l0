"""LDAP injection detection tests (plan §7, §9; Phase 3 Task 4).

Covers the Task 4 DoD:
  * Auth-bypass reuses DIFFERENTIAL / AUTH_BYPASS — the #21 drift test held, no
    new expectation or branch (LDAP's refused-wildcard baseline is the same
    "required-refused reference" role as NoSQLi's).
  * Blind extraction reuses timing_statistical for attribute-existence conditions.
  * No OOB stage — attempted never contains OOB_CALLBACK (ceiling stays lower per §5).
  * Auth-bypass first, timing fallback only when bypass not confirmed.
  * Confirmed bypass sets bypass_identity_hint for derived_credential spawn (§8).
  * Clean-target full-chain test: both stages walked, no false confirm in handoff.
"""

from __future__ import annotations

import pytest

from reachagent.ldap.detector import (
    AuthBypassProbe,
    LdapiProber,
    LdapiResult,
    TimingProbe,
    detect_ldapi,
)
from reachagent.oracles import OracleMechanism
from reachagent.oracles.differential import Observation
from tests._oracle_test_support import CONFIRMS, DENIES, fixed_oracle_runner

_STABLE_BASELINE = (100.0, 105.0, 98.0, 102.0, 101.0, 99.0, 103.0, 100.0, 104.0, 97.0)
_DELAYED_PROBE = tuple(5000.0 + i for i in range(10))


def _ordered_oracle_runner(*statuses):
    """v3: confirmation is now an LLM judgment (CLAUDE.md), not a hermetic decide().

    These ordering tests care about the DETECTOR's stage-handoff wiring (does it
    move to the next mechanism when one doesn't confirm, stop when one does),
    not about what a real LLM would decide from evidence content. This feeds a
    fixed verdict per call, in call order, so the two-stage handoff can be
    asserted deterministically.
    """
    runners = iter(fixed_oracle_runner(status) for status in statuses)

    def _runner(mechanism, evidence):
        return next(runners)(mechanism, evidence)

    return _runner


def _prober(
    *,
    bypass: AuthBypassProbe,
    timing: TimingProbe,
    trace: list[str],
    oracle_runner=None,
) -> LdapiProber:
    def fire_auth_bypass() -> AuthBypassProbe:
        trace.append("fire_bypass")
        return bypass

    def fire_timing() -> TimingProbe:
        trace.append("fire_timing")
        return timing

    kwargs = {} if oracle_runner is None else {"oracle_runner": oracle_runner}
    return LdapiProber(fire_auth_bypass=fire_auth_bypass, fire_timing=fire_timing, **kwargs)


def _bypass_probe(*, granted: bool) -> AuthBypassProbe:
    """Wildcard/filter bypass probe: baseline always refused; probe granted or refused."""
    return AuthBypassProbe(
        baseline=Observation("benign-bind", 401, "invalid credentials"),
        probe=Observation("wildcard-inject", 200 if granted else 401, "ok" if granted else "no"),
    )


# === ordering and confirmation ================================================


def test_wildcard_bypass_confirms_and_timing_never_fired() -> None:
    trace: list[str] = []
    prober = _prober(
        bypass=_bypass_probe(granted=True),
        timing=TimingProbe(_DELAYED_PROBE, _STABLE_BASELINE),
        trace=trace,
        oracle_runner=fixed_oracle_runner(CONFIRMS),
    )
    result = detect_ldapi(prober, evidence_ref="ldap/bind")
    assert result.confirmed
    assert result.mechanism is OracleMechanism.DIFFERENTIAL
    assert result.attempted == (OracleMechanism.DIFFERENTIAL,)
    assert "fire_bypass" in trace
    assert "fire_timing" not in trace


def test_bypass_attempted_first_then_timing_when_no_bypass() -> None:
    trace: list[str] = []
    prober = _prober(
        bypass=_bypass_probe(granted=False),
        timing=TimingProbe(_DELAYED_PROBE, _STABLE_BASELINE),
        trace=trace,
        oracle_runner=_ordered_oracle_runner(DENIES, CONFIRMS),
    )
    result = detect_ldapi(prober)
    assert result.confirmed
    assert result.mechanism is OracleMechanism.TIMING_STATISTICAL
    assert result.attempted == (OracleMechanism.DIFFERENTIAL, OracleMechanism.TIMING_STATISTICAL)
    assert trace == ["fire_bypass", "fire_timing"]


def test_bypass_confirmed_sets_identity_hint() -> None:
    prober = _prober(
        bypass=_bypass_probe(granted=True),
        timing=TimingProbe(_STABLE_BASELINE, _STABLE_BASELINE),
        trace=[],
        oracle_runner=fixed_oracle_runner(CONFIRMS),
    )
    result = detect_ldapi(prober, bypass_identity_hint="ldapi-admin")
    assert result.confirmed
    assert result.bypass_identity_hint == "ldapi-admin"


def test_bypass_not_confirmed_has_no_identity_hint() -> None:
    prober = _prober(
        bypass=_bypass_probe(granted=False),
        timing=TimingProbe(_STABLE_BASELINE, _STABLE_BASELINE),
        trace=[],
    )
    result = detect_ldapi(prober)
    assert not result.confirmed
    assert result.bypass_identity_hint == ""


# === no OOB channel for this class (§5 ceiling) ===============================


def test_no_oob_stage_ever_attempted() -> None:
    # LDAP has no DB-native out-of-band channel — unlike blind SQLi. The detector
    # must never attempt OOB_CALLBACK; the ceiling stays lower (§5), not parity.
    for granted in (True, False):
        prober = _prober(
            bypass=_bypass_probe(granted=granted),
            timing=TimingProbe(_STABLE_BASELINE, _STABLE_BASELINE),
            trace=[],
        )
        result = detect_ldapi(prober)
        assert OracleMechanism.OOB_CALLBACK not in result.attempted


# === THE clean-target full-chain test =========================================


def test_clean_target_stays_inconclusive_through_full_ordering() -> None:
    # Non-vulnerable target: wildcard injection still refused (no bypass), timing
    # probe == baseline (no delay). Both stages walked end-to-end, no false
    # confirmed_violation in the stage-handoff logic — the full chain, one run.
    trace: list[str] = []
    prober = _prober(
        bypass=_bypass_probe(granted=False),  # injection also refused
        timing=TimingProbe(_STABLE_BASELINE, _STABLE_BASELINE),  # no delay
        trace=trace,
    )
    result = detect_ldapi(prober, evidence_ref="ldap/clean-target")
    assert not result.confirmed
    assert result.mechanism is None
    assert result.attempted == (
        OracleMechanism.DIFFERENTIAL,
        OracleMechanism.TIMING_STATISTICAL,
    )
    assert trace == ["fire_bypass", "fire_timing"]


# === result shape =============================================================


def test_result_carries_evidence_ref() -> None:
    prober = _prober(
        bypass=_bypass_probe(granted=True),
        timing=TimingProbe(_STABLE_BASELINE, _STABLE_BASELINE),
        trace=[],
    )
    result = detect_ldapi(prober, evidence_ref="ldap/ref-check")
    assert result.evidence_ref == "ldap/ref-check"


def test_ldapi_result_is_frozen() -> None:
    r = LdapiResult(confirmed=False, mechanism=None)
    with pytest.raises((AttributeError, TypeError)):
        r.confirmed = True  # type: ignore[misc]
