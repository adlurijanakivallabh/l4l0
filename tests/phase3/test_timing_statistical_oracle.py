"""Paired-trial statistical timing oracle tests (plan §7, Phase 3 Task 2).

Covers the Task 2 DoD:
  * registered and callable via ``run_oracle`` (no ``UnknownOracleError``);
  * a synthetic delay confirms, equal latencies do not;
  * negative control is mandatory — probe-only raises, not inconclusive;
  * the decision is deterministic (fixed input, fixed output, no randomness);
  * **the noise-only case is rejected** — jitter that would look like a signal
    to a naive single-measurement check does not confirm here;
  * exactly three §7 families are registered (differential, business_rule,
    timing_statistical), not a fourth uncontrolled addition.
"""

from __future__ import annotations

import pytest

from reachagent.graph.nodes import FindingStatus
from reachagent.oracles import OracleMechanism
from reachagent.oracles.base import OracleVerdict
from reachagent.oracles.registry import _REGISTRY, UnknownOracleError, get_oracle
from reachagent.oracles.timing_statistical import (
    PairedTrialEvidence,
    TimingStatisticalOracle,
    ValidationError,
    decide,
)
from reachagent.tools.validator import run_oracle

# A benign baseline: 10 near-identical sub-second latencies with normal jitter.
_STABLE_BASELINE = (100.0, 105.0, 98.0, 102.0, 101.0, 99.0, 103.0, 100.0, 104.0, 97.0)


def _evidence(
    probe: tuple[float, ...], baseline: tuple[float, ...], **kw: object
) -> PairedTrialEvidence:
    return PairedTrialEvidence(
        probe_latencies_ms=probe,
        baseline_latencies_ms=baseline,
        evidence_ref="timing/test",
        **kw,  # type: ignore[arg-type]
    )


# --- registration (DoD: callable via run_oracle, three families) -------------


def test_timing_family_is_registered() -> None:
    oracle = get_oracle(OracleMechanism.TIMING_STATISTICAL)
    assert isinstance(oracle, TimingStatisticalOracle)
    assert oracle.mechanism is OracleMechanism.TIMING_STATISTICAL


def test_run_oracle_reaches_timing_family_without_unknown_error() -> None:
    # A real delayed probe against a stable baseline confirms through the
    # Validator's run_oracle path — proves the family is wired end to end.
    probe = tuple(5000.0 + i for i in range(10))  # ~5 s delay
    verdict = run_oracle(OracleMechanism.TIMING_STATISTICAL, _evidence(probe, _STABLE_BASELINE))
    assert isinstance(verdict, OracleVerdict)
    assert verdict.is_violation


def test_exactly_three_families_registered() -> None:
    # §7 names six families; three are built (differential Phase 1,
    # business_rule Phase 2, timing_statistical Phase 3). This is the
    # tripwire against a fourth uncontrolled addition slipping in.
    assert set(_REGISTRY) == {
        OracleMechanism.DIFFERENTIAL,
        OracleMechanism.BUSINESS_RULE_INVARIANT,
        OracleMechanism.TIMING_STATISTICAL,
    }


def test_timing_mechanism_is_one_of_the_six_declared_families() -> None:
    # The mechanism must already exist in the §7 enum — registering it is not
    # adding a seventh family, it's building a declared-but-stubbed one.
    assert OracleMechanism.TIMING_STATISTICAL in set(OracleMechanism)


# --- confirm / not-confirm (DoD: synthetic delay vs equal latencies) ---------


def test_synthetic_delay_confirms() -> None:
    probe = tuple(5000.0 + i * 2 for i in range(12))  # ~5 s injected delay, N=12
    assert decide(_evidence(probe, _STABLE_BASELINE)) is FindingStatus.CONFIRMED_VIOLATION


def test_equal_latencies_do_not_confirm() -> None:
    # Probe and baseline drawn from the same distribution: no injected delay.
    assert decide(_evidence(_STABLE_BASELINE, _STABLE_BASELINE)) is FindingStatus.INCONCLUSIVE


def test_probe_slightly_slower_but_within_jitter_does_not_confirm() -> None:
    # _STABLE_BASELINE mean=100.9, std≈2.47, threshold≈108.3.
    # Probe at +5.0 gives mean 105.9 — below threshold, not a signal.
    probe = tuple(x + 5.0 for x in _STABLE_BASELINE)
    assert decide(_evidence(probe, _STABLE_BASELINE)) is FindingStatus.INCONCLUSIVE


# --- THE noise-only rejection (DoD: jitter alone must not look like signal) ---


def test_noise_alone_does_not_confirm_even_with_a_slow_outlier() -> None:
    """A control with no real injection: one probe request happened to spike
    from network jitter, but the *mean* stays within threshold. A naive
    single-measurement / max-latency check would fire on the outlier; the
    paired-trial oracle, comparing means against the baseline's own spread,
    correctly rejects it.

    Baseline alternates 50/950 ms (mean=500, std=450, threshold=1850).
    Probe has one 5000 ms outlier but the other 9 requests are normal —
    probe mean ≈ 590 ms, well below the 1850 ms threshold.
    """
    # Wide-spread baseline: mean=500, std=450, threshold = 500 + 3*450 = 1850.
    noisy_baseline = (50.0, 950.0, 50.0, 950.0, 50.0, 950.0, 50.0, 950.0, 50.0, 950.0)
    # One jitter spike at 5000 ms; the other 9 are normal (~90–110 ms).
    # Probe mean = (5000 + 9*100) / 10 = 590 ms — below 1850 ms threshold.
    noisy_probe = (5000.0, 100.0, 90.0, 110.0, 95.0, 105.0, 100.0, 90.0, 110.0, 100.0)
    # A max-latency heuristic would see 5000 ms and scream. The mean test does not:
    verdict = decide(_evidence(noisy_probe, noisy_baseline))
    assert verdict is FindingStatus.INCONCLUSIVE


def test_wide_baseline_spread_raises_the_bar() -> None:
    # Same probe mean, but a baseline with large σ absorbs it — no confirmation.
    # Proves the threshold is baseline-relative (N×σ), not an absolute constant.
    wide_baseline = (0.0, 1000.0, 0.0, 1000.0, 0.0, 1000.0, 0.0, 1000.0, 0.0, 1000.0)
    probe = tuple(700.0 for _ in range(10))  # above the 500 mean, but < mean+3σ
    assert decide(_evidence(probe, wide_baseline)) is FindingStatus.INCONCLUSIVE


# --- mandatory negative control (DoD: probe-only raises, not inconclusive) ----


def test_missing_baseline_raises_not_inconclusive() -> None:
    with pytest.raises(ValidationError, match="baseline requires"):
        decide(
            PairedTrialEvidence(
                probe_latencies_ms=tuple(5000.0 for _ in range(10)),
                baseline_latencies_ms=(),
                evidence_ref="timing/test",
            )
        )


def test_too_few_baseline_trials_raises() -> None:
    with pytest.raises(ValidationError, match="baseline requires ≥10"):
        decide(_evidence(tuple(5000.0 for _ in range(10)), tuple(100.0 for _ in range(9))))


def test_too_few_probe_trials_raises() -> None:
    with pytest.raises(ValidationError, match="probe requires ≥10"):
        decide(_evidence(tuple(5000.0 for _ in range(9)), _STABLE_BASELINE))


# --- determinism (DoD: fixed input → fixed output, no randomness) ------------


def test_decision_is_deterministic() -> None:
    probe = tuple(5000.0 + i for i in range(10))
    ev = _evidence(probe, _STABLE_BASELINE)
    first = decide(ev)
    for _ in range(50):
        assert decide(ev) is first  # same evidence, same verdict, every time


def test_verdict_carries_mechanism_and_evidence_ref() -> None:
    probe = tuple(5000.0 for _ in range(10))
    verdict = TimingStatisticalOracle().run(_evidence(probe, _STABLE_BASELINE))
    assert verdict.mechanism is OracleMechanism.TIMING_STATISTICAL
    assert verdict.evidence_ref == "timing/test"


# --- type discipline (mirrors differential/business_rule) --------------------


def test_wrong_evidence_type_raises_typeerror() -> None:
    with pytest.raises(TypeError, match="PairedTrialEvidence"):
        TimingStatisticalOracle().run(object())


def test_perfectly_stable_baseline_confirms_any_higher_probe() -> None:
    # σ == 0 → threshold collapses to probe_mean > baseline_mean. Any consistent
    # delay above a flat baseline is a real signal.
    flat_baseline = tuple(100.0 for _ in range(10))
    probe = tuple(150.0 for _ in range(10))
    assert decide(_evidence(probe, flat_baseline)) is FindingStatus.CONFIRMED_VIOLATION


def test_unknown_mechanism_still_raises() -> None:
    # Sanity: the registry still refuses genuinely-unbuilt families loudly.
    with pytest.raises(UnknownOracleError):
        get_oracle(OracleMechanism.OOB_CALLBACK)
