"""Request smuggling (CL.TE desync) detection tests (§7).

Covers:
  * Detector unit tests via in-memory fake probers: a confirmed desync (probe
    latencies far above baseline) and a clean target (comparable latencies).
  * Reuses the existing TIMING_STATISTICAL oracle unchanged — no new oracle
    branch to test here.

v3 (CLAUDE.md): decide() is gone — confirmation is now an LLM judgment, not
something a hermetic test can re-derive deterministically. The "confirmed"
case now asserts on DETECTOR WIRING (does it correctly relay a fixed verdict
into `.confirmed`) via an injected `oracle_runner`, matching the pattern in
tests/phase3/test_path_traversal.py and tests/phase6/test_oracle_hardening.py.
"""

from __future__ import annotations

from reachagent.smuggling.detector import (
    SmugglingProber,
    SmugglingTimingProbe,
    detect_request_smuggling,
)
from tests._oracle_test_support import CONFIRMS, fixed_oracle_runner

_BASELINE = tuple(50.0 + i for i in range(10))  # ~50-59ms, tight and fast
_HUNG_PROBE = tuple(8000.0 + i for i in range(10))  # ~8s — the bounded-hang signal
_CLEAN_PROBE = tuple(52.0 + i for i in range(10))  # comparable to baseline — no desync


def _prober(
    probe: tuple[float, ...], baseline: tuple[float, ...], **kwargs: object
) -> SmugglingProber:
    return SmugglingProber(
        fire_timing=lambda: SmugglingTimingProbe(
            probe_latencies_ms=probe, baseline_latencies_ms=baseline
        ),
        **kwargs,
    )


def test_detector_confirms_a_hung_probe_far_above_baseline() -> None:
    prober = _prober(_HUNG_PROBE, _BASELINE, oracle_runner=fixed_oracle_runner(CONFIRMS))
    result = detect_request_smuggling(prober, evidence_ref="rs/1")
    assert result.confirmed is True


def test_detector_clean_target_not_confirmed() -> None:
    # No oracle_runner override: falls through to the real judgment path with
    # no LLM client configured, which fails closed to inconclusive — same
    # observable outcome (not confirmed) as a genuinely clean target.
    result = detect_request_smuggling(_prober(_CLEAN_PROBE, _BASELINE), evidence_ref="rs/clean")
    assert result.confirmed is False


def test_detector_too_few_trials_does_not_raise_now_fails_closed() -> None:
    # v3 (CLAUDE.md): the old ValidationError-on-too-few-trials check lived in
    # the now-removed decide() path. llm_judgment.judge() does not validate
    # trial counts before judging — a short trial run no longer raises, it
    # just falls through to the same fail-closed inconclusive as any other
    # evidence the judgment can't make sense of (no LLM client configured
    # here). Never a fabricated confirmation either way.
    short = _prober(_HUNG_PROBE[:3], _BASELINE[:3])
    result = detect_request_smuggling(short, evidence_ref="rs/short")
    assert result.confirmed is False
