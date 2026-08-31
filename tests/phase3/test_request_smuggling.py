"""Request smuggling (CL.TE desync) detection tests (§7).

Covers:
  * Detector unit tests via in-memory fake probers: a confirmed desync (probe
    latencies far above baseline), a clean target (comparable latencies), and
    the oracle's own validation errors (too few trials) propagating correctly.
  * Reuses the existing TIMING_STATISTICAL oracle unchanged — no new oracle
    branch to test here; test_timing_statistical.py already covers decide().
"""

from __future__ import annotations

import pytest

from reachagent.smuggling.detector import (
    SmugglingProber,
    SmugglingTimingProbe,
    detect_request_smuggling,
)

_BASELINE = tuple(50.0 + i for i in range(10))  # ~50-59ms, tight and fast
_HUNG_PROBE = tuple(8000.0 + i for i in range(10))  # ~8s — the bounded-hang signal
_CLEAN_PROBE = tuple(52.0 + i for i in range(10))  # comparable to baseline — no desync


def _prober(probe: tuple[float, ...], baseline: tuple[float, ...]) -> SmugglingProber:
    return SmugglingProber(
        fire_timing=lambda: SmugglingTimingProbe(
            probe_latencies_ms=probe, baseline_latencies_ms=baseline
        )
    )


def test_detector_confirms_a_hung_probe_far_above_baseline() -> None:
    result = detect_request_smuggling(_prober(_HUNG_PROBE, _BASELINE), evidence_ref="rs/1")
    assert result.confirmed is True


def test_detector_clean_target_not_confirmed() -> None:
    result = detect_request_smuggling(_prober(_CLEAN_PROBE, _BASELINE), evidence_ref="rs/clean")
    assert result.confirmed is False


def test_detector_too_few_trials_raises_not_silently_inconclusive() -> None:
    # Matches the underlying oracle's own contract: a missing/short trial run
    # is a caller bug, not an ambiguous result — never silently swallowed.
    from reachagent.oracles.timing_statistical import ValidationError

    short = _prober(_HUNG_PROBE[:3], _BASELINE[:3])
    with pytest.raises(ValidationError):
        detect_request_smuggling(short, evidence_ref="rs/short")
