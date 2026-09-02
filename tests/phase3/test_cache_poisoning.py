"""Web cache poisoning detection tests (§7).

Covers:
  * Detector unit tests via in-memory fake probers: confirmed violation
    (marker replayed from cache), per-request reflection with no cache
    involved → denied, no reflection at all → not confirmed.

v3: the WEB_CACHE_POISONING oracle-level decide() unit tests were removed —
that fixed decision logic no longer exists (live judgment now goes through
reachagent.oracles.llm_judgment.judge). Detector tests now assert on WIRING
(does the detector correctly relay a fixed verdict into `.confirmed`) via an
injected `oracle_runner`, not on judgment itself — matching
tests/phase3/test_path_traversal.py.
"""

from __future__ import annotations

from reachagent.cachepoisoning.detector import (
    CachePoisoningProbe,
    CachePoisoningProber,
    detect_cache_poisoning,
)
from tests._oracle_test_support import CONFIRMS, INCONCLUSIVE, fixed_oracle_runner

_MARKER = "reachagent-cache-poison-canary-7f3a2b"

# === Detector unit tests ======================================================


def _prober(
    status: int = 0,
    poisoned_body: str = "",
    reread_body: str = "",
    marker: str = _MARKER,
    *,
    verdict=INCONCLUSIVE,
) -> CachePoisoningProber:
    return CachePoisoningProber(
        fire_probe=lambda: CachePoisoningProbe(
            poisoned_status=status, poisoned_body=poisoned_body, reread_body=reread_body
        ),
        marker=marker,
        oracle_runner=fixed_oracle_runner(verdict),
    )


def test_detector_confirms_marker_replayed_from_cache() -> None:
    body = f'<link rel="canonical" href="https://{_MARKER}/">'
    result = detect_cache_poisoning(
        _prober(status=200, poisoned_body=body, reread_body=body, verdict=CONFIRMS),
        evidence_ref="cp/1",
    )
    assert result.confirmed is True


def test_detector_reflection_without_cache_replay_is_denied() -> None:
    body = f'<link rel="canonical" href="https://{_MARKER}/">'
    result = detect_cache_poisoning(
        _prober(
            status=200,
            poisoned_body=body,
            reread_body="<html>clean</html>",
            verdict=INCONCLUSIVE,
        ),
        evidence_ref="cp/no-replay",
    )
    assert result.confirmed is False


def test_detector_no_reflection_not_confirmed() -> None:
    result = detect_cache_poisoning(
        _prober(
            status=200,
            poisoned_body="<html>unrelated</html>",
            reread_body="",
            verdict=INCONCLUSIVE,
        ),
        evidence_ref="cp/no-reflection",
    )
    assert result.confirmed is False


def test_detector_non_2xx_probe_not_confirmed() -> None:
    body = f"marker={_MARKER}"
    result = detect_cache_poisoning(
        _prober(status=500, poisoned_body=body, reread_body=body, verdict=INCONCLUSIVE),
        evidence_ref="cp/error",
    )
    assert result.confirmed is False
