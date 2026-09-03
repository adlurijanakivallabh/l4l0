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


# === Technique-diversity corroboration (v3 V3): a delayed third read -------


class _SequencedRunner:
    """Returns a different fixed verdict on each successive call."""

    def __init__(self, verdicts: list) -> None:
        self._verdicts = list(verdicts)

    def __call__(self, mechanism, evidence):  # noqa: ANN001
        return fixed_oracle_runner(self._verdicts.pop(0))(mechanism, evidence)


def test_no_delayed_reread_configured_is_byte_for_byte_unchanged() -> None:
    body = f'<link rel="canonical" href="https://{_MARKER}/">'
    result = detect_cache_poisoning(
        _prober(status=200, poisoned_body=body, reread_body=body, verdict=CONFIRMS),
        evidence_ref="cp/single",
    )
    assert result.confirmed is True
    assert result.corroborated is False


def test_marker_still_present_in_delayed_reread_corroborates() -> None:
    body = f'<link rel="canonical" href="https://{_MARKER}/">'
    runner = _SequencedRunner([CONFIRMS, CONFIRMS])
    prober = CachePoisoningProber(
        fire_probe=lambda: CachePoisoningProbe(
            poisoned_status=200, poisoned_body=body, reread_body=body
        ),
        marker=_MARKER,
        oracle_runner=runner,
        fire_delayed_reread=lambda: body,
    )
    result = detect_cache_poisoning(prober, evidence_ref="cp/corroborated")
    assert result.confirmed is True
    assert result.corroborated is True


def test_marker_gone_by_delayed_reread_fails_closed() -> None:
    """A marker present only in the immediate re-read (not a later, delayed
    one) is exactly the 'reused the same pooled upstream connection' false
    positive this corroboration rules out — must NOT confirm."""
    body = f'<link rel="canonical" href="https://{_MARKER}/">'
    runner = _SequencedRunner([CONFIRMS, INCONCLUSIVE])
    prober = CachePoisoningProber(
        fire_probe=lambda: CachePoisoningProbe(
            poisoned_status=200, poisoned_body=body, reread_body=body
        ),
        marker=_MARKER,
        oracle_runner=runner,
        fire_delayed_reread=lambda: "<html>clean, marker expired</html>",
    )
    result = detect_cache_poisoning(prober, evidence_ref="cp/contradicted")
    assert result.confirmed is False
    assert result.corroborated is False


def test_delayed_reread_never_fired_when_primary_does_not_confirm() -> None:
    calls = {"n": 0}

    def _delayed() -> str:
        calls["n"] += 1
        return "irrelevant"

    prober = CachePoisoningProber(
        fire_probe=lambda: CachePoisoningProbe(
            poisoned_status=200, poisoned_body="<html>unrelated</html>", reread_body=""
        ),
        marker=_MARKER,
        oracle_runner=fixed_oracle_runner(INCONCLUSIVE),
        fire_delayed_reread=_delayed,
    )
    result = detect_cache_poisoning(prober, evidence_ref="cp/no-primary")
    assert result.confirmed is False
    assert calls["n"] == 0  # no wasted delayed probe confirming a negative
