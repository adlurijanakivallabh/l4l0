"""Web cache poisoning detection tests (§7).

Covers:
  * Detector unit tests via in-memory fake probers: confirmed violation
    (marker replayed from cache), per-request reflection with no cache
    involved → denied, no reflection at all → not confirmed.
  * Oracle-level unit tests for the WEB_CACHE_POISONING decide() branch directly.
"""

from __future__ import annotations

from reachagent.cachepoisoning.detector import (
    CachePoisoningProbe,
    CachePoisoningProber,
    detect_cache_poisoning,
)
from reachagent.graph.nodes import FindingStatus
from reachagent.oracles.structural import StructuralCheckType, StructuralEvidence, decide

_MARKER = "reachagent-cache-poison-canary-7f3a2b"

# === Detector unit tests ======================================================


def _prober(
    status: int = 0, poisoned_body: str = "", reread_body: str = "", marker: str = _MARKER
) -> CachePoisoningProber:
    return CachePoisoningProber(
        fire_probe=lambda: CachePoisoningProbe(
            poisoned_status=status, poisoned_body=poisoned_body, reread_body=reread_body
        ),
        marker=marker,
    )


def test_detector_confirms_marker_replayed_from_cache() -> None:
    body = f'<link rel="canonical" href="https://{_MARKER}/">'
    result = detect_cache_poisoning(
        _prober(status=200, poisoned_body=body, reread_body=body), evidence_ref="cp/1"
    )
    assert result.confirmed is True


def test_detector_reflection_without_cache_replay_is_denied() -> None:
    body = f'<link rel="canonical" href="https://{_MARKER}/">'
    result = detect_cache_poisoning(
        _prober(status=200, poisoned_body=body, reread_body="<html>clean</html>"),
        evidence_ref="cp/no-replay",
    )
    assert result.confirmed is False


def test_detector_no_reflection_not_confirmed() -> None:
    result = detect_cache_poisoning(
        _prober(status=200, poisoned_body="<html>unrelated</html>", reread_body=""),
        evidence_ref="cp/no-reflection",
    )
    assert result.confirmed is False


def test_detector_non_2xx_probe_not_confirmed() -> None:
    body = f"marker={_MARKER}"
    result = detect_cache_poisoning(
        _prober(status=500, poisoned_body=body, reread_body=body), evidence_ref="cp/error"
    )
    assert result.confirmed is False


# === Oracle-level unit tests (WEB_CACHE_POISONING decide branch) =============


def _cache_evidence(
    probe_status: int = 0,
    response_body: str = "",
    reread_response_body: str = "",
    sentinel: str = _MARKER,
) -> StructuralEvidence:
    return StructuralEvidence(
        check_type=StructuralCheckType.WEB_CACHE_POISONING,
        probe_status=probe_status,
        sentinel=sentinel,
        response_body=response_body,
        reread_response_body=reread_response_body,
    )


def test_oracle_marker_in_both_responses_is_violation() -> None:
    assert (
        decide(
            _cache_evidence(probe_status=200, response_body=_MARKER, reread_response_body=_MARKER)
        )
        is FindingStatus.CONFIRMED_VIOLATION
    )


def test_oracle_marker_only_in_poisoning_probe_is_denied() -> None:
    assert (
        decide(_cache_evidence(probe_status=200, response_body=_MARKER, reread_response_body=""))
        is FindingStatus.CONFIRMED_DENIED
    )


def test_oracle_no_marker_anywhere_is_inconclusive() -> None:
    assert (
        decide(_cache_evidence(probe_status=200, response_body="", reread_response_body=""))
        is FindingStatus.INCONCLUSIVE
    )


def test_oracle_non_2xx_probe_is_inconclusive() -> None:
    assert (
        decide(
            _cache_evidence(probe_status=500, response_body=_MARKER, reread_response_body=_MARKER)
        )
        is FindingStatus.INCONCLUSIVE
    )


def test_oracle_missing_sentinel_is_inconclusive() -> None:
    assert (
        decide(
            _cache_evidence(
                probe_status=200, response_body="x", reread_response_body="x", sentinel=""
            )
        )
        is FindingStatus.INCONCLUSIVE
    )
