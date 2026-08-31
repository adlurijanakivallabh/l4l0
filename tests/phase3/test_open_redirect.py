"""Open redirect detection tests (§7).

Covers:
  * Detector unit tests via in-memory fake probers: confirmed violation
    (sentinel echoed into Location), rewritten/relative Location → denied,
    non-3xx status → not confirmed.
  * Oracle-level unit tests for the OPEN_REDIRECT decide() branch directly.
"""

from __future__ import annotations

from reachagent.graph.nodes import FindingStatus
from reachagent.openredirect.detector import (
    OpenRedirectProber,
    RedirectProbe,
    detect_open_redirect,
)
from reachagent.oracles.structural import StructuralCheckType, StructuralEvidence, decide

_ATTACKER_URL = "https://evil.example/reachagent-open-redirect-probe"

# === Detector unit tests ======================================================


def _prober(status: int = 0, location: str = "", target: str = _ATTACKER_URL) -> OpenRedirectProber:
    return OpenRedirectProber(
        fire_probe=lambda: RedirectProbe(status=status, location=location),
        probe_target=target,
    )


def test_detector_confirms_sentinel_echoed_into_location() -> None:
    result = detect_open_redirect(_prober(status=302, location=_ATTACKER_URL), evidence_ref="or/1")
    assert result.confirmed is True


def test_detector_rewritten_location_is_denied() -> None:
    result = detect_open_redirect(
        _prober(status=302, location="/login"), evidence_ref="or/rewritten"
    )
    assert result.confirmed is False


def test_detector_non_redirect_status_not_confirmed() -> None:
    result = detect_open_redirect(_prober(status=200, location=""), evidence_ref="or/no-redirect")
    assert result.confirmed is False


def test_detector_partial_prefix_match_still_confirms() -> None:
    # The server may append a query string or fragment after the attacker URL.
    result = detect_open_redirect(
        _prober(status=302, location=f"{_ATTACKER_URL}?tracking=1"), evidence_ref="or/suffix"
    )
    assert result.confirmed is True


# === Oracle-level unit tests (OPEN_REDIRECT decide branch) ====================


def _redirect_evidence(
    probe_status: int = 0, location: str = "", sentinel: str = _ATTACKER_URL
) -> StructuralEvidence:
    return StructuralEvidence(
        check_type=StructuralCheckType.OPEN_REDIRECT,
        probe_status=probe_status,
        location=location,
        sentinel=sentinel,
    )


def test_oracle_open_redirect_sentinel_in_location_is_violation() -> None:
    assert (
        decide(_redirect_evidence(probe_status=302, location=_ATTACKER_URL))
        is FindingStatus.CONFIRMED_VIOLATION
    )


def test_oracle_open_redirect_non_3xx_is_inconclusive() -> None:
    assert decide(_redirect_evidence(probe_status=200, location="")) is FindingStatus.INCONCLUSIVE


def test_oracle_open_redirect_rewritten_target_is_denied() -> None:
    assert (
        decide(_redirect_evidence(probe_status=302, location="/login"))
        is FindingStatus.CONFIRMED_DENIED
    )


def test_oracle_open_redirect_3xx_with_no_location_is_inconclusive() -> None:
    assert decide(_redirect_evidence(probe_status=302, location="")) is FindingStatus.INCONCLUSIVE
