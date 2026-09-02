"""Open redirect detection tests (§7).

Covers:
  * Detector unit tests via in-memory fake probers: confirmed violation
    (sentinel echoed into Location), rewritten/relative Location → denied,
    non-3xx status → not confirmed.

v3: the OPEN_REDIRECT decide() branch this file also tested was removed
from reachagent.oracles.structural (live judgment now goes through
reachagent.oracles.llm_judgment.judge), so those oracle-level tests were
deleted. The remaining detector tests now assert on DETECTOR WIRING (does it
correctly relay a fixed verdict into `.confirmed`) via an injected
`oracle_runner`, not on judgment itself — matching
tests/phase3/test_path_traversal.py.
"""

from __future__ import annotations

from reachagent.openredirect.detector import (
    OpenRedirectProber,
    RedirectProbe,
    detect_open_redirect,
)
from tests._oracle_test_support import CONFIRMS, INCONCLUSIVE, fixed_oracle_runner

_ATTACKER_URL = "https://evil.example/reachagent-open-redirect-probe"

# === Detector unit tests ======================================================


def _prober(
    status: int = 0, location: str = "", target: str = _ATTACKER_URL, *, verdict=INCONCLUSIVE
) -> OpenRedirectProber:
    return OpenRedirectProber(
        fire_probe=lambda: RedirectProbe(status=status, location=location),
        probe_target=target,
        oracle_runner=fixed_oracle_runner(verdict),
    )


def test_detector_confirms_sentinel_echoed_into_location() -> None:
    result = detect_open_redirect(
        _prober(status=302, location=_ATTACKER_URL, verdict=CONFIRMS), evidence_ref="or/1"
    )
    assert result.confirmed is True


def test_detector_rewritten_location_is_denied() -> None:
    result = detect_open_redirect(
        _prober(status=302, location="/login", verdict=INCONCLUSIVE), evidence_ref="or/rewritten"
    )
    assert result.confirmed is False


def test_detector_non_redirect_status_not_confirmed() -> None:
    result = detect_open_redirect(
        _prober(status=200, location="", verdict=INCONCLUSIVE), evidence_ref="or/no-redirect"
    )
    assert result.confirmed is False


def test_detector_partial_prefix_match_still_confirms() -> None:
    # The server may append a query string or fragment after the attacker URL.
    result = detect_open_redirect(
        _prober(status=302, location=f"{_ATTACKER_URL}?tracking=1", verdict=CONFIRMS),
        evidence_ref="or/suffix",
    )
    assert result.confirmed is True
