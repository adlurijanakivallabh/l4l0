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


# === Technique-diversity corroboration (v3 V3) ===============================


class _SequencedRunner:
    """Returns a different fixed verdict on each successive call — needed to
    test corroboration, where the primary and second-probe calls must be
    judged independently."""

    def __init__(self, verdicts: list) -> None:
        self._verdicts = list(verdicts)

    def __call__(self, mechanism, evidence):  # noqa: ANN001
        return fixed_oracle_runner(self._verdicts.pop(0))(mechanism, evidence)


def test_no_second_probe_configured_is_byte_for_byte_unchanged() -> None:
    """Omitting fire_second_probe (the default) must behave exactly as before
    this feature existed — a single-probe confirm, no corroboration field set."""
    result = detect_open_redirect(
        _prober(status=302, location=_ATTACKER_URL, verdict=CONFIRMS), evidence_ref="or/single"
    )
    assert result.confirmed is True
    assert result.corroborated is False


def test_second_probe_also_confirming_corroborates() -> None:
    runner = _SequencedRunner([CONFIRMS, CONFIRMS])
    prober = OpenRedirectProber(
        fire_probe=lambda: RedirectProbe(status=302, location=_ATTACKER_URL),
        fire_second_probe=lambda: RedirectProbe(status=302, location=_ATTACKER_URL),
        probe_target=_ATTACKER_URL,
        oracle_runner=runner,
    )
    result = detect_open_redirect(prober, evidence_ref="or/corroborated")
    assert result.confirmed is True
    assert result.corroborated is True


def test_second_probe_not_reflecting_fails_closed_not_the_uncorroborated_primary() -> None:
    """A confirmed first probe whose second, different parameter does NOT also
    reflect the attacker URL must NOT confirm — never fall back to trusting
    the uncorroborated single probe."""
    runner = _SequencedRunner([CONFIRMS, INCONCLUSIVE])
    prober = OpenRedirectProber(
        fire_probe=lambda: RedirectProbe(status=302, location=_ATTACKER_URL),
        fire_second_probe=lambda: RedirectProbe(status=302, location="/login"),
        probe_target=_ATTACKER_URL,
        oracle_runner=runner,
    )
    result = detect_open_redirect(prober, evidence_ref="or/contradicted")
    assert result.confirmed is False
    assert result.corroborated is False


def test_second_probe_never_fired_when_primary_does_not_confirm() -> None:
    calls = {"n": 0}

    def _second() -> RedirectProbe:
        calls["n"] += 1
        return RedirectProbe(status=302, location=_ATTACKER_URL)

    prober = OpenRedirectProber(
        fire_probe=lambda: RedirectProbe(status=200, location=""),
        fire_second_probe=_second,
        probe_target=_ATTACKER_URL,
        oracle_runner=fixed_oracle_runner(INCONCLUSIVE),
    )
    result = detect_open_redirect(prober, evidence_ref="or/no-primary")
    assert result.confirmed is False
    assert calls["n"] == 0  # no wasted probe confirming a negative
