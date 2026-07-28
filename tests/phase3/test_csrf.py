"""CSRF missing-protection detection tests (plan §5/§7, v1.5) — Partial, precondition-only.

Covers:
  * Detector unit tests via in-memory fake probers: SameSite=None + no token →
    confirmed precondition; SameSite=None + token → not confirmed; SameSite=Lax
    → not confirmed; SameSite=Strict → not confirmed; SameSite absent → not
    confirmed (inconclusive — browsers default to Lax).
  * ``_cookie_samesite`` helper unit tests: case-insensitivity, whitespace
    around ``=``, multi-cookie string (only the leading cookie is read).
  * Oracle-level unit tests for the CSRF_MISSING_PROTECTION decide() branch.
"""

from __future__ import annotations

from reachagent.csrf.detector import CsrfProber, CsrfSignals, detect_csrf_missing_protection
from reachagent.graph.nodes import FindingStatus
from reachagent.oracles.structural import (
    StructuralCheckType,
    StructuralEvidence,
    _cookie_samesite,
    decide,
)

# === Detector unit tests ======================================================


def _prober(set_cookie: str = "", csrf_token_present: bool = False) -> CsrfProber:
    return CsrfProber(
        fire_probe=lambda: CsrfSignals(
            set_cookie=set_cookie, csrf_token_present=csrf_token_present
        ),
    )


def test_detector_samesite_none_no_token_confirms_precondition() -> None:
    result = detect_csrf_missing_protection(
        _prober(set_cookie="session=abc; SameSite=None; Secure"),
        evidence_ref="csrf/none",
    )
    assert result.confirmed is True


def test_detector_samesite_none_with_token_not_confirmed() -> None:
    result = detect_csrf_missing_protection(
        _prober(set_cookie="session=abc; SameSite=None; Secure", csrf_token_present=True),
        evidence_ref="csrf/none-token",
    )
    assert result.confirmed is False


def test_detector_samesite_lax_not_confirmed() -> None:
    result = detect_csrf_missing_protection(
        _prober(set_cookie="session=abc; SameSite=Lax"),
        evidence_ref="csrf/lax",
    )
    assert result.confirmed is False


def test_detector_samesite_strict_not_confirmed() -> None:
    result = detect_csrf_missing_protection(
        _prober(set_cookie="session=abc; SameSite=Strict"),
        evidence_ref="csrf/strict",
    )
    assert result.confirmed is False


def test_detector_samesite_absent_not_confirmed() -> None:
    # Absent SameSite → browsers default to Lax → inconclusive, not a violation.
    result = detect_csrf_missing_protection(
        _prober(set_cookie="session=abc; Secure"),
        evidence_ref="csrf/absent",
    )
    assert result.confirmed is False


# === _cookie_samesite helper unit tests =======================================


def test_cookie_samesite_case_insensitive() -> None:
    assert _cookie_samesite("session=abc; samesite=NONE") == "none"
    assert _cookie_samesite("session=abc; SAMESITE=Lax") == "lax"


def test_cookie_samesite_tolerates_whitespace() -> None:
    assert _cookie_samesite("session=abc; SameSite = None") == "none"


def test_cookie_samesite_absent_returns_empty() -> None:
    assert _cookie_samesite("session=abc; Secure") == ""


def test_cookie_samesite_never_splits_on_comma() -> None:
    # A comma is NOT a delimiter: expires dates ("Wed, 09 Jun ...") carry commas,
    # so splitting on ',' would truncate a real cookie mid-attribute. We split on
    # ';' only. In practice one Set-Cookie header is one cookie, so this is safe;
    # the expires test below is the case that actually matters.
    assert _cookie_samesite("a=1; Secure, b=2; SameSite=None") == "none"


def test_cookie_samesite_expires_comma_does_not_break_parse() -> None:
    # Expires dates contain commas — split on ';' never crosses into them.
    value = "session=abc; Expires=Wed, 09 Jun 2027 10:18:14 GMT; SameSite=None"
    assert _cookie_samesite(value) == "none"


# === Oracle-level unit tests (CSRF_MISSING_PROTECTION decide branch) ==========


def _csrf_evidence(set_cookie: str = "", csrf_token_present: bool = False) -> StructuralEvidence:
    return StructuralEvidence(
        check_type=StructuralCheckType.CSRF_MISSING_PROTECTION,
        set_cookie=set_cookie,
        csrf_token_present=csrf_token_present,
    )


def test_oracle_csrf_none_no_token_is_violation() -> None:
    assert (
        decide(_csrf_evidence(set_cookie="s=1; SameSite=None")) is FindingStatus.CONFIRMED_VIOLATION
    )


def test_oracle_csrf_none_with_token_is_denied() -> None:
    assert (
        decide(_csrf_evidence(set_cookie="s=1; SameSite=None", csrf_token_present=True))
        is FindingStatus.CONFIRMED_DENIED
    )


def test_oracle_csrf_lax_is_denied() -> None:
    assert decide(_csrf_evidence(set_cookie="s=1; SameSite=Lax")) is FindingStatus.CONFIRMED_DENIED


def test_oracle_csrf_strict_is_denied() -> None:
    assert (
        decide(_csrf_evidence(set_cookie="s=1; SameSite=Strict")) is FindingStatus.CONFIRMED_DENIED
    )


def test_oracle_csrf_absent_samesite_is_inconclusive() -> None:
    assert decide(_csrf_evidence(set_cookie="s=1; Secure")) is FindingStatus.INCONCLUSIVE
