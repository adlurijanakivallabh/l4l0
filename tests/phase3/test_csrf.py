"""CSRF missing-protection detection tests (plan §5/§7, v1.5) — Partial, precondition-only.

Covers:
  * Detector unit tests via in-memory fake probers: SameSite=None + no token →
    confirmed precondition; SameSite=None + token → not confirmed; SameSite=Lax
    → not confirmed; SameSite=Strict → not confirmed; SameSite absent → not
    confirmed (inconclusive — browsers default to Lax).

v3 (CLAUDE.md): decide() is gone — confirmation is now an LLM judgment, not
something a hermetic test can re-derive deterministically. These tests now
assert on DETECTOR WIRING (does it correctly relay a fixed verdict into
``.confirmed``) via an injected ``oracle_runner``, not on judgment itself.
"""

from __future__ import annotations

from reachagent.csrf.detector import CsrfProber, CsrfSignals, detect_csrf_missing_protection
from tests._oracle_test_support import CONFIRMS, DENIES, INCONCLUSIVE, fixed_oracle_runner

# === Detector unit tests ======================================================


def _prober(
    set_cookie: str = "", csrf_token_present: bool = False, *, status=CONFIRMS
) -> CsrfProber:
    return CsrfProber(
        fire_probe=lambda: CsrfSignals(
            set_cookie=set_cookie, csrf_token_present=csrf_token_present
        ),
        oracle_runner=fixed_oracle_runner(status),
    )


def test_detector_samesite_none_no_token_confirms_precondition() -> None:
    result = detect_csrf_missing_protection(
        _prober(set_cookie="session=abc; SameSite=None; Secure", status=CONFIRMS),
        evidence_ref="csrf/none",
    )
    assert result.confirmed is True


def test_detector_samesite_none_with_token_not_confirmed() -> None:
    result = detect_csrf_missing_protection(
        _prober(
            set_cookie="session=abc; SameSite=None; Secure",
            csrf_token_present=True,
            status=DENIES,
        ),
        evidence_ref="csrf/none-token",
    )
    assert result.confirmed is False


def test_detector_samesite_lax_not_confirmed() -> None:
    result = detect_csrf_missing_protection(
        _prober(set_cookie="session=abc; SameSite=Lax", status=DENIES),
        evidence_ref="csrf/lax",
    )
    assert result.confirmed is False


def test_detector_samesite_strict_not_confirmed() -> None:
    result = detect_csrf_missing_protection(
        _prober(set_cookie="session=abc; SameSite=Strict", status=DENIES),
        evidence_ref="csrf/strict",
    )
    assert result.confirmed is False


def test_detector_samesite_absent_not_confirmed() -> None:
    # Absent SameSite → browsers default to Lax → inconclusive, not a violation.
    result = detect_csrf_missing_protection(
        _prober(set_cookie="session=abc; Secure", status=INCONCLUSIVE),
        evidence_ref="csrf/absent",
    )
    assert result.confirmed is False
