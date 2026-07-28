"""Clickjacking detection tests (plan §5/§7, v1.5).

Covers:
  * Detector unit tests via in-memory fake probers: confirmed violation (both
    defenses absent), XFO-only → denied, CSP frame-ancestors-only → denied,
    empty headers → violation (framable).
  * Oracle-level unit tests for the CLICKJACKING decide() branch directly.
"""

from __future__ import annotations

from reachagent.clickjacking.detector import (
    ClickjackingProber,
    FramingHeaders,
    detect_clickjacking,
)
from reachagent.graph.nodes import FindingStatus
from reachagent.oracles.structural import StructuralCheckType, StructuralEvidence, decide

# === Detector unit tests ======================================================


def _prober(x_frame_options: str = "", csp: str = "") -> ClickjackingProber:
    return ClickjackingProber(
        fire_probe=lambda: FramingHeaders(x_frame_options=x_frame_options, csp=csp),
    )


def test_detector_confirms_when_both_defenses_absent() -> None:
    result = detect_clickjacking(_prober(), evidence_ref="clickjacking/1")
    assert result.confirmed is True


def test_detector_xfo_only_is_denied() -> None:
    result = detect_clickjacking(_prober(x_frame_options="DENY"), evidence_ref="clickjacking/xfo")
    assert result.confirmed is False


def test_detector_xfo_sameorigin_is_denied() -> None:
    result = detect_clickjacking(
        _prober(x_frame_options="SAMEORIGIN"), evidence_ref="clickjacking/xfo-so"
    )
    assert result.confirmed is False


def test_detector_csp_frame_ancestors_only_is_denied() -> None:
    result = detect_clickjacking(
        _prober(csp="default-src 'self'; frame-ancestors 'none'"),
        evidence_ref="clickjacking/csp",
    )
    assert result.confirmed is False


def test_detector_csp_frame_ancestors_case_insensitive() -> None:
    result = detect_clickjacking(
        _prober(csp="Frame-Ancestors 'self'"), evidence_ref="clickjacking/csp-case"
    )
    assert result.confirmed is False


def test_detector_csp_without_frame_ancestors_still_framable() -> None:
    # A CSP that lacks frame-ancestors is not a framing defense.
    result = detect_clickjacking(
        _prober(csp="default-src 'self'"), evidence_ref="clickjacking/csp-noframe"
    )
    assert result.confirmed is True


def test_detector_whitespace_xfo_is_not_a_defense() -> None:
    result = detect_clickjacking(
        _prober(x_frame_options="   "), evidence_ref="clickjacking/xfo-blank"
    )
    assert result.confirmed is True


def test_detector_xfo_allowall_is_violation() -> None:
    # Browsers ignore invalid XFO values; ALLOWALL leaves the page framable.
    result = detect_clickjacking(
        _prober(x_frame_options="ALLOWALL"), evidence_ref="clickjacking/xfo-allowall"
    )
    assert result.confirmed is True


def test_detector_frame_ancestors_wildcard_is_violation() -> None:
    # frame-ancestors * permits all framing → no defense.
    result = detect_clickjacking(
        _prober(csp="frame-ancestors *"), evidence_ref="clickjacking/fa-wildcard"
    )
    assert result.confirmed is True


def test_detector_xfo_allow_from_is_denied() -> None:
    result = detect_clickjacking(
        _prober(x_frame_options="ALLOW-FROM https://trusted.example"),
        evidence_ref="clickjacking/xfo-allowfrom",
    )
    assert result.confirmed is False


def test_detector_frame_ancestors_explicit_origins_is_denied() -> None:
    result = detect_clickjacking(
        _prober(csp="frame-ancestors 'self' https://x.com"),
        evidence_ref="clickjacking/fa-origins",
    )
    assert result.confirmed is False


# === Oracle-level unit tests (CLICKJACKING decide branch) =====================


def _cj_evidence(x_frame_options: str = "", csp: str = "") -> StructuralEvidence:
    return StructuralEvidence(
        check_type=StructuralCheckType.CLICKJACKING,
        x_frame_options=x_frame_options,
        csp=csp,
    )


def test_oracle_clickjacking_both_absent_is_violation() -> None:
    assert decide(_cj_evidence()) is FindingStatus.CONFIRMED_VIOLATION


def test_oracle_clickjacking_xfo_present_is_denied() -> None:
    assert decide(_cj_evidence(x_frame_options="DENY")) is FindingStatus.CONFIRMED_DENIED


def test_oracle_clickjacking_frame_ancestors_present_is_denied() -> None:
    assert decide(_cj_evidence(csp="frame-ancestors 'none'")) is FindingStatus.CONFIRMED_DENIED


def test_oracle_clickjacking_both_present_is_denied() -> None:
    assert (
        decide(_cj_evidence(x_frame_options="DENY", csp="frame-ancestors 'self'"))
        is FindingStatus.CONFIRMED_DENIED
    )


def test_oracle_clickjacking_xfo_allowall_is_violation() -> None:
    assert decide(_cj_evidence(x_frame_options="ALLOWALL")) is FindingStatus.CONFIRMED_VIOLATION


def test_oracle_clickjacking_frame_ancestors_wildcard_is_violation() -> None:
    assert (
        decide(_cj_evidence(x_frame_options="", csp="frame-ancestors *"))
        is FindingStatus.CONFIRMED_VIOLATION
    )
