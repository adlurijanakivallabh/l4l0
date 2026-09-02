"""Clickjacking detection tests (plan §5/§7, v1.5).

Covers:
  * Detector unit tests via in-memory fake probers: confirmed violation (both
    defenses absent), XFO-only → denied, CSP frame-ancestors-only → denied,
    empty headers → violation (framable).

v3: the CLICKJACKING decide() branch this file also tested was removed from
reachagent.oracles.structural (live judgment now goes through
reachagent.oracles.llm_judgment.judge), so those oracle-level tests were
deleted.
"""

from __future__ import annotations

from reachagent.clickjacking.detector import (
    ClickjackingProber,
    FramingHeaders,
    detect_clickjacking,
)
from tests._oracle_test_support import CONFIRMS, DENIES, fixed_oracle_runner

# === Detector unit tests ======================================================
#
# v3 (CLAUDE.md): decide() is gone — confirmation is now an LLM judgment, not
# something a hermetic test can re-derive deterministically. These tests now
# assert on DETECTOR WIRING (does it correctly relay a fixed verdict into
# `.confirmed`) via an injected `oracle_runner`, matching whichever verdict the
# case is illustrating (both defenses absent / a weak or absent defense ==
# CONFIRMS a framing violation; an effective defense present == DENIES it).


def _prober(x_frame_options: str = "", csp: str = "", *, status=CONFIRMS) -> ClickjackingProber:
    return ClickjackingProber(
        fire_probe=lambda: FramingHeaders(x_frame_options=x_frame_options, csp=csp),
        oracle_runner=fixed_oracle_runner(status),
    )


def test_detector_confirms_when_both_defenses_absent() -> None:
    result = detect_clickjacking(_prober(status=CONFIRMS), evidence_ref="clickjacking/1")
    assert result.confirmed is True


def test_detector_xfo_only_is_denied() -> None:
    result = detect_clickjacking(
        _prober(x_frame_options="DENY", status=DENIES), evidence_ref="clickjacking/xfo"
    )
    assert result.confirmed is False


def test_detector_xfo_sameorigin_is_denied() -> None:
    result = detect_clickjacking(
        _prober(x_frame_options="SAMEORIGIN", status=DENIES), evidence_ref="clickjacking/xfo-so"
    )
    assert result.confirmed is False


def test_detector_csp_frame_ancestors_only_is_denied() -> None:
    result = detect_clickjacking(
        _prober(csp="default-src 'self'; frame-ancestors 'none'", status=DENIES),
        evidence_ref="clickjacking/csp",
    )
    assert result.confirmed is False


def test_detector_csp_frame_ancestors_case_insensitive() -> None:
    result = detect_clickjacking(
        _prober(csp="Frame-Ancestors 'self'", status=DENIES), evidence_ref="clickjacking/csp-case"
    )
    assert result.confirmed is False


def test_detector_csp_without_frame_ancestors_still_framable() -> None:
    # A CSP that lacks frame-ancestors is not a framing defense.
    result = detect_clickjacking(
        _prober(csp="default-src 'self'", status=CONFIRMS), evidence_ref="clickjacking/csp-noframe"
    )
    assert result.confirmed is True


def test_detector_whitespace_xfo_is_not_a_defense() -> None:
    result = detect_clickjacking(
        _prober(x_frame_options="   ", status=CONFIRMS), evidence_ref="clickjacking/xfo-blank"
    )
    assert result.confirmed is True


def test_detector_xfo_allowall_is_violation() -> None:
    # Browsers ignore invalid XFO values; ALLOWALL leaves the page framable.
    result = detect_clickjacking(
        _prober(x_frame_options="ALLOWALL", status=CONFIRMS),
        evidence_ref="clickjacking/xfo-allowall",
    )
    assert result.confirmed is True


def test_detector_frame_ancestors_wildcard_is_violation() -> None:
    # frame-ancestors * permits all framing → no defense.
    result = detect_clickjacking(
        _prober(csp="frame-ancestors *", status=CONFIRMS), evidence_ref="clickjacking/fa-wildcard"
    )
    assert result.confirmed is True


def test_detector_xfo_allow_from_is_denied() -> None:
    result = detect_clickjacking(
        _prober(x_frame_options="ALLOW-FROM https://trusted.example", status=DENIES),
        evidence_ref="clickjacking/xfo-allowfrom",
    )
    assert result.confirmed is False


def test_detector_frame_ancestors_explicit_origins_is_denied() -> None:
    result = detect_clickjacking(
        _prober(csp="frame-ancestors 'self' https://x.com", status=DENIES),
        evidence_ref="clickjacking/fa-origins",
    )
    assert result.confirmed is False
