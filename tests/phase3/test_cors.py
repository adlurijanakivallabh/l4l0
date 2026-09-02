"""CORS misconfiguration detection tests (plan §5/§7, v1.5).

Covers:
  * Detector unit tests via in-memory fake probers: confirmed violation
    (origin-reflected ACAO + credentials), reflection-without-credentials →
    denied, credentials-without-reflection → denied, ACAO: * with credentials →
    denied (browsers reject the pair), empty headers → not confirmed.

v3 (CLAUDE.md): decide() is gone — confirmation is now an LLM judgment, not
something a hermetic test can re-derive deterministically. These tests now
assert on DETECTOR WIRING (does it correctly relay a fixed verdict into
`.confirmed`) via an injected `oracle_runner`, not on judgment itself.
"""

from __future__ import annotations

from reachagent.cors.detector import CorsHeaders, CorsProber, detect_cors_misconfig
from tests._oracle_test_support import CONFIRMS, DENIES, fixed_oracle_runner

_ATTACKER_ORIGIN = "https://evil.example"

# === Detector unit tests ======================================================


def _prober(
    acao: str = "", acac: str = "", origin: str = _ATTACKER_ORIGIN, *, status=DENIES
) -> CorsProber:
    return CorsProber(
        fire_probe=lambda: CorsHeaders(acao=acao, acac=acac),
        probe_origin=origin,
        oracle_runner=fixed_oracle_runner(status),
    )


def test_detector_confirms_reflected_origin_with_credentials() -> None:
    result = detect_cors_misconfig(
        _prober(acao=_ATTACKER_ORIGIN, acac="true", status=CONFIRMS), evidence_ref="cors/1"
    )
    assert result.confirmed is True


def test_detector_reflection_without_credentials_is_denied() -> None:
    result = detect_cors_misconfig(
        _prober(acao=_ATTACKER_ORIGIN, acac="", status=DENIES), evidence_ref="cors/no-creds"
    )
    assert result.confirmed is False


def test_detector_credentials_without_reflection_is_denied() -> None:
    # Server echoes a fixed trusted origin, not the attacker's.
    result = detect_cors_misconfig(
        _prober(acao="https://trusted.example", acac="true", status=DENIES),
        evidence_ref="cors/no-reflect",
    )
    assert result.confirmed is False


def test_detector_wildcard_with_credentials_is_denied() -> None:
    # ACAO: * with credentials is rejected by browsers → not exploitable.
    result = detect_cors_misconfig(
        _prober(acao="*", acac="true", status=DENIES), evidence_ref="cors/wildcard-creds"
    )
    assert result.confirmed is False


def test_detector_empty_headers_not_confirmed() -> None:
    result = detect_cors_misconfig(_prober(status=DENIES), evidence_ref="cors/empty")
    assert result.confirmed is False


def test_detector_credentials_case_insensitive() -> None:
    result = detect_cors_misconfig(
        _prober(acao=_ATTACKER_ORIGIN, acac="TRUE", status=CONFIRMS), evidence_ref="cors/case"
    )
    assert result.confirmed is True
