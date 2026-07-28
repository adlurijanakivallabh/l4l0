"""CORS misconfiguration detection tests (plan §5/§7, v1.5).

Covers:
  * Detector unit tests via in-memory fake probers: confirmed violation
    (origin-reflected ACAO + credentials), reflection-without-credentials →
    denied, credentials-without-reflection → denied, ACAO: * with credentials →
    denied (browsers reject the pair), empty headers → not confirmed.
  * Oracle-level unit tests for the CORS_MISCONFIG decide() branch directly.
"""

from __future__ import annotations

from reachagent.cors.detector import CorsHeaders, CorsProber, detect_cors_misconfig
from reachagent.graph.nodes import FindingStatus
from reachagent.oracles.structural import StructuralCheckType, StructuralEvidence, decide

_ATTACKER_ORIGIN = "https://evil.example"

# === Detector unit tests ======================================================


def _prober(acao: str = "", acac: str = "", origin: str = _ATTACKER_ORIGIN) -> CorsProber:
    return CorsProber(
        fire_probe=lambda: CorsHeaders(acao=acao, acac=acac),
        probe_origin=origin,
    )


def test_detector_confirms_reflected_origin_with_credentials() -> None:
    result = detect_cors_misconfig(
        _prober(acao=_ATTACKER_ORIGIN, acac="true"), evidence_ref="cors/1"
    )
    assert result.confirmed is True


def test_detector_reflection_without_credentials_is_denied() -> None:
    result = detect_cors_misconfig(
        _prober(acao=_ATTACKER_ORIGIN, acac=""), evidence_ref="cors/no-creds"
    )
    assert result.confirmed is False


def test_detector_credentials_without_reflection_is_denied() -> None:
    # Server echoes a fixed trusted origin, not the attacker's.
    result = detect_cors_misconfig(
        _prober(acao="https://trusted.example", acac="true"),
        evidence_ref="cors/no-reflect",
    )
    assert result.confirmed is False


def test_detector_wildcard_with_credentials_is_denied() -> None:
    # ACAO: * with credentials is rejected by browsers → not exploitable.
    result = detect_cors_misconfig(
        _prober(acao="*", acac="true"), evidence_ref="cors/wildcard-creds"
    )
    assert result.confirmed is False


def test_detector_empty_headers_not_confirmed() -> None:
    result = detect_cors_misconfig(_prober(), evidence_ref="cors/empty")
    assert result.confirmed is False


def test_detector_credentials_case_insensitive() -> None:
    result = detect_cors_misconfig(
        _prober(acao=_ATTACKER_ORIGIN, acac="TRUE"), evidence_ref="cors/case"
    )
    assert result.confirmed is True


# === Oracle-level unit tests (CORS_MISCONFIG decide branch) ===================


def _cors_evidence(
    acao: str = "", acac: str = "", probe_origin: str = _ATTACKER_ORIGIN
) -> StructuralEvidence:
    return StructuralEvidence(
        check_type=StructuralCheckType.CORS_MISCONFIG,
        acao=acao,
        acac=acac,
        probe_origin=probe_origin,
    )


def test_oracle_cors_reflected_with_credentials_is_violation() -> None:
    assert (
        decide(_cors_evidence(acao=_ATTACKER_ORIGIN, acac="true"))
        is FindingStatus.CONFIRMED_VIOLATION
    )


def test_oracle_cors_reflected_without_credentials_is_denied() -> None:
    assert (
        decide(_cors_evidence(acao=_ATTACKER_ORIGIN, acac="false"))
        is FindingStatus.CONFIRMED_DENIED
    )


def test_oracle_cors_wildcard_with_credentials_is_denied() -> None:
    assert decide(_cors_evidence(acao="*", acac="true")) is FindingStatus.CONFIRMED_DENIED


def test_oracle_cors_empty_acao_is_inconclusive() -> None:
    assert decide(_cors_evidence(acao="", acac="true")) is FindingStatus.INCONCLUSIVE
