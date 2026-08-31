"""Subdomain takeover detector — hermetic tests (§7, Prober-injection pattern).

Uses the real default registry runner (no validator import, no fake oracle) —
same pattern as test_request_smuggling.py. The oracle's own decide() branch is
covered separately in test_subdomain_takeover_oracle.py.
"""

from __future__ import annotations

from reachagent.subdomain_takeover.detector import (
    FINGERPRINTS,
    SubdomainTakeoverProbe,
    SubdomainTakeoverProber,
    detect_subdomain_takeover,
    match_fingerprint,
)

_S3_MARKER = "The specified bucket does not exist"


def _prober(status: int, body: str) -> SubdomainTakeoverProber:
    return SubdomainTakeoverProber(
        fire_probe=lambda: SubdomainTakeoverProbe(status=status, body=body)
    )


def test_match_fingerprint_recognizes_a_known_dangling_s3_cname() -> None:
    assert match_fingerprint("forgotten-bucket.s3.amazonaws.com") == _S3_MARKER


def test_match_fingerprint_is_case_insensitive() -> None:
    assert match_fingerprint("FORGOTTEN.S3.AMAZONAWS.COM") == _S3_MARKER


def test_match_fingerprint_returns_none_for_an_unknown_service() -> None:
    assert match_fingerprint("api.internal-vendor.example.com") is None


def test_every_fingerprint_entry_has_a_non_empty_sentinel() -> None:
    assert len(FINGERPRINTS) > 0
    for suffix, sentinel in FINGERPRINTS:
        assert suffix.startswith(".")
        assert sentinel


def test_confirmed_dangling_cname_yields_a_confirmed_result() -> None:
    prober = _prober(200, f"<Error>{_S3_MARKER}</Error>")
    result = detect_subdomain_takeover(prober, sentinel=_S3_MARKER, evidence_ref="ref-1")
    assert result.confirmed is True
    assert result.evidence_ref == "ref-1"


def test_live_service_yields_no_confirmation() -> None:
    prober = _prober(200, "<html>a real site</html>")
    result = detect_subdomain_takeover(prober, sentinel=_S3_MARKER)
    assert result.confirmed is False


def test_non_2xx_response_yields_no_confirmation_even_with_marker_text() -> None:
    prober = _prober(404, _S3_MARKER)
    result = detect_subdomain_takeover(prober, sentinel=_S3_MARKER)
    assert result.confirmed is False
