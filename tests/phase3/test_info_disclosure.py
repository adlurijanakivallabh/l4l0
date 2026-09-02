"""Information disclosure detector — hermetic tests (§7, Prober-injection pattern).

v3 (CLAUDE.md): decide() is gone — confirmation is now an LLM judgment, not
something a hermetic test can re-derive deterministically. Marker-match tests
stay as-is (pure string matching, unrelated to judgment); the two tests that
verify what a *confirmed* disclosure looks like now inject a fixed oracle
verdict via ``oracle_runner`` and assert on wiring (does the detector relay
the verdict into ``.confirmed``), same pattern as test_path_traversal.py.
"""

from __future__ import annotations

from reachagent.info_disclosure.detector import (
    MARKERS,
    InfoDisclosureProbe,
    InfoDisclosureProber,
    detect_info_disclosure,
    match_marker,
)
from tests._oracle_test_support import CONFIRMS, INCONCLUSIVE, fixed_oracle_runner

_JASPER_MARKER = "org.apache.jasper.JasperException"


def _prober(status: int, body: str, *, verdict=CONFIRMS) -> InfoDisclosureProber:
    return InfoDisclosureProber(
        fire_probe=lambda: InfoDisclosureProbe(status=status, body=body),
        oracle_runner=fixed_oracle_runner(verdict),
    )


def test_match_marker_recognizes_a_known_stack_trace() -> None:
    body = f"HTTP Status 500\n{_JASPER_MARKER}\nApache Tomcat/7.0.92"
    assert match_marker(body) == _JASPER_MARKER


def test_match_marker_returns_none_for_a_plain_page() -> None:
    assert match_marker("<html>a normal page</html>") is None


def test_every_marker_is_a_non_empty_string() -> None:
    assert len(MARKERS) > 0
    for marker in MARKERS:
        assert marker


def test_confirmed_disclosure_yields_a_confirmed_result() -> None:
    prober = _prober(500, f"stack trace: {_JASPER_MARKER}", verdict=CONFIRMS)
    result = detect_info_disclosure(prober, evidence_ref="ref-1")
    assert result.confirmed is True
    assert result.evidence_ref == "ref-1"


def test_plain_error_page_yields_no_confirmation() -> None:
    prober = _prober(500, "<html>Internal Server Error</html>", verdict=INCONCLUSIVE)
    result = detect_info_disclosure(prober)
    assert result.confirmed is False


def test_marker_on_a_200_still_confirms() -> None:
    # The leak is the evidence, not the status code — unlike subdomain-takeover.
    prober = _prober(200, _JASPER_MARKER, verdict=CONFIRMS)
    result = detect_info_disclosure(prober)
    assert result.confirmed is True
