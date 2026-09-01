"""Information disclosure — STRUCTURAL INFO_DISCLOSURE decide() branch tests (§7).

Oracle-level only; the detector/driver tests live in
tests/phase3/test_info_disclosure.py and
tests/scan/test_info_disclosure_reconfirm.py.
"""

from __future__ import annotations

from reachagent.graph.nodes import FindingStatus
from reachagent.oracles.structural import StructuralCheckType, StructuralEvidence, decide

_MARKER = "org.apache.jasper.JasperException"


def _evidence(
    probe_status: int = 0, response_body: str = "", sentinel: str = _MARKER
) -> StructuralEvidence:
    return StructuralEvidence(
        check_type=StructuralCheckType.INFO_DISCLOSURE,
        probe_status=probe_status,
        sentinel=sentinel,
        response_body=response_body,
    )


def test_marker_in_response_is_violation() -> None:
    body = f"HTTP Status 500 - Internal Server Error\n{_MARKER}\nApache Tomcat/7.0.92"
    evidence = _evidence(probe_status=500, response_body=body)
    assert decide(evidence) is FindingStatus.CONFIRMED_VIOLATION


def test_marker_present_regardless_of_status_code() -> None:
    # Unlike subdomain-takeover, the marker itself is the evidence — a 200 or
    # 404 carrying a stack trace is just as much a leak as a 500 carrying one.
    violation = FindingStatus.CONFIRMED_VIOLATION
    assert decide(_evidence(probe_status=200, response_body=_MARKER)) is violation
    assert decide(_evidence(probe_status=404, response_body=_MARKER)) is violation


def test_no_marker_is_inconclusive() -> None:
    assert (
        decide(_evidence(probe_status=500, response_body="<html>a plain error page</html>"))
        is FindingStatus.INCONCLUSIVE
    )


def test_missing_sentinel_is_inconclusive() -> None:
    assert (
        decide(_evidence(probe_status=500, response_body="anything", sentinel=""))
        is FindingStatus.INCONCLUSIVE
    )
