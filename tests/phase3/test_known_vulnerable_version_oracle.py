"""Known-vulnerable-version — STRUCTURAL KNOWN_VULNERABLE_VERSION decide() branch (§7).

Oracle-level only; the CVE-intel client/detector tests live in
tests/cve_intel/.
"""

from __future__ import annotations

from reachagent.graph.nodes import FindingStatus
from reachagent.oracles.structural import StructuralCheckType, StructuralEvidence, decide

_VERSION = "Apache Tomcat/7.0.92"


def _evidence(
    probe_status: int = 0, response_body: str = "", sentinel: str = _VERSION
) -> StructuralEvidence:
    return StructuralEvidence(
        check_type=StructuralCheckType.KNOWN_VULNERABLE_VERSION,
        probe_status=probe_status,
        sentinel=sentinel,
        response_body=response_body,
    )


def test_version_string_present_in_2xx_response_is_violation() -> None:
    body = f"<html><body>Welcome — {_VERSION}</body></html>"
    result = decide(_evidence(probe_status=200, response_body=body))
    assert result is FindingStatus.CONFIRMED_VIOLATION


def test_version_string_present_on_error_page_is_still_a_violation() -> None:
    # Deliberately no status-code gate: a version banner on a 404/500 error
    # page is just as real as one on a 2xx.
    body = f"<h1>404 Not Found</h1><address>{_VERSION}</address>"
    result = decide(_evidence(probe_status=404, response_body=body))
    assert result is FindingStatus.CONFIRMED_VIOLATION


def test_version_string_absent_is_inconclusive() -> None:
    body = "<html><body>Welcome</body></html>"
    assert decide(_evidence(probe_status=200, response_body=body)) is FindingStatus.INCONCLUSIVE


def test_missing_sentinel_is_inconclusive() -> None:
    assert (
        decide(_evidence(probe_status=200, response_body="anything", sentinel=""))
        is FindingStatus.INCONCLUSIVE
    )
