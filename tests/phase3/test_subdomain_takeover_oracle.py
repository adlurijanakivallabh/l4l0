"""Subdomain takeover — STRUCTURAL SUBDOMAIN_TAKEOVER decide() branch tests (§7).

Oracle-level only; the detector/driver tests live in
tests/phase3/test_subdomain_takeover.py and
tests/scan/test_subdomain_takeover_driver.py.
"""

from __future__ import annotations

from reachagent.graph.nodes import FindingStatus
from reachagent.oracles.structural import StructuralCheckType, StructuralEvidence, decide

_MARKER = "The specified bucket does not exist"


def _evidence(
    probe_status: int = 0, response_body: str = "", sentinel: str = _MARKER
) -> StructuralEvidence:
    return StructuralEvidence(
        check_type=StructuralCheckType.SUBDOMAIN_TAKEOVER,
        probe_status=probe_status,
        sentinel=sentinel,
        response_body=response_body,
    )


def test_marker_in_successful_response_is_violation() -> None:
    body = f"<Error><Code>NoSuchBucket</Code><Message>{_MARKER}</Message></Error>"
    evidence = _evidence(probe_status=200, response_body=body)
    assert decide(evidence) is FindingStatus.CONFIRMED_VIOLATION


def test_no_marker_is_inconclusive() -> None:
    assert (
        decide(_evidence(probe_status=200, response_body="<html>a real site</html>"))
        is FindingStatus.INCONCLUSIVE
    )


def test_non_2xx_status_is_inconclusive_even_with_marker_text() -> None:
    # A 404/5xx proves nothing about claim state on its own — only a
    # successfully-rendered unclaimed-service page is decisive.
    assert decide(_evidence(probe_status=404, response_body=_MARKER)) is FindingStatus.INCONCLUSIVE


def test_missing_sentinel_is_inconclusive() -> None:
    assert (
        decide(_evidence(probe_status=200, response_body="anything", sentinel=""))
        is FindingStatus.INCONCLUSIVE
    )
