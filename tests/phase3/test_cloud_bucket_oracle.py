"""Cloud bucket exposure — STRUCTURAL CLOUD_BUCKET_EXPOSURE decide() branch tests (§7).

Oracle-level only; the detector/driver tests live in
tests/phase3/test_cloud_bucket.py and
tests/scan/test_cloud_bucket_driver.py.
"""

from __future__ import annotations

from reachagent.graph.nodes import FindingStatus
from reachagent.oracles.structural import StructuralCheckType, StructuralEvidence, decide

_MARKER = "<ListBucketResult"


def _evidence(
    probe_status: int = 0, response_body: str = "", sentinel: str = _MARKER
) -> StructuralEvidence:
    return StructuralEvidence(
        check_type=StructuralCheckType.CLOUD_BUCKET_EXPOSURE,
        probe_status=probe_status,
        sentinel=sentinel,
        response_body=response_body,
    )


def test_marker_in_successful_response_is_violation() -> None:
    body = f"<?xml version='1.0'?>{_MARKER}<Name>bucket</Name></ListBucketResult>"
    evidence = _evidence(probe_status=200, response_body=body)
    assert decide(evidence) is FindingStatus.CONFIRMED_VIOLATION


def test_no_marker_is_inconclusive() -> None:
    body = "<Error><Code>AccessDenied</Code></Error>"
    assert decide(_evidence(probe_status=200, response_body=body)) is FindingStatus.INCONCLUSIVE


def test_non_2xx_status_is_inconclusive_even_with_marker_text() -> None:
    assert decide(_evidence(probe_status=403, response_body=_MARKER)) is FindingStatus.INCONCLUSIVE


def test_missing_sentinel_is_inconclusive() -> None:
    assert (
        decide(_evidence(probe_status=200, response_body="anything", sentinel=""))
        is FindingStatus.INCONCLUSIVE
    )
