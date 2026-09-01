"""Default credentials — STRUCTURAL DEFAULT_CREDENTIALS decide() branch tests (§7).

Oracle-level only; the detector/driver tests live in
tests/scan/test_default_credentials_driver.py.
"""

from __future__ import annotations

from reachagent.graph.nodes import FindingStatus
from reachagent.oracles.structural import StructuralCheckType, StructuralEvidence, decide


def _evidence(probe_status: int = 200, session_captured: bool = False) -> StructuralEvidence:
    return StructuralEvidence(
        check_type=StructuralCheckType.DEFAULT_CREDENTIALS,
        probe_status=probe_status,
        session_captured=session_captured,
    )


def test_captured_session_on_success_status_is_violation() -> None:
    assert (
        decide(_evidence(probe_status=200, session_captured=True))
        is FindingStatus.CONFIRMED_VIOLATION
    )


def test_no_session_material_is_denied_not_inconclusive() -> None:
    # A decisive rejection (the pair simply doesn't work) is a real denial,
    # not an unknown outcome.
    assert (
        decide(_evidence(probe_status=200, session_captured=False))
        is FindingStatus.CONFIRMED_DENIED
    )


def test_error_status_is_inconclusive_even_with_session_flag_set() -> None:
    assert decide(_evidence(probe_status=500, session_captured=True)) is FindingStatus.INCONCLUSIVE
