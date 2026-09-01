"""Rate-limit absence — STRUCTURAL RATE_LIMIT_ABSENT decide() branch tests (§7).

Oracle-level only; the detector/driver tests live in
tests/phase3/test_rate_limit.py and
tests/scan/test_rate_limit_absence_driver.py.
"""

from __future__ import annotations

from reachagent.graph.nodes import FindingStatus
from reachagent.oracles.structural import StructuralCheckType, StructuralEvidence, decide


def _evidence(
    attempts_planned: int = 6, attempts_completed: int = 6, lockout_signal_observed: bool = False
) -> StructuralEvidence:
    return StructuralEvidence(
        check_type=StructuralCheckType.RATE_LIMIT_ABSENT,
        attempts_planned=attempts_planned,
        attempts_completed=attempts_completed,
        lockout_signal_observed=lockout_signal_observed,
    )


def test_complete_burst_with_no_lockout_signal_is_violation() -> None:
    assert decide(_evidence()) is FindingStatus.CONFIRMED_VIOLATION


def test_lockout_signal_observed_is_denied() -> None:
    assert decide(_evidence(lockout_signal_observed=True)) is FindingStatus.CONFIRMED_DENIED


def test_incomplete_burst_is_inconclusive_never_a_manufactured_violation() -> None:
    assert decide(_evidence(attempts_planned=6, attempts_completed=3)) is FindingStatus.INCONCLUSIVE


def test_zero_planned_attempts_is_inconclusive() -> None:
    assert decide(_evidence(attempts_planned=0, attempts_completed=0)) is FindingStatus.INCONCLUSIVE
