"""Pure-oracle unit tests for mass-assignment detection (§7, §9).

Mirrors tests/phase3/test_nosql_detection.py's style: in-memory Observation
fakes, no firer, no network — the exhaustive small decision table.
"""

from __future__ import annotations

from reachagent.mass_assignment.detector import (
    MassAssignmentProbe,
    MassAssignmentProber,
    detect_mass_assignment,
)
from reachagent.oracles.differential import Observation


def _prober(status: int, value: str) -> MassAssignmentProber:
    def fire_probe() -> MassAssignmentProbe:
        return MassAssignmentProbe(
            reference=Observation("expected-privileged-value", 200, "true"),
            reread=Observation("reread-after-mutation", status, value),
        )

    return MassAssignmentProber(fire_probe=fire_probe)


def test_privileged_field_persisted_confirms() -> None:
    result = detect_mass_assignment(_prober(200, "true"), evidence_ref="ma/test")
    assert result.confirmed is True
    assert result.mechanism is not None
    assert result.mechanism.value == "differential"


def test_field_absent_or_false_is_not_confirmed() -> None:
    result = detect_mass_assignment(_prober(200, "false"))
    assert result.confirmed is False


def test_write_refused_is_not_confirmed() -> None:
    result = detect_mass_assignment(_prober(403, ""))
    assert result.confirmed is False


def test_reread_errored_is_not_confirmed() -> None:
    result = detect_mass_assignment(_prober(0, ""))
    assert result.confirmed is False


def test_result_is_frozen() -> None:
    import pytest

    from reachagent.mass_assignment.detector import MassAssignmentResult

    r = MassAssignmentResult(confirmed=False, mechanism=None)
    with pytest.raises((AttributeError, TypeError)):
        r.confirmed = True  # type: ignore[misc]
