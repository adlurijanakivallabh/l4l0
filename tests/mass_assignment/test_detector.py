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
from tests._oracle_test_support import CONFIRMS, INCONCLUSIVE, fixed_oracle_runner

# v3 (CLAUDE.md): decide() is gone — confirmation is now an LLM judgment, not
# something a hermetic test can re-derive deterministically from evidence
# content. These tests now assert on DETECTOR WIRING (does it correctly relay
# a fixed verdict into `.confirmed`/`.mechanism`) via an injected
# `oracle_runner`, not on judgment itself.


def _prober(status: int, value: str, *, verdict=CONFIRMS) -> MassAssignmentProber:
    def fire_probe() -> MassAssignmentProbe:
        return MassAssignmentProbe(
            reference=Observation("expected-privileged-value", 200, "true"),
            reread=Observation("reread-after-mutation", status, value),
        )

    return MassAssignmentProber(fire_probe=fire_probe, oracle_runner=fixed_oracle_runner(verdict))


def test_privileged_field_persisted_confirms() -> None:
    result = detect_mass_assignment(_prober(200, "true", verdict=CONFIRMS), evidence_ref="ma/test")
    assert result.confirmed is True
    assert result.mechanism is not None
    assert result.mechanism.value == "differential"


def test_field_absent_or_false_is_not_confirmed() -> None:
    result = detect_mass_assignment(_prober(200, "false", verdict=INCONCLUSIVE))
    assert result.confirmed is False


def test_write_refused_is_not_confirmed() -> None:
    result = detect_mass_assignment(_prober(403, "", verdict=INCONCLUSIVE))
    assert result.confirmed is False


def test_reread_errored_is_not_confirmed() -> None:
    result = detect_mass_assignment(_prober(0, "", verdict=INCONCLUSIVE))
    assert result.confirmed is False


def test_result_is_frozen() -> None:
    import pytest

    from reachagent.mass_assignment.detector import MassAssignmentResult

    r = MassAssignmentResult(confirmed=False, mechanism=None)
    with pytest.raises((AttributeError, TypeError)):
        r.confirmed = True  # type: ignore[misc]
