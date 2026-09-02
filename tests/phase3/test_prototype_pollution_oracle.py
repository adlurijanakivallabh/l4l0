"""Prototype pollution — STRUCTURAL PROTOTYPE_POLLUTION decide() branch (§7, v2 W9).

Oracle-level only; the live browser driver lives in scan/prototype_pollution.py and is
tested via a fake BrowserDriver in tests/scan/test_prototype_pollution.py.
"""

from __future__ import annotations

from reachagent.graph.nodes import FindingStatus
from reachagent.oracles.structural import StructuralCheckType, StructuralEvidence, decide


def _evidence(probe_status: int = 0, polluted: bool = False) -> StructuralEvidence:
    return StructuralEvidence(
        check_type=StructuralCheckType.PROTOTYPE_POLLUTION,
        probe_status=probe_status,
        polluted=polluted,
    )


def test_marker_present_after_a_decisive_2xx_load_is_violation() -> None:
    assert decide(_evidence(probe_status=200, polluted=True)) is FindingStatus.CONFIRMED_VIOLATION


def test_marker_absent_after_a_decisive_2xx_load_is_confirmed_denied() -> None:
    # A genuine negative observation — the page loaded and we directly checked; not
    # ambiguous, so it must NOT be INCONCLUSIVE (that would wrongly imply "couldn't tell").
    assert decide(_evidence(probe_status=200, polluted=False)) is FindingStatus.CONFIRMED_DENIED


def test_non_2xx_load_is_inconclusive_even_if_polluted_somehow_true() -> None:
    # The page's client-side merge logic may never have run at all on an error page —
    # a non-2xx load proves nothing either way.
    assert decide(_evidence(probe_status=500, polluted=True)) is FindingStatus.INCONCLUSIVE
    assert decide(_evidence(probe_status=404, polluted=False)) is FindingStatus.INCONCLUSIVE


def test_evidence_rejects_a_non_bool_polluted_field() -> None:
    import pytest

    with pytest.raises(TypeError, match="polluted must be a boolean"):
        decide(
            StructuralEvidence(
                check_type=StructuralCheckType.PROTOTYPE_POLLUTION,
                probe_status=200,
                polluted="yes",  # type: ignore[arg-type]
            )
        )
