"""Pure-oracle unit tests for cross-identity IDOR-via-write detection (§7, §9).

Sibling to bola/detector.py's own tests — does not touch bola.detector at
all, so the enumerable/disclosed precondition tests in
test_bola_enables_precondition.py stay exactly as they were. Mirrors
tests/mass_assignment/test_detector.py's style: in-memory fakes, no firer,
no network.
"""

from __future__ import annotations

from reachagent.bola.idor_detector import IdorProbe, IdorProber, detect_idor
from tests._oracle_test_support import CONFIRMS, DENIES, INCONCLUSIVE, fixed_oracle_runner

# v3 (CLAUDE.md): decide() is gone — confirmation is now an LLM judgment, not
# something a hermetic test can re-derive deterministically. These tests now
# assert on DETECTOR WIRING (does it correctly relay a fixed verdict into
# `.confirmed`) via an injected `oracle_runner`, not on judgment itself.


def _prober(non_owner_status: int, *, status=CONFIRMS) -> IdorProber:
    return IdorProber(
        fire_probe=lambda: IdorProbe(non_owner_status=non_owner_status),
        oracle_runner=fixed_oracle_runner(status),
    )


def test_non_owner_write_succeeding_confirms() -> None:
    result = detect_idor(_prober(200, status=CONFIRMS), evidence_ref="idor/1")
    assert result.confirmed is True


def test_non_owner_write_refused_is_denied() -> None:
    result = detect_idor(_prober(403, status=DENIES))
    assert result.confirmed is False


def test_non_owner_write_not_found_is_denied() -> None:
    result = detect_idor(_prober(404, status=DENIES))
    assert result.confirmed is False


def test_non_owner_write_server_error_is_inconclusive() -> None:
    result = detect_idor(_prober(500, status=INCONCLUSIVE))
    assert result.confirmed is False


def test_no_content_write_also_confirms() -> None:
    # A 204 No Content is still a successful write — the object was mutated.
    result = detect_idor(_prober(204, status=CONFIRMS))
    assert result.confirmed is True
