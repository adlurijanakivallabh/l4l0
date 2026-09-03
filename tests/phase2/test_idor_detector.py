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


# --- Technique-diversity corroboration (v3 V3): a third identity's write ----


class _SequencedRunner:
    """Returns a different fixed verdict on each successive call."""

    def __init__(self, verdicts: list) -> None:
        self._verdicts = list(verdicts)

    def __call__(self, mechanism, evidence):  # noqa: ANN001
        return fixed_oracle_runner(self._verdicts.pop(0))(mechanism, evidence)


def test_no_second_probe_configured_is_byte_for_byte_unchanged() -> None:
    result = detect_idor(_prober(200, status=CONFIRMS), evidence_ref="idor/single")
    assert result.confirmed is True
    assert result.corroborated is False


def test_second_identity_write_also_succeeding_corroborates() -> None:
    runner = _SequencedRunner([CONFIRMS, CONFIRMS])
    prober = IdorProber(
        fire_probe=lambda: IdorProbe(non_owner_status=200),
        fire_second_probe=lambda: IdorProbe(non_owner_status=200),
        oracle_runner=runner,
    )
    result = detect_idor(prober, evidence_ref="idor/corroborated")
    assert result.confirmed is True
    assert result.corroborated is True


def test_second_identity_write_refused_fails_closed() -> None:
    """A confirmed first non-owner write whose second, independent identity's
    write is refused must NOT confirm — never fall back to trusting the
    uncorroborated single write (the first non-owner session may simply have
    its own unrelated delegated access to this one object)."""
    runner = _SequencedRunner([CONFIRMS, DENIES])
    prober = IdorProber(
        fire_probe=lambda: IdorProbe(non_owner_status=200),
        fire_second_probe=lambda: IdorProbe(non_owner_status=403),
        oracle_runner=runner,
    )
    result = detect_idor(prober, evidence_ref="idor/contradicted")
    assert result.confirmed is False
    assert result.corroborated is False


def test_second_probe_never_fired_when_primary_does_not_confirm() -> None:
    calls = {"n": 0}

    def _second() -> IdorProbe:
        calls["n"] += 1
        return IdorProbe(non_owner_status=200)

    prober = IdorProber(
        fire_probe=lambda: IdorProbe(non_owner_status=403),
        fire_second_probe=_second,
        oracle_runner=fixed_oracle_runner(DENIES),
    )
    result = detect_idor(prober, evidence_ref="idor/no-primary")
    assert result.confirmed is False
    assert calls["n"] == 0  # no wasted extra mutation confirming a negative
