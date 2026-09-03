"""Rate-limit-absence detector — hermetic tests (§7, Prober-injection pattern).

v3 (CLAUDE.md): decide() is gone — confirmation is now an LLM judgment, not
something a hermetic test can re-derive deterministically. The "no lockout
signal across a full burst" case now asserts on DETECTOR WIRING (does it
correctly relay a fixed verdict into `.confirmed`) via an injected
`oracle_runner`, matching tests/phase3/test_path_traversal.py. The other
cases here never reach a violation verdict either way (no lockout signal to
judge, or an incomplete burst), so they still pass against the real default
registry runner unchanged.
"""

from __future__ import annotations

import reachagent.rate_limit.detector as rate_limit_detector
from reachagent.rate_limit.detector import (
    LOCKOUT_MARKERS,
    RateLimitProbe,
    RateLimitProber,
    detect_rate_limit_absence,
    has_lockout_signal,
)
from tests._oracle_test_support import CONFIRMS, INCONCLUSIVE, fixed_oracle_runner


def test_has_lockout_signal_on_429_status() -> None:
    assert has_lockout_signal(429, "") is True


def test_has_lockout_signal_on_known_body_marker() -> None:
    assert has_lockout_signal(401, "Error: too many attempts, try again later") is True


def test_has_lockout_signal_false_on_plain_rejection() -> None:
    assert has_lockout_signal(401, "invalid username or password") is False


def test_every_marker_is_a_non_empty_string() -> None:
    assert len(LOCKOUT_MARKERS) > 0
    for marker in LOCKOUT_MARKERS:
        assert marker


def test_no_lockout_across_full_burst_confirms_absence() -> None:
    def fire_attempt(_i: int) -> RateLimitProbe:
        return RateLimitProbe(status=401, body="invalid credentials")

    prober = RateLimitProber(fire_attempt=fire_attempt, oracle_runner=fixed_oracle_runner(CONFIRMS))
    result = detect_rate_limit_absence(prober, evidence_ref="ref-1")
    assert result.confirmed is True
    assert result.attempts_completed == 6
    assert result.evidence_ref == "ref-1"


def test_lockout_partway_through_burst_yields_no_confirmation() -> None:
    calls = {"n": 0}

    def fire_attempt(_i: int) -> RateLimitProbe:
        calls["n"] += 1
        if calls["n"] >= 3:
            return RateLimitProbe(status=429, body="too many requests")
        return RateLimitProbe(status=401, body="invalid credentials")

    prober = RateLimitProber(fire_attempt=fire_attempt)
    result = detect_rate_limit_absence(prober)
    assert result.confirmed is False


def test_transport_failure_mid_burst_yields_no_confirmation() -> None:
    calls = {"n": 0}

    def fire_attempt(_i: int) -> RateLimitProbe:
        calls["n"] += 1
        if calls["n"] >= 2:
            raise ConnectionError("boom")
        return RateLimitProbe(status=401, body="invalid credentials")

    prober = RateLimitProber(fire_attempt=fire_attempt)
    result = detect_rate_limit_absence(prober)
    assert result.confirmed is False
    assert result.attempts_completed == 1


class _SequencedRunner:
    """Returns a different fixed verdict on each successive call — lets a
    test give the first burst and the corroborating second burst distinct
    verdicts, matching tests/phase3/test_cache_poisoning.py's own pattern."""

    def __init__(self, verdicts: list) -> None:
        self._verdicts = list(verdicts)

    def __call__(self, mechanism, evidence):  # noqa: ANN001
        return fixed_oracle_runner(self._verdicts.pop(0))(mechanism, evidence)


def _no_lockout_attempt(_i: int) -> RateLimitProbe:
    return RateLimitProbe(status=401, body="invalid credentials")


def test_no_fire_second_attempt_is_byte_for_byte_unchanged() -> None:
    """Omitting fire_second_attempt (the default) never even looks at corroborated."""
    prober = RateLimitProber(
        fire_attempt=_no_lockout_attempt, oracle_runner=fixed_oracle_runner(CONFIRMS)
    )
    result = detect_rate_limit_absence(prober, evidence_ref="ref-plain")
    assert result.confirmed is True
    assert result.corroborated is False


def test_second_burst_never_fires_when_primary_does_not_confirm() -> None:
    def _fail_if_called(_i: int) -> RateLimitProbe:
        raise AssertionError("second burst must not fire when the primary never confirmed")

    prober = RateLimitProber(
        fire_attempt=_no_lockout_attempt,
        oracle_runner=fixed_oracle_runner(INCONCLUSIVE),
        fire_second_attempt=_fail_if_called,
    )
    result = detect_rate_limit_absence(prober)
    assert result.confirmed is False
    assert result.corroborated is False


def test_corroboration_confirms_when_second_burst_also_shows_no_lockout(monkeypatch) -> None:  # noqa: ANN001
    monkeypatch.setattr(rate_limit_detector, "_COOLDOWN_S", 0.0)
    prober = RateLimitProber(
        fire_attempt=_no_lockout_attempt,
        oracle_runner=_SequencedRunner([CONFIRMS, CONFIRMS]),
        fire_second_attempt=_no_lockout_attempt,
    )
    result = detect_rate_limit_absence(prober, evidence_ref="ref-corroborated")
    assert result.confirmed is True
    assert result.corroborated is True


def test_corroboration_fails_closed_when_second_burst_shows_lockout(monkeypatch) -> None:  # noqa: ANN001
    """A second burst that DOES show a lockout signal contradicts the first —
    fails closed to not-confirmed, never falls back to the uncorroborated
    primary result."""
    monkeypatch.setattr(rate_limit_detector, "_COOLDOWN_S", 0.0)

    def _second_attempt_with_lockout(_i: int) -> RateLimitProbe:
        return RateLimitProbe(status=429, body="too many requests")

    prober = RateLimitProber(
        fire_attempt=_no_lockout_attempt,
        oracle_runner=_SequencedRunner([CONFIRMS, INCONCLUSIVE]),
        fire_second_attempt=_second_attempt_with_lockout,
    )
    result = detect_rate_limit_absence(prober)
    assert result.confirmed is False
    assert result.corroborated is False
