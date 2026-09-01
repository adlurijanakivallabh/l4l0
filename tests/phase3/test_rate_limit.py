"""Rate-limit-absence detector — hermetic tests (§7, Prober-injection pattern).

Uses the real default registry runner (no validator import, no fake oracle) —
same pattern as test_subdomain_takeover.py. The oracle's own decide() branch
is covered separately in test_rate_limit_oracle.py.
"""

from __future__ import annotations

from reachagent.rate_limit.detector import (
    LOCKOUT_MARKERS,
    RateLimitProbe,
    RateLimitProber,
    detect_rate_limit_absence,
    has_lockout_signal,
)


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

    prober = RateLimitProber(fire_attempt=fire_attempt)
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
