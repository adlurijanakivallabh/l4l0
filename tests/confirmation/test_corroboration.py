"""Multi-shot corroboration — hermetic tests (Build Order 5)."""

from __future__ import annotations

import pytest

from reachagent.confirmation.corroboration import corroborate


def test_stops_early_once_required_agreements_reached() -> None:
    calls = {"n": 0}

    def always_agree() -> bool:
        calls["n"] += 1
        return True

    result = corroborate(always_agree, required_agreements=1, max_attempts=3)
    assert result.corroborated is True
    assert result.attempts == 1  # stopped immediately, no wasted extra calls
    assert calls["n"] == 1


def test_requires_the_configured_number_of_agreements() -> None:
    result = corroborate(lambda: True, required_agreements=2, max_attempts=3)
    assert result.corroborated is True
    assert result.attempts == 2
    assert result.agreements == 2


def test_never_agreeing_exhausts_max_attempts_without_corroborating() -> None:
    calls = {"n": 0}

    def never_agree() -> bool:
        calls["n"] += 1
        return False

    result = corroborate(never_agree, required_agreements=2, max_attempts=3)
    assert result.corroborated is False
    assert result.agreements == 0
    assert result.attempts == 3
    assert calls["n"] == 3  # the explicit cap is honored, never exceeded


def test_a_one_off_flaky_agreement_does_not_corroborate() -> None:
    # First call agrees, rest don't -- exactly the observed live shape
    # (a genuine, confirmed live scan false positive under system load).
    calls = {"n": 0}

    def flaky() -> bool:
        calls["n"] += 1
        return calls["n"] == 1

    result = corroborate(flaky, required_agreements=2, max_attempts=3)
    assert result.corroborated is False
    assert result.agreements == 1


def test_max_attempts_is_never_exceeded_even_with_intermittent_agreement() -> None:
    calls = {"n": 0}

    def sometimes() -> bool:
        calls["n"] += 1
        return calls["n"] == 2  # agrees only on attempt 2, never enough alone

    result = corroborate(sometimes, required_agreements=3, max_attempts=3)
    assert result.corroborated is False
    assert result.attempts == 3
    assert calls["n"] == 3


def test_max_attempts_below_one_is_rejected() -> None:
    with pytest.raises(ValueError, match="max_attempts"):
        corroborate(lambda: True, max_attempts=0)


def test_required_agreements_above_max_attempts_is_rejected() -> None:
    with pytest.raises(ValueError, match="required_agreements"):
        corroborate(lambda: True, required_agreements=5, max_attempts=3)


def test_required_agreements_below_one_is_rejected() -> None:
    with pytest.raises(ValueError, match="required_agreements"):
        corroborate(lambda: True, required_agreements=0, max_attempts=3)


def test_default_max_attempts_is_a_small_explicit_cap() -> None:
    # The cap exists to catch a one-off flaky signal, never to let an
    # ambiguous candidate be probed indefinitely.
    calls = {"n": 0}

    def never_agree() -> bool:
        calls["n"] += 1
        return False

    corroborate(never_agree, required_agreements=1)
    assert calls["n"] <= 3
