"""Tests for ScopeGuard decisions."""

from __future__ import annotations

import pytest

from lalo.core.errors import TargetOutOfScopeError
from lalo.execution.scope import Decision, ScopeGuard
from lalo.execution.target import Engagement


def _guard(**kwargs: object) -> ScopeGuard:
    eng = Engagement.from_specs(["example.com", "*.example.com"])
    # Fake resolver: engagement hosts resolve to a benign public IP, never metadata.
    return ScopeGuard(engagement=eng, resolver=lambda h: frozenset({"93.184.216.34"}), **kwargs)  # type: ignore[arg-type]


def test_in_engagement_allowed() -> None:
    assert _guard().check("https://app.example.com/login").decision is Decision.ALLOWED


def test_out_of_engagement_skipped_by_default() -> None:
    d = _guard().check("https://evil.com/x")
    assert d.decision is Decision.SKIPPED
    assert d.reason == "out_of_engagement"


def test_out_of_engagement_denied_with_egress_lock() -> None:
    d = _guard(egress_lock=True).check("https://evil.com/x")
    assert d.decision is Decision.DENIED


def test_metadata_literal_ip_denied() -> None:
    assert _guard().check("http://169.254.169.254/latest/meta-data/").decision is Decision.DENIED


def test_metadata_via_resolution_denied() -> None:
    eng = Engagement.from_specs(["metadata.internal"])
    guard = ScopeGuard(engagement=eng, resolver=lambda h: frozenset({"169.254.169.254"}))
    assert guard.check("http://metadata.internal/").decision is Decision.DENIED


def test_enforce_raises_on_denied() -> None:
    with pytest.raises(TargetOutOfScopeError):
        _guard(egress_lock=True).enforce("https://evil.com/")


def test_resolve_and_pin_caches() -> None:
    calls = {"n": 0}

    def resolver(host: str) -> frozenset[str]:
        calls["n"] += 1
        return frozenset({"93.184.216.34"})

    eng = Engagement.from_specs(["example.com"])
    guard = ScopeGuard(engagement=eng, resolver=resolver)
    guard.resolve_and_pin("example.com")
    guard.resolve_and_pin("example.com")
    assert calls["n"] == 1
