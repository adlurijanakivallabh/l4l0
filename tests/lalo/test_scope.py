"""Tests for ScopeGuard decisions, including the pinned-IP dial mechanism."""

from __future__ import annotations

import pytest

from lalo.core.errors import TargetOutOfScopeError
from lalo.execution.scope import Decision, ScopeGuard
from lalo.execution.target import Engagement


def _guard(**kwargs: object) -> ScopeGuard:
    eng = Engagement.from_specs(["example.com", "*.example.com"])
    return ScopeGuard(engagement=eng, resolver=lambda h: frozenset({"93.184.216.34"}), **kwargs)  # type: ignore[arg-type]


def test_in_engagement_allowed() -> None:
    assert _guard().check("https://app.example.com/login").decision is Decision.ALLOWED


def test_out_of_engagement_skipped_by_default() -> None:
    d = _guard().check("https://evil.com/x")
    assert d.decision is Decision.SKIPPED
    assert d.reason == "out_of_engagement"


def test_out_of_engagement_denied_with_egress_lock() -> None:
    assert _guard(egress_lock=True).check("https://evil.com/x").decision is Decision.DENIED


def test_metadata_literal_ip_denied() -> None:
    assert _guard().check("http://169.254.169.254/latest/meta-data/").decision is Decision.DENIED


def test_metadata_hostname_denied_regardless_of_resolution() -> None:
    # A metadata HOSTNAME is denied even if it happens to resolve to a benign IP —
    # a name can point anywhere; block the well-known ones outright.
    guard = ScopeGuard(
        engagement=Engagement.from_specs(["metadata.google.internal"]),
        resolver=lambda h: frozenset({"10.0.0.5"}),
    )
    assert guard.check("http://metadata.google.internal/x").decision is Decision.DENIED


def test_metadata_via_resolution_denied() -> None:
    eng = Engagement.from_specs(["metadata.internal"])
    guard = ScopeGuard(engagement=eng, resolver=lambda h: frozenset({"169.254.169.254"}))
    assert guard.check("http://metadata.internal/").decision is Decision.DENIED


def test_non_http_scheme_denied() -> None:
    assert _guard().check("file:///etc/passwd").decision is Decision.DENIED
    assert _guard().check("gopher://example.com/x").decision is Decision.DENIED


def test_local_lab_target_allowed_no_blanket_private_ip_block() -> None:
    # Deliberate divergence from a general-purpose fetch tool's default-deny-
    # private-ranges policy: L4L0 must be able to test local lab targets.
    guard = ScopeGuard(
        engagement=Engagement.from_specs(["127.0.0.1"]), resolver=lambda h: frozenset({"127.0.0.1"})
    )
    assert guard.check("http://127.0.0.1:5000/").decision is Decision.ALLOWED


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


def test_pin_for_connect_uses_the_same_cached_resolution_as_the_scope_check() -> None:
    # The load-bearing DNS-rebinding defense: the scope check and the actual
    # dial must agree on the SAME resolved IP, from one cached resolution.
    guard = _guard()
    guard.check("https://app.example.com/")  # triggers resolve_and_pin internally
    assert guard.pin_for_connect("app.example.com") == "93.184.216.34"


def test_pin_for_connect_literal_ip_passthrough() -> None:
    guard = _guard()
    assert guard.pin_for_connect("10.1.2.3") == "10.1.2.3"


def test_pin_for_connect_returns_none_on_resolution_failure() -> None:
    guard = ScopeGuard(
        engagement=Engagement.from_specs(["nowhere.invalid"]), resolver=lambda h: frozenset()
    )
    assert guard.pin_for_connect("nowhere.invalid") is None
