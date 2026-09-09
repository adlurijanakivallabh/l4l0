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


def test_scheme_neutral_checks_are_engagement_only_not_scheme_restricted() -> None:
    """tcp:// (raw_tcp) and dns:// (dns_query) reuse this same check() for a
    plain hostname with no real URL scheme of its own - neither should be
    rejected as an unrecognized scheme the way file:// genuinely is."""
    assert _guard().check("tcp://app.example.com:22").decision is Decision.ALLOWED
    assert _guard().check("dns://app.example.com").decision is Decision.ALLOWED


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


def test_resolve_and_pin_is_thread_safe_under_concurrent_first_resolution() -> None:
    """Regression: an unsynchronized check-then-set let two threads missing
    the cache for the SAME host at once each call the resolver, with the
    last writer winning - one ScopeGuard is shared for the whole scan, and
    fire_concurrent/spawn_agents can genuinely race a first resolution this
    way. That breaks the check==dial identity the DNS-rebinding defense
    depends on: check() could validate one thread's resolved IP while
    pin_for_connect() (reading the now-overwritten cache) actually dials a
    DIFFERENT one a racing thread resolved. Every concurrent caller must
    see exactly one real resolution and the identical resulting value."""
    import threading

    call_count = {"n": 0}
    count_lock = threading.Lock()

    def resolver(host: str) -> frozenset[str]:
        with count_lock:
            call_count["n"] += 1
            n = call_count["n"]
        return frozenset({f"10.0.0.{n}"})

    eng = Engagement.from_specs(["example.com"])
    guard = ScopeGuard(engagement=eng, resolver=resolver)
    results: list[frozenset[str] | None] = [None] * 16

    def _resolve(i: int) -> None:
        results[i] = guard.resolve_and_pin("example.com")

    threads = [threading.Thread(target=_resolve, args=(i,)) for i in range(16)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert call_count["n"] == 1  # exactly one real resolution, despite 16 racing callers
    assert len({r for r in results if r is not None}) == 1  # every caller saw the same value


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


def test_port_restricted_rule_is_enforced_even_when_the_url_omits_an_explicit_port() -> None:
    # An operator who scopes ONLY port 8443 must not be bypassed by a URL that
    # simply omits the port -- that request still actually dials the scheme's
    # default port (443 for https), which was never authorized.
    guard = ScopeGuard(
        engagement=Engagement.from_specs(["api.example.com:8443"]),
        resolver=lambda h: frozenset({"93.184.216.34"}),
    )
    assert guard.check("https://api.example.com/admin").decision is Decision.SKIPPED
    assert guard.check("https://api.example.com:8443/admin").decision is Decision.ALLOWED
    assert guard.check("https://api.example.com:80/admin").decision is Decision.SKIPPED


def test_malformed_port_is_denied_not_a_crash() -> None:
    # urlsplit() parses the port lazily -- .port raises ValueError only when
    # read, which used to escape check() uncaught instead of degrading like
    # every other refusal path in this module.
    assert _guard().check("http://app.example.com:notaport/x").decision is Decision.DENIED
