"""Tests for the declared-engagement target model."""

from __future__ import annotations

from lalo.execution.target import Engagement, TargetRule


def test_from_specs_parses_forms() -> None:
    eng = Engagement.from_specs(
        ["example.com", "*.example.com", "api.example.com:8443", "https://secure.example.com"]
    )
    assert len(eng.rules) == 4
    assert TargetRule(host="example.com") in eng.rules
    assert any(r.host == "*.example.com" for r in eng.rules)
    assert any(r.host == "api.example.com" and r.ports == frozenset({8443}) for r in eng.rules)
    assert any(
        r.host == "secure.example.com" and r.schemes == frozenset({"https"}) for r in eng.rules
    )


def test_in_engagement_exact_and_wildcard() -> None:
    eng = Engagement.from_specs(["example.com", "*.example.com"])
    assert eng.in_engagement("example.com")
    assert eng.in_engagement("app.example.com")
    assert eng.in_engagement("deep.app.example.com")
    assert not eng.in_engagement("evil.com")
    assert not eng.in_engagement(None)


def test_local_lab_targets_work_by_design() -> None:
    # Deliberate divergence from a general "fetch public URLs" tool's policy:
    # L4L0's engagement model must allow local/internal hosts since that's its
    # actual, routine use case (a lab container, an internal corporate app).
    eng = Engagement.from_specs(["127.0.0.1", "10.0.5.20"])
    assert eng.in_engagement("127.0.0.1")
    assert eng.in_engagement("10.0.5.20")


def test_bracketed_ipv6_specs_without_a_scheme_prefix_parse_correctly() -> None:
    # A bracketed IPv6 literal with no scheme (the form the docstring's own
    # examples imply is supported for a bare host[:port] spec) used to fall
    # through to a branch that kept the brackets/port as part of the literal
    # `host` string, producing a rule that could never match a real request.
    with_port = Engagement.from_specs(["[::1]:8080"])
    assert with_port.in_engagement("::1", 8080)
    assert not with_port.in_engagement("::1", 9090)

    without_port = Engagement.from_specs(["[::1]"])
    assert without_port.in_engagement("::1")


def test_port_and_scheme_restrictions() -> None:
    eng = Engagement.from_specs(["api.example.com:8443"])
    assert eng.in_engagement("api.example.com", 8443)
    assert not eng.in_engagement("api.example.com", 80)
    assert eng.in_engagement("api.example.com", None)

    https_only = Engagement.from_specs(["https://x.example.com"])
    assert https_only.in_engagement("x.example.com", None, "https")
    assert not https_only.in_engagement("x.example.com", None, "http")
