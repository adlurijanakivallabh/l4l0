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
    assert eng.in_engagement("deep.app.example.com")  # fnmatch '*' spans dots
    assert not eng.in_engagement("evil.com")
    assert not eng.in_engagement(None)


def test_port_and_scheme_restrictions() -> None:
    eng = Engagement.from_specs(["api.example.com:8443"])
    assert eng.in_engagement("api.example.com", 8443)
    assert not eng.in_engagement("api.example.com", 80)
    # port unknown -> not rejected by the port rule
    assert eng.in_engagement("api.example.com", None)

    https_only = Engagement.from_specs(["https://x.example.com"])
    assert https_only.in_engagement("x.example.com", None, "https")
    assert not https_only.in_engagement("x.example.com", None, "http")
