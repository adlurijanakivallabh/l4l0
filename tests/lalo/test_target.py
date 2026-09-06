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


def test_describe_empty_engagement() -> None:
    assert Engagement(rules=()).describe() == "(no targets declared)"


def test_describe_renders_every_rule_with_host_scheme_and_port() -> None:
    eng = Engagement.from_specs(["example.com", "https://api.example.com:8443"])
    rendered = eng.describe()
    assert "- example.com" in rendered
    assert "api.example.com" in rendered
    assert "scheme(s): https" in rendered
    assert "port(s): 8443" in rendered


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


def test_from_specs_a_malformed_port_in_a_scheme_prefixed_spec_does_not_crash() -> None:
    # urlsplit(...).port raises ValueError on a non-numeric or out-of-range
    # port string; one bad entry among possibly many operator-supplied specs
    # must degrade to "no port restriction" (matching the plain host:port
    # branch's own established behavior for a non-digit port), never crash
    # the whole engagement.
    eng = Engagement.from_specs(["good.com", "https://example.com:abc/path"])
    assert len(eng.rules) == 2
    assert any(r.host == "example.com" and r.ports is None for r in eng.rules)


def test_from_specs_an_out_of_range_port_does_not_crash() -> None:
    eng = Engagement.from_specs(["https://example.com:99999"])
    assert eng.rules[0].ports is None


def test_from_specs_a_malformed_port_in_a_bracketed_ipv6_spec_does_not_crash() -> None:
    eng = Engagement.from_specs(["[::1]:notaport"])
    assert eng.rules[0].host == "::1"
    assert eng.rules[0].ports is None


def test_port_and_scheme_restrictions() -> None:
    eng = Engagement.from_specs(["api.example.com:8443"])
    assert eng.in_engagement("api.example.com", 8443)
    assert not eng.in_engagement("api.example.com", 80)
    assert eng.in_engagement("api.example.com", None)

    https_only = Engagement.from_specs(["https://x.example.com"])
    assert https_only.in_engagement("x.example.com", None, "https")
    assert not https_only.in_engagement("x.example.com", None, "http")


def test_path_prefix_scoping_restricts_to_the_declared_subtree() -> None:
    eng = Engagement.from_specs(["https://example.com/api/v2"])
    assert eng.in_engagement("example.com", 443, "https", "/api/v2")
    assert eng.in_engagement("example.com", 443, "https", "/api/v2/users")
    assert eng.in_engagement("example.com", 443, "https", "/api/v2/users/1")
    assert not eng.in_engagement("example.com", 443, "https", "/admin")
    # A sibling path that merely shares the string prefix ("/api/v2" is a
    # substring of "/api/v20") must NOT match -- this is a segment-wise
    # prefix check, not a naive str.startswith.
    assert not eng.in_engagement("example.com", 443, "https", "/api/v20/users")


def test_a_target_spec_with_no_path_component_restricts_nothing() -> None:
    eng = Engagement.from_specs(["https://example.com"])
    assert eng.in_engagement("example.com", 443, "https", "/anything/at/all")
    assert eng.in_engagement("example.com", 443, "https", None)


def test_path_prefix_scoping_rejects_dot_dot_traversal_even_when_encoded() -> None:
    eng = Engagement.from_specs(["https://example.com/api/v2"])
    # Plain traversal.
    assert not eng.in_engagement("example.com", 443, "https", "/api/v2/../admin")
    # Single-layer percent-encoded traversal.
    assert not eng.in_engagement("example.com", 443, "https", "/api/v2/%2e%2e/admin")
    # Double-encoded traversal ("%252e%252e" decodes to "%2e%2e" decodes to "..").
    assert not eng.in_engagement("example.com", 443, "https", "/api/v2/%252e%252e/admin")


def test_path_prefix_scoping_rejects_excessive_encoding_depth() -> None:
    # Still decodable after the round cap -- must be REJECTED, never guessed
    # at by returning whatever the last round happened to produce. Verified
    # by direct simulation: "%252525252e%252525252e" needs a 5th unquote()
    # round to fully resolve to ".." (4 rounds only gets to "%2e%2e"), so it
    # must be rejected as still-decodable residue, not silently allowed
    # through as some other, wrong path.
    eng = Engagement.from_specs(["https://example.com/api"])
    five_layers_deep = "/api/%252525252e%252525252e"
    assert not eng.in_engagement("example.com", 443, "https", five_layers_deep)


def test_an_operators_own_malformed_path_spec_drops_the_whole_rule() -> None:
    # A suspicious path in the OPERATOR's own declared scope must never
    # silently widen to "no path restriction at all" -- drop the spec.
    eng = Engagement.from_specs(["good.com", "https://bad.com/api/../escape"])
    assert len(eng.rules) == 1
    assert eng.rules[0].host == "good.com"


def test_describe_renders_the_path_prefix() -> None:
    eng = Engagement.from_specs(["https://example.com/api/v2"])
    assert "path prefix: /api/v2" in eng.describe()


# --- exclude carve-out --------------------------------------------------


def test_exclude_carves_a_host_out_of_a_broader_include_rule() -> None:
    eng = Engagement.from_specs(["*.example.com"], exclude_specs=["admin.example.com"])
    assert eng.in_engagement("app.example.com")
    assert not eng.in_engagement("admin.example.com")


def test_exclude_carves_a_path_out_of_an_otherwise_in_scope_host() -> None:
    eng = Engagement.from_specs(
        ["https://example.com"], exclude_specs=["https://example.com/admin"]
    )
    assert eng.in_engagement("example.com", 443, "https", "/api/users")
    assert not eng.in_engagement("example.com", 443, "https", "/admin")
    assert not eng.in_engagement("example.com", 443, "https", "/admin/settings")


def test_exclude_always_wins_even_against_a_more_specific_include() -> None:
    eng = Engagement.from_specs(
        ["example.com", "admin.example.com"], exclude_specs=["admin.example.com"]
    )
    assert not eng.in_engagement("admin.example.com")


def test_no_exclude_specs_behaves_exactly_like_before() -> None:
    eng = Engagement.from_specs(["*.example.com"])
    assert eng.exclude_rules == ()
    assert eng.in_engagement("admin.example.com")


def test_describe_renders_excluded_rules_separately() -> None:
    eng = Engagement.from_specs(["*.example.com"], exclude_specs=["admin.example.com"])
    rendered = eng.describe()
    assert "admin.example.com" in rendered
    assert "Excluded" in rendered
    # the excluded entry appears after the "Excluded" marker, not mixed into
    # the plain included-rules list above it
    assert rendered.index("Excluded") < rendered.rindex("admin.example.com")


def test_describe_with_no_excludes_has_no_excluded_section() -> None:
    eng = Engagement.from_specs(["example.com"])
    assert "Excluded" not in eng.describe()
