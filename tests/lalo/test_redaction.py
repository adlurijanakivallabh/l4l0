"""Tests for the shared redaction module (pattern-based + exact-match, universal)."""

from __future__ import annotations

from lalo.core.redaction import (
    REDACTION_PLACEHOLDER,
    SecretRedactor,
    looks_secret_shaped,
    normalize_semantic_label,
    redact,
    safe_error_from_code,
    safe_target_url,
    set_redaction_enabled,
    shared_redactor,
)


def test_looks_secret_shaped_detects_known_shapes() -> None:
    jwt = "eyJhbGciOiJIUzI1NiedcITHENd.eyJzdWIiOiIxMjM0NTY3ODkw.dQw4w9WgXcQ7abc"
    assert looks_secret_shaped(jwt)
    assert looks_secret_shaped("AKIAIOSFODNN7EXAMPLE")
    assert looks_secret_shaped("sk-ant-abcdefghijklmnopqrstuvwxyz012345")
    assert looks_secret_shaped("aGVsbG9fd29ybGRfdGhpc19pc19hX3NlY3JldA==")


def test_looks_secret_shaped_ignores_ordinary_text() -> None:
    assert not looks_secret_shaped("hello")
    assert not looks_secret_shaped("the quick brown fox jumps over")
    assert not looks_secret_shaped("GET /api/users/42 HTTP/1.1")


def test_pattern_based_redaction() -> None:
    text = "Authorization: Bearer eyJhbGciOiJIUzI1NiiiXX.eyJzdWIiOiJhYmM1.sig9value00"
    out = redact(text)
    assert "eyJhbGci" not in out
    assert REDACTION_PLACEHOLDER in out


def test_redact_leaves_plain_text_untouched() -> None:
    text = "found reflected XSS in the search parameter"
    assert redact(text) == text


def test_exact_match_redacts_a_configured_secret_with_no_known_shape() -> None:
    # A short, non-shape-matching operator credential (e.g. a login password) —
    # the pattern layer alone would never catch this; exact-match closes the gap.
    r = SecretRedactor()
    r.register_secret("hunter2horse")
    assert "hunter2horse" not in r.redact("login failed for password hunter2horse")


def test_shared_instance_is_universal() -> None:
    # Registering on the shared instance affects the module-level redact() too —
    # this IS the fix for a reference redaction engine's own documented gap
    # (a shared replacer that several call sites never actually used).
    shared_redactor().register_secret("zzz-unique-marker-9f3a")
    assert "zzz-unique-marker-9f3a" not in redact("token=zzz-unique-marker-9f3a")


def test_json_style_secret() -> None:
    out = redact('{"username":"bob","password":"hunter2secret"}')
    assert "hunter2secret" not in out
    assert "bob" in out


def test_pem_private_key_header() -> None:
    assert REDACTION_PLACEHOLDER in redact("-----BEGIN RSA PRIVATE KEY-----\nMIIE...")


def test_redact_does_not_leak_a_suffix_when_one_secret_is_a_substring_of_another() -> None:
    # Registering a secret that is itself a prefix of another registered secret
    # must never cause the longer secret's own remainder to survive redaction --
    # this is order-dependent on plain set iteration, so it must hold regardless
    # of which one happens to be processed first.
    r = SecretRedactor()
    r.register_secret("abc123")
    r.register_secret("abc123456")
    out = r.redact("leaked abc123456 here")
    assert "123456" not in out
    assert "456" not in out
    assert out == f"leaked {REDACTION_PLACEHOLDER} here"


def test_safe_target_url_handles_a_non_numeric_port_without_crashing() -> None:
    # urlsplit() parses the port lazily -- accessing .port on a malformed port
    # raises ValueError only when read, not at urlsplit() time itself.
    assert safe_target_url("http://evil.com:abc/path?x=1") == REDACTION_PLACEHOLDER


def test_safe_target_url_strips_userinfo_and_sensitive_query() -> None:
    url = "https://user:hunter2@app.example.com:8443/login?token=abc123secret&next=/home"
    out = safe_target_url(url)
    assert "hunter2" not in out
    assert "user:" not in out
    assert "abc123secret" not in out
    # The per-key pass already replaces the token VALUE with REDACTED; the
    # whole-URL redact() pass this function now also runs (closing the
    # path-secret gap - see the dedicated test below) then matches
    # _TOKEN_PATTERNS' own "token=<non-whitespace>" key=value pattern
    # against the resulting "token=REDACTED&next=/home" and swallows the
    # rest of the query string too, since `&`/`/` aren't whitespace - an
    # over-redaction this module's own docstring explicitly accepts
    # ("over-redacting... is fine; leaking a real secret is not"), just a
    # broader span than before.
    assert "REDACTED" in out
    assert "app.example.com:8443" in out


def test_safe_target_url_redacts_a_jwt_shaped_token_embedded_in_the_path() -> None:
    """Regression: safe_target_url only ever redacted the query string by
    exact key name - a secret embedded in the PATH (a password-reset link,
    a JWT-in-path pattern) reached every downstream consumer of this
    "already redacted" value (the dedup key, the graph node, the delivered
    report) in cleartext."""
    jwt = (
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0."
        "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
    )
    url = f"https://app.example.com/reset/{jwt}"
    out = safe_target_url(url)
    assert jwt not in out
    assert "REDACTED" in out
    assert "app.example.com" in out


def test_safe_target_url_redacts_a_high_entropy_query_value_under_an_unlisted_key() -> None:
    """A secret under a key not in the exact-match _SENSITIVE_KEYS set (e.g.
    a dashed variant, or a key this project's list simply doesn't name) must
    still be caught by the pattern/entropy pass over the assembled URL."""
    secret = "aG9wZWZ1bGx5LXNlY3JldC1sb29raW5nLXZhbHVlLTEyMzQ1Njc4"
    url = f"https://app.example.com/verify?resetkey={secret}"
    out = safe_target_url(url)
    assert secret not in out
    assert "REDACTED" in out


def test_safe_error_from_code_is_fixed_table() -> None:
    assert safe_error_from_code("scope_violation") == (
        "Target is outside the declared engagement scope."
    )
    assert safe_error_from_code("some raw exception text") == "An unexpected error occurred."


def test_normalize_semantic_label() -> None:
    assert normalize_semantic_label("  SQL Injection (blind) ") == "sql_injection_blind"
    assert normalize_semantic_label("!!!") == "unlabeled"


# --- set_redaction_enabled: an explicit, informed operator opt-out ----------
# Reset after every test suite-wide via conftest.py's own autouse fixture,
# not just within this file - see that fixture's docstring for why.


def test_set_redaction_enabled_false_makes_redact_a_passthrough() -> None:
    text = "Authorization: Bearer eyJhbGciOiJIUzI1NiiiXX.eyJzdWIiOiJhYmM1.sig9value00"
    set_redaction_enabled(False)
    assert redact(text) == text


def test_set_redaction_enabled_true_restores_normal_redaction() -> None:
    text = "Authorization: Bearer eyJhbGciOiJIUzI1NiiiXX.eyJzdWIiOiJhYmM1.sig9value00"
    set_redaction_enabled(False)
    set_redaction_enabled(True)
    assert REDACTION_PLACEHOLDER in redact(text)


def test_safe_error_from_code_covers_every_lalo_error_code() -> None:
    """Every concrete LaloError subclass's `code` needs its own entry in
    _ERROR_MESSAGES - an uncovered code silently falls back to the generic
    "unknown" message, and nothing else in the codebase would ever notice
    the table had drifted out of sync with core/errors.py."""
    from lalo.core import errors

    codes = {
        obj.code
        for obj in vars(errors).values()
        if isinstance(obj, type) and issubclass(obj, errors.LaloError)
    }
    assert codes == {
        "unknown",
        "config_error",
        "provider_error",
        "provider_refusal",
        "provider_unavailable",
        "all_providers_failed",
        "scope_error",
        "scope_violation",
        "target_unreachable",
        "container_error",
        "spawn_depth_exceeded",
        "login_failed",
        "session_not_mirrored",
        "jwt_malformed",
        "totp_secret_invalid",
        "resume_config_mismatch",
        "cost_limit_exceeded",
    }
    fallback = safe_error_from_code("definitely-not-a-real-code")
    for code in sorted(codes - {"unknown"}):
        assert safe_error_from_code(code) != fallback, (
            f"{code!r} has no dedicated entry in _ERROR_MESSAGES and silently "
            "falls back to the generic unknown-error message"
        )


def test_safe_error_from_code_remediation_hints_name_the_real_opt_in_knobs() -> None:
    """target_unreachable/login_failed are the two LaloError codes that can
    actually reach a live scan_failed event today (via ScanConfig's
    fail_on_unreachable_targets/fail_on_broken_login, both opt-in and False
    by default) - lock the wording so a future rename of either field is
    caught here instead of silently going stale in the message text."""
    assert safe_error_from_code("target_unreachable") == (
        "The target failed its reachability preflight; confirm it is up, or turn "
        "off fail_on_unreachable_targets to proceed anyway."
    )
    assert safe_error_from_code("login_failed") == (
        "Login did not produce a usable session; check the identity's "
        "credentials, or turn off fail_on_broken_login to proceed anyway."
    )
