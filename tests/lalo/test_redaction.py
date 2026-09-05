"""Tests for the shared redaction module — the one source of truth for secrets."""

from __future__ import annotations

from lalo.core.redaction import (
    REDACTION_PLACEHOLDER,
    looks_secret_shaped,
    normalize_semantic_label,
    redact,
    safe_error_from_code,
    safe_target_url,
)


def test_looks_secret_shaped_detects_known_shapes() -> None:
    jwt = "eyJhbGciOiJIUzI1NiedcITHENd.eyJzdWIiOiIxMjM0NTY3ODkw.dQw4w9WgXcQ7abc"
    assert looks_secret_shaped(jwt)
    assert looks_secret_shaped("AKIAIOSFODNN7EXAMPLE")
    assert looks_secret_shaped("sk-ant-abcdefghijklmnopqrstuvwxyz012345")
    # High-entropy blob.
    assert looks_secret_shaped("aGVsbG9fd29ybGRfdGhpc19pc19hX3NlY3JldA==")


def test_looks_secret_shaped_ignores_ordinary_text() -> None:
    assert not looks_secret_shaped("hello")
    assert not looks_secret_shaped("the quick brown fox jumps over")
    assert not looks_secret_shaped("GET /api/users/42 HTTP/1.1")


def test_redact_replaces_secrets_but_keeps_context() -> None:
    text = "Authorization: Bearer eyJhbGciOiJIUzI1NiiiXX.eyJzdWIiOiJhYmM1.sig9value00"
    out = redact(text)
    assert "eyJhbGci" not in out
    assert REDACTION_PLACEHOLDER in out


def test_redact_leaves_plain_text_untouched() -> None:
    text = "found reflected XSS in the search parameter"
    assert redact(text) == text


def test_redact_more_secret_shapes() -> None:
    for secret in (
        "AIzaSyD-EXAMPLE_key_1234567890abcdefghil",  # Google API key (39 chars)
        "sk_live_abcdef0123456789ABCDEF",  # Stripe
        "ocx_data_5ece2a7afb4335315ce3fa02e5ccbcf7",  # OpenCodex-style
        "gho_ABCDEFGHIJKLMNOPQRSTUVWXYZ012345",  # GitHub oauth
    ):
        out = redact(f"key is {secret} end")
        assert secret not in out, secret
        assert REDACTION_PLACEHOLDER in out


def test_redact_json_style_secret() -> None:
    out = redact('{"username":"bob","password":"hunter2secret"}')
    assert "hunter2secret" not in out
    assert "bob" in out  # non-secret field preserved


def test_redact_pem_private_key_header() -> None:
    assert REDACTION_PLACEHOLDER in redact("-----BEGIN RSA PRIVATE KEY-----\nMIIE...")


def test_safe_target_url_strips_userinfo_and_sensitive_query() -> None:
    url = "https://user:hunter2@app.example.com:8443/login?token=abc123secret&next=/home"
    out = safe_target_url(url)
    assert "hunter2" not in out
    assert "user:" not in out
    assert "abc123secret" not in out
    # The value is redacted, not dropped (the ascii marker survives url-encoding).
    assert "token=" in out and "REDACTED" in out
    assert "app.example.com:8443" in out
    assert "/login" in out
    assert "next=%2Fhome" in out or "next=/home" in out


def test_safe_error_from_code_is_fixed_table() -> None:
    assert safe_error_from_code("scope_violation") == (
        "Target is outside the declared engagement scope."
    )
    # Unknown code -> generic, never echoes the input.
    assert safe_error_from_code("some raw exception text") == "An unexpected error occurred."


def test_normalize_semantic_label() -> None:
    assert normalize_semantic_label("  SQL Injection (blind) ") == "sql_injection_blind"
    assert normalize_semantic_label("!!!") == "unlabeled"
