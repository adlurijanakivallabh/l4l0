"""Tests for the evidence-provenance grounding check."""

from __future__ import annotations

from lalo.findings.grounding import is_grounded


def test_is_grounded_true_when_excerpt_is_a_real_substring() -> None:
    evidence = ["HTTP/1.1 200 OK\nContent-Type: text/plain\n\nadmin=true"]
    assert is_grounded("admin=true", evidence) is True


def test_is_grounded_false_for_a_fabricated_claim_not_in_any_evidence() -> None:
    evidence = ["HTTP/1.1 200 OK\n\nwelcome"]
    assert is_grounded("admin_password=secret", evidence) is False


def test_is_grounded_false_for_a_partially_laundered_claim() -> None:
    # A claim that mixes real captured text with a fabricated tail must not
    # ground just because a prefix of it really occurred somewhere.
    evidence = ["GET / -> HTTP/1.0 200 OK"]
    assert is_grounded("GET / -> HTTP/1.0 200 OK; admin_password=secret", evidence) is False


def test_is_grounded_normalizes_crlf_vs_lf() -> None:
    evidence = ["line1\r\nline2\r\nline3"]
    assert is_grounded("line1\nline2\nline3", evidence) is True


def test_is_grounded_false_for_blank_excerpt() -> None:
    assert is_grounded("   ", ["some real evidence"]) is False


def test_is_grounded_checks_every_evidence_blob() -> None:
    evidence = ["irrelevant blob", "the real one has secret=abc123 in it"]
    assert is_grounded("secret=abc123", evidence) is True


def test_is_grounded_true_for_pretty_printed_json_matching_a_compact_evidence_blob() -> None:
    """Reproduces a real false negative from a live run against VAmPI: the
    model's own evidence_excerpt was multi-line pretty-printed JSON quoting
    the same object a captured response's evidence blob held as compact
    single-line JSON - same content, different whitespace only."""
    excerpt = '"admin": true,\n      "email": "admin@mail.com",\n      "username": "admin"'
    evidence = [
        'Raw response excerpt: { "users": [ '
        '{ "admin": true, "email": "admin@mail.com", "username": "admin" } ] }'
    ]
    assert is_grounded(excerpt, evidence) is True


def test_is_grounded_still_rejects_a_laundered_claim_regardless_of_whitespace() -> None:
    """The whitespace-collapsing extension must never let a genuinely
    fabricated token sequence through just because it's spread across lines."""
    evidence = ["GET / -> HTTP/1.0 200 OK"]
    excerpt = "GET /  ->  HTTP/1.0   200   OK\n; admin_password=secret"
    assert is_grounded(excerpt, evidence) is False
