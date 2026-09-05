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
