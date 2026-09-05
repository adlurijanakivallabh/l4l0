"""Tests for the payload corpus, resolver, and mutation."""

from __future__ import annotations

from lalo.payloads import mutate, resolve_value, select
from lalo.payloads.corpus import Payload


def test_select_by_class_and_context() -> None:
    sqli = select("sqli")
    assert sqli and all(p.vuln_class == "sqli" for p in sqli)
    sql_ctx = select("xss", context="html")
    assert sql_ctx and all(p.context == "html" for p in sql_ctx)


def test_exclude_oob_when_requested() -> None:
    with_oob = select("cmdi", include_oob=True)
    without_oob = select("cmdi", include_oob=False)
    assert any(p.oob for p in with_oob)
    assert not any(p.oob for p in without_oob)


def test_oast_substitution() -> None:
    oob = next(p for p in select("ssrf") if p.oob)
    resolved = resolve_value(oob, oast_domain="abc123.oast.local")
    assert "abc123.oast.local" in resolved
    assert "{{OAST" not in resolved


def test_oob_without_target_resolves_empty() -> None:
    oob = next(p for p in select("cmdi") if p.oob)
    assert resolve_value(oob) == ""  # never fake a callback target


def test_non_oob_resolves_verbatim() -> None:
    p = Payload("' OR '1'='1", "sqli", "sql")
    assert resolve_value(p) == "' OR '1'='1"


def test_mutate_produces_encoding_variants() -> None:
    variants = dict(mutate("../etc/passwd", ["url", "double_url"]))
    assert variants["url"] == "..%2Fetc%2Fpasswd"
    assert "%252F" in variants["double_url"]


def test_mutate_sql_comment_and_case() -> None:
    variants = dict(mutate("OR 1=1", ["sql_comment", "case_toggle"]))
    assert "/**/" in variants["sql_comment"]
    assert variants["case_toggle"].lower() == "or 1=1"
