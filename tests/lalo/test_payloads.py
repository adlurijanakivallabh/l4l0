"""Tests for the deliberately narrow Phase 10 payload helpers."""

from __future__ import annotations

from lalo.oast import OASTServer
from lalo.payloads import (
    double_url_encode,
    html_entity_encode,
    substitute_oast,
    unicode_escape,
    url_encode,
)


def test_substitute_oast_replaces_the_placeholder() -> None:
    template = "http://{{oast}}/x?probe=1"
    assert substitute_oast(template, "abc123.oast.local") == "http://abc123.oast.local/x?probe=1"


def test_substitute_oast_replaces_every_occurrence() -> None:
    template = "{{oast}} and {{oast}} again"
    assert substitute_oast(template, "v") == "v and v again"


def test_substitute_oast_no_placeholder_is_a_no_op() -> None:
    template = "no placeholder here"
    assert substitute_oast(template, "v") == template


def test_substitute_oast_wires_a_real_callback_url_from_a_real_oast_server() -> None:
    with OASTServer() as oast:
        token = oast.issue_token(probe_ref="phase10-check")
        payload = substitute_oast("curl {{oast}}", oast.callback_url(token))
        assert payload == f"curl {oast.callback_url(token)}"
        assert token in payload


def test_url_encode_escapes_reserved_characters() -> None:
    assert url_encode("a b&c") == "a%20b%26c"


def test_double_url_encode_encodes_twice() -> None:
    assert double_url_encode("a b") == url_encode(url_encode("a b"))
    assert double_url_encode("a b") == "a%2520b"


def test_unicode_escape_produces_js_style_escapes() -> None:
    assert unicode_escape("ab") == "\\u0061\\u0062"


def test_html_entity_encode_produces_decimal_entities() -> None:
    assert html_entity_encode("<a>") == "&#60;&#97;&#62;"
