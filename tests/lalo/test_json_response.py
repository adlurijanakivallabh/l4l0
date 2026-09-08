"""Tests for the shared JSON-object extraction helper."""

from __future__ import annotations

from lalo.core.json_response import extract_json_object


def test_extracts_a_clean_json_object() -> None:
    assert extract_json_object('{"a": 1}') == {"a": 1}


def test_extracts_a_json_object_surrounded_by_prose() -> None:
    text = 'Here is the answer:\n{"a": 1, "b": "two"}\nHope that helps!'
    assert extract_json_object(text) == {"a": 1, "b": "two"}


def test_returns_none_when_no_braces_are_present() -> None:
    assert extract_json_object("no json here at all") is None


def test_returns_none_for_malformed_json_inside_braces() -> None:
    assert extract_json_object('{"a": }') is None


def test_returns_none_when_the_parsed_value_is_not_an_object() -> None:
    # A bare JSON array or string is valid JSON but not the dict this
    # helper's every caller actually needs.
    assert extract_json_object("[1, 2, 3]") is None
