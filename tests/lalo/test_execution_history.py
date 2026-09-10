"""Tests for the passive HTTP request/response history log."""

from __future__ import annotations

from lalo.execution.firer import FireResult
from lalo.execution.history import RequestHistory


def _fire_result(**overrides: object) -> FireResult:
    defaults = dict(
        method="GET", url="https://x/a", fired=True, scope_reason="in_scope", status=200
    )
    defaults.update(overrides)
    return FireResult(**defaults)  # type: ignore[arg-type]


def test_record_and_list_round_trips() -> None:
    history = RequestHistory()
    history.record("GET", "https://x/a", {"Accept": "*/*"}, b"", _fire_result())
    entries = history.list()
    assert len(entries) == 1
    assert entries[0].url == "https://x/a"
    assert entries[0].index == 0


def test_list_filters_by_url_substring_and_method() -> None:
    history = RequestHistory()
    history.record("GET", "https://x/a", {}, b"", _fire_result(url="https://x/a"))
    history.record("POST", "https://x/b", {}, b"", _fire_result(method="POST", url="https://x/b"))
    assert [e.url for e in history.list(url_contains="/b")] == ["https://x/b"]
    assert [e.method for e in history.list(method="post")] == ["POST"]


def test_get_returns_none_for_an_unknown_index() -> None:
    history = RequestHistory()
    assert history.get(99) is None


def test_history_drops_oldest_entries_past_max_entries() -> None:
    history = RequestHistory(max_entries=2)
    for i in range(3):
        history.record("GET", f"https://x/{i}", {}, b"", _fire_result(url=f"https://x/{i}"))
    urls = [e.url for e in history.list()]
    assert urls == ["https://x/1", "https://x/2"]
