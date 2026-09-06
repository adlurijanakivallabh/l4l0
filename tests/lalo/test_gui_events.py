"""Tests for the cursor-resumable, bounded event log."""

from __future__ import annotations

import time

import pytest

from lalo.gui.events import EventLog


def test_append_returns_an_event_with_an_id_and_category() -> None:
    log = EventLog()
    event = log.append("log", {"text": "hello"})
    assert event.category == "log"
    assert event.payload == {"text": "hello"}
    assert event.id


def test_chain_is_a_real_category_the_frontend_can_render() -> None:
    """A closed EventCategory that omitted "chain" made the SPA's Attack
    Chains UI unreachable - no correctly-typed caller could ever populate
    it. This is the backend half of that fix: chain is a real category."""
    log = EventLog()
    event = log.append("chain", {"node_ids": ["a", "b", "c"]})
    assert event.category == "chain"
    _cursor, events = log.snapshot()
    assert events[0].payload == {"node_ids": ["a", "b", "c"]}


def test_snapshot_returns_every_live_event_and_the_current_cursor() -> None:
    log = EventLog()
    log.append("log", {"text": "a"})
    log.append("agent", {"name": "root"})
    cursor, events = log.snapshot()
    assert cursor == 2
    assert [e.payload for e in events] == [{"text": "a"}, {"name": "root"}]


def test_changes_since_returns_only_events_after_the_given_cursor() -> None:
    log = EventLog()
    log.append("log", {"text": "a"})
    cursor1, _ = log.snapshot()
    log.append("log", {"text": "b"})
    cursor2, changes = log.changes_since(cursor1)
    assert [e.payload for e in changes] == [{"text": "b"}]
    assert cursor2 == 2


def test_changes_since_zero_returns_everything() -> None:
    log = EventLog()
    log.append("log", {"text": "a"})
    log.append("log", {"text": "b"})
    _cursor, changes = log.changes_since(0)
    assert len(changes) == 2


def test_changes_since_current_cursor_returns_nothing_new() -> None:
    log = EventLog()
    log.append("log", {"text": "a"})
    cursor, _ = log.snapshot()
    _new_cursor, changes = log.changes_since(cursor)
    assert changes == []


def test_changes_since_rejects_a_cursor_ahead_of_the_log() -> None:
    log = EventLog()
    log.append("log", {"text": "a"})
    with pytest.raises(ValueError, match="outside the available history"):
        log.changes_since(999)


def test_changes_since_rejects_a_negative_cursor() -> None:
    log = EventLog()
    with pytest.raises(ValueError, match="outside the available history"):
        log.changes_since(-1)


def test_update_mutates_an_existing_event_and_bumps_its_change_cursor() -> None:
    log = EventLog()
    event = log.append("agent", {"status": "running"})
    cursor1, _ = log.snapshot()
    updated = log.update(event.id, {"status": "completed"})
    assert updated is not None
    assert updated.payload == {"status": "completed"}
    assert updated.version == 2
    _cursor2, changes = log.changes_since(cursor1)
    assert len(changes) == 1
    assert changes[0].payload == {"status": "completed"}


def test_update_merges_rather_than_replaces_the_payload() -> None:
    log = EventLog()
    event = log.append("agent", {"name": "root", "status": "running"})
    log.update(event.id, {"status": "completed"})
    _cursor, events = log.snapshot()
    assert events[0].payload == {"name": "root", "status": "completed"}


def test_update_of_an_unknown_event_id_is_a_no_op_not_an_error() -> None:
    log = EventLog()
    assert log.update("nonexistent", {"x": 1}) is None


def test_a_reconnect_sees_an_earlier_events_later_update_not_just_new_events() -> None:
    """The core reason this isn't a simple append-only offset log: an event
    created before a client's last-known cursor, but mutated after it, must
    still appear in that client's changes_since result."""
    log = EventLog()
    event = log.append("agent", {"status": "running"})
    log.append("log", {"text": "unrelated"})
    cursor_after_both, _ = log.snapshot()
    log.update(event.id, {"status": "completed"})  # mutates the FIRST event
    _cursor, changes = log.changes_since(cursor_after_both)
    assert len(changes) == 1
    assert changes[0].id == event.id
    assert changes[0].payload["status"] == "completed"


def test_bounded_eviction_drops_the_oldest_event_past_the_cap() -> None:
    log = EventLog(max_events=3)
    ids = [log.append("log", {"i": i}).id for i in range(5)]
    _cursor, events = log.snapshot()
    assert [e.id for e in events] == ids[-3:]


def test_eviction_cleans_up_change_cursor_bookkeeping() -> None:
    log = EventLog(max_events=1)
    first = log.append("log", {"i": 0})
    log.append("log", {"i": 1})  # evicts `first`
    # updating an evicted event is a no-op, not a crash or a resurrection
    assert log.update(first.id, {"i": 99}) is None
    _cursor, events = log.snapshot()
    assert len(events) == 1


def test_event_carries_a_wall_clock_timestamp() -> None:
    before = time.time()
    log = EventLog()
    event = log.append("status", {"event": "x"})
    after = time.time()
    assert before <= event.ts <= after
