"""A cursor-resumable, bounded event log — the GUI's one source of truth.

Adopts a reference agent's own real cursor mechanism directly, read in full
from ``interface/tui/backend/live_view.py``: a monotonically increasing
global cursor, a per-event "last changed at cursor N" map (so an event that
is created once and *updated* in place later — e.g. a streaming tool call
that gets its output attached after it starts — is correctly re-included
in a "what changed since cursor C" query, not just brand-new events), and a
bounded ring buffer that evicts the oldest event (and its cursor bookkeeping)
once a cap is hit so a long-running scan's memory stays flat. Renamed
generically and adapted from that reference's TUI-event-projection use case
to this project's own categorized status/log/agent/finding/chain events.

A different reference's own generic pub/sub (``graph/subscriptions/
controller.go``'s ``Channel[T]``, read in full) was checked specifically
for the "reconnect reconciliation" idea the governing plan names — and
found to have none: its ``Subscribe``/``Publish``/``Broadcast`` model is
pure live fan-out with no history buffer at all, so a client that
reconnects gets nothing published before its new subscription, and a slow
subscriber silently drops events past a timeout. That confirms this
project's cursor-resumable design is the piece actually closing a gap
neither reference solves, not a redundant reimplementation of something
already fully solved elsewhere.
"""

from __future__ import annotations

import itertools
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Literal

EventCategory = Literal["status", "log", "agent", "finding", "steering", "chain", "shell"]

MAX_EVENTS = 10_000


@dataclass
class Event:
    id: str
    category: EventCategory
    payload: dict[str, Any]
    version: int = 1
    ts: float = field(default_factory=time.time)


class EventLog:
    """Append/update categorized events; serve a snapshot or a since-cursor delta."""

    def __init__(self, *, max_events: int = MAX_EVENTS) -> None:
        self._max_events = max_events
        # deque, not list: eviction below is popleft() (O(1)) rather than
        # list.pop(0) (O(n), shifting every remaining element) - the latter
        # would make every append cost O(max_events) once a long-running
        # scan's log is at capacity, purely from bookkeeping.
        self._events: deque[Event] = deque()
        self._by_id: dict[str, Event] = {}
        self._change_cursor: dict[str, int] = {}
        self._cursor = 0
        self._ids = itertools.count(1)

    def append(self, category: EventCategory, payload: dict[str, Any]) -> Event:
        event = Event(id=f"evt-{next(self._ids)}", category=category, payload=payload)
        self._events.append(event)
        self._by_id[event.id] = event
        self._mark_changed(event)
        if len(self._events) > self._max_events:
            evicted = self._events.popleft()
            self._by_id.pop(evicted.id, None)
            self._change_cursor.pop(evicted.id, None)
        return event

    def update(self, event_id: str, payload: dict[str, Any]) -> Event | None:
        """Merge ``payload`` into an existing event and bump its change-cursor.

        Returns ``None`` (a no-op) if ``event_id`` no longer exists — either
        it was never created, or it has since been evicted from the bounded
        window. Never raises: a caller updating a since-evicted event is a
        normal race in a long-running scan, not an error.
        """
        event = self._by_id.get(event_id)
        if event is None:
            return None
        event.payload = {**event.payload, **payload}
        event.version += 1
        self._mark_changed(event)
        return event

    def _mark_changed(self, event: Event) -> None:
        self._cursor += 1
        self._change_cursor[event.id] = self._cursor

    def snapshot(self) -> tuple[int, list[Event]]:
        """The current cursor plus every live event — for a fresh connection."""
        return self._cursor, list(self._events)

    def changes_since(self, cursor: int) -> tuple[int, list[Event]]:
        """The current cursor plus every event changed after ``cursor`` — for a reconnect.

        Raises :class:`ValueError` for a cursor outside the log's known
        range (negative, or ahead of the log's own current cursor) — a
        client presenting such a cursor has a bug or is replaying a
        different log entirely, and silently returning nothing would hide
        that rather than surface it.
        """
        if cursor < 0 or cursor > self._cursor:
            raise ValueError(f"cursor {cursor} is outside the available history")
        changed_ids = sorted(
            (change_cursor, event_id)
            for event_id, change_cursor in self._change_cursor.items()
            if change_cursor > cursor
        )
        changed = [self._by_id[event_id] for _change_cursor, event_id in changed_ids]
        return self._cursor, changed
