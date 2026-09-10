"""Passive HTTP request/response history - a byproduct of firing, for later
listing, inspection, and replay-with-edits. Recorded at HttpFirer.fire()'s
one existing choke point (see attach_recorder there), so http/
fire_concurrent/diff_responses all populate it automatically with zero
change to any of their own call sites.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass

from .firer import FireResult

_DEFAULT_MAX_ENTRIES = 500


@dataclass(frozen=True)
class HistoryEntry:
    index: int
    method: str
    url: str
    request_headers: dict[str, str]
    request_body: bytes
    result: FireResult


class RequestHistory:
    """Bounded, thread-safe in-memory history for one scan's fired requests."""

    def __init__(self, *, max_entries: int = _DEFAULT_MAX_ENTRIES) -> None:
        self._entries: list[HistoryEntry] = []
        self._max_entries = max_entries
        self._next_index = 0
        self._lock = threading.Lock()

    def record(
        self,
        method: str,
        url: str,
        headers: dict[str, str] | None,
        body: bytes | None,
        result: FireResult,
    ) -> None:
        with self._lock:
            entry = HistoryEntry(
                index=self._next_index,
                method=method.upper(),
                url=url,
                request_headers=dict(headers or {}),
                request_body=body or b"",
                result=result,
            )
            self._next_index += 1
            self._entries.append(entry)
            if len(self._entries) > self._max_entries:
                # ponytail: oldest-entry eviction, not a ring buffer - fine
                # at this scan-local, single-digit-thousands scale; a ring
                # buffer only pays for itself at a size this never reaches.
                self._entries.pop(0)

    def list(
        self, *, url_contains: str | None = None, method: str | None = None
    ) -> list[HistoryEntry]:
        with self._lock:
            entries = list(self._entries)
        if url_contains:
            entries = [e for e in entries if url_contains.lower() in e.url.lower()]
        if method:
            entries = [e for e in entries if e.method == method.upper()]
        return entries

    def get(self, index: int) -> HistoryEntry | None:
        with self._lock:
            return next((e for e in self._entries if e.index == index), None)
