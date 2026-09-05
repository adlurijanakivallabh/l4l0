"""Durable append-only journal for crash-safe resume.

Design choice, made deliberately against a reference agent's own coordinator
(which persists crash-recovery state via a *periodic* full-graph snapshot,
atomically written via tempfile+rename): a periodic snapshot can still lose
whatever happened between the last snapshot and a crash. This journal instead
records **every individual side-effecting step the instant it completes** — an
append-only event log, not a periodic snapshot — so resume never redoes lost
work and never duplicates a side effect (a fired request, a spawned agent, a
recorded finding), regardless of exactly when the crash happened. The same
reference's own re-drive-safety idea (detect that a declared state was already
achieved and adopt it, rather than redoing or erroring) is what ``run_once``
implements for every individual key.
"""

from __future__ import annotations

import json
import os
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class Checkpoint:
    key: str
    result: Any


class DurableJournal:
    def __init__(self, path: str | os.PathLike[str]) -> None:
        self.path = Path(path)
        self._entries: dict[str, Any] = {}
        self._load()

    def _load(self) -> None:
        if not self.path.exists():
            return
        for line in self.path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except (json.JSONDecodeError, ValueError):
                continue  # torn final line from a crash mid-write -> skip, not fatal
            if isinstance(record, dict) and "key" in record:
                self._entries[str(record["key"])] = record.get("result")

    def has(self, key: str) -> bool:
        return key in self._entries

    def get(self, key: str) -> Any:
        return self._entries.get(key)

    def record(self, key: str, result: Any) -> None:
        # Serialize and durably write FIRST, update in-memory state only after
        # that succeeds. Doing it in the other order (as this once did) means a
        # serialization failure (e.g. a non-JSON-serializable result) or a
        # transient disk error leaves _entries believing a step completed when
        # nothing was ever persisted — has() would return True, a resumed
        # process wouldn't see the key at all, and within the same process the
        # step would never be retried. This ordering makes an unrecorded step
        # look exactly like it never ran, which is the truth.
        self.path.parent.mkdir(parents=True, exist_ok=True)
        line = json.dumps({"key": key, "result": result}, sort_keys=True) + "\n"
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(line)
            handle.flush()
            os.fsync(handle.fileno())
        self._entries[key] = result

    def run_once(self, key: str, fn: Callable[[], Any]) -> Any:
        """Execute ``fn`` once ever for ``key``; on resume return the cached result
        instead of re-running it — the re-drive-safety property: a declared state
        already achieved is adopted, never redone, never double-committed."""
        if self.has(key):
            return self.get(key)
        result = fn()
        self.record(key, result)
        return result

    def completed_keys(self) -> list[str]:
        return list(self._entries)
