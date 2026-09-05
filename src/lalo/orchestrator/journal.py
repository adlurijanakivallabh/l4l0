"""Durable append-only journal for crash-safe resume.

Each completed step is recorded as one JSON line. On restart the journal reloads,
and :meth:`run_once` returns a completed step's cached result instead of
re-executing it — so a resumed scan never duplicates a side effect (a fired
request, a spawned agent) and never loses a recorded result.
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
                continue  # torn final line from a crash -> skip
            if isinstance(record, dict) and "key" in record:
                self._entries[str(record["key"])] = record.get("result")

    def has(self, key: str) -> bool:
        return key in self._entries

    def get(self, key: str) -> Any:
        return self._entries.get(key)

    def record(self, key: str, result: Any) -> None:
        self._entries[key] = result
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps({"key": key, "result": result}, sort_keys=True) + "\n")
            handle.flush()
            os.fsync(handle.fileno())

    def run_once(self, key: str, fn: Callable[[], Any]) -> Any:
        """Execute ``fn`` once ever for ``key``; on resume return the cached result."""
        if self.has(key):
            return self.get(key)
        result = fn()
        self.record(key, result)
        return result

    def completed_keys(self) -> list[str]:
        return list(self._entries)
