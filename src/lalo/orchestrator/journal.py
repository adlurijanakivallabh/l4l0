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

Phase 2, a studied reference agent's own pass: reading that reference's own
running-agents documentation note on
``RunConfig.trace_include_sensitive_data`` (an opt-out for whether LLM/tool
I/O — potentially including credentials scraped mid-scan — gets written into
a persisted trace) surfaced a real gap here, not there: this journal is
plausibly the single most sensitive artifact L4L0 produces (a raw, complete
record of every side-effecting step's actual result, arguably more detailed
than the final report), yet unlike every OTHER persisted artifact it does not
route through :func:`~lalo.core.atomic_io.atomic_write_verified` (a whole-
file replace primitive is the wrong shape for an append-only log growing over
a long-running scan — read-modify-write-the-whole-file on every step would be
quadratic) and so never picked up that primitive's owner-only (0600) file
permissions. Fixed narrowly here instead: the file is created (and, on an
existing file from before this fix, re-tightened) at 0600 directly, without
giving up true O(1)-per-record append behavior. Redaction is deliberately
NOT applied to journaled values themselves (only display/report paths redact)
— a resumed step may legitimately need to reuse an exact prior result (e.g. a
session token from a journaled login step); silently substituting a
redaction placeholder into operational state the system depends on for
correctness would be worse than the exposure this file-permission fix
addresses.
"""

from __future__ import annotations

import json
import os
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..core.atomic_io import append_owner_only_line
from ..core.logging import get_logger

_log = get_logger("lalo.journal")


@dataclass(frozen=True)
class Checkpoint:
    key: str
    result: Any
    ts: float = field(default_factory=time.time)
    # NOT what DurableJournal actually persists/reads -- it has zero real
    # construction call sites anywhere in this codebase. The journal's own
    # on-disk {"key", "result", "ts"} JSON lines (record()/_load() below) are
    # the real timestamp source; use DurableJournal.ts_for(key) for that.


class DurableJournal:
    def __init__(self, path: str | os.PathLike[str]) -> None:
        self.path = Path(path)
        self._entries: dict[str, Any] = {}
        self._ts: dict[str, float] = {}
        self._lock = threading.Lock()
        self._load()

    def _load(self) -> None:
        if not self.path.exists():
            return
        lines = self.path.read_text(encoding="utf-8").splitlines()
        last_index = len(lines) - 1
        for i, line in enumerate(lines):
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except (json.JSONDecodeError, ValueError):
                # A crash mid-write can only ever torn the LAST line - skip
                # that one without comment. Any OTHER line failing to parse
                # is real corruption, not a crash artifact, and dropping it
                # silently would hide exactly the "resume state silently
                # corrupted after a crash" scenario this journal exists to
                # prevent - a dropped checkpoint here means a resumed step
                # whose journal record didn't survive gets silently
                # re-executed (re-firing a request, re-spawning a child).
                if i != last_index:
                    _log.warning("journal line %d unparseable, dropping: %s", i, self.path)
                continue
            if isinstance(record, dict) and "key" in record:
                key = str(record["key"])
                self._entries[key] = record.get("result")
                # Older journal files predate the "ts" field -- fall back to
                # not-recorded (None) for those lines rather than fabricating
                # a false-now timestamp for a step that actually landed earlier.
                ts = record.get("ts")
                if isinstance(ts, int | float):
                    self._ts[key] = float(ts)

    def has(self, key: str) -> bool:
        return key in self._entries

    def get(self, key: str) -> Any:
        return self._entries.get(key)

    def ts_for(self, key: str) -> float | None:
        """The wall-clock time ``key`` was recorded, or ``None`` if the key
        doesn't exist (mirroring ``get()``'s own not-found behavior) or was
        loaded from a pre-timestamp journal file."""
        return self._ts.get(key)

    def record(self, key: str, result: Any) -> None:
        # Serialize and durably write FIRST, update in-memory state only after
        # that succeeds. Doing it in the other order (as this once did) means a
        # serialization failure (e.g. a non-JSON-serializable result) or a
        # transient disk error leaves _entries believing a step completed when
        # nothing was ever persisted — has() would return True, a resumed
        # process wouldn't see the key at all, and within the same process the
        # step would never be retried. This ordering makes an unrecorded step
        # look exactly like it never ran, which is the truth.
        #
        # Locked because spawn_agents' concurrent children now all journal
        # through this same instance (each under its own child_id namespace) -
        # matches this project's existing Budget/Tracer/ScanRunner._graph_lock/
        # HttpFirer._breaker_lock pattern for state shared across spawn_agents'
        # ThreadPoolExecutor workers. has()/get()/ts_for()/completed_keys()
        # stay unlocked reads of self._entries/self._ts - plain dict reads are
        # safe under the GIL, matching Tracer.span()'s own unlocked
        # self.spans.append() (only its counter()'s read-modify-write is
        # guarded).
        ts = time.time()
        line = json.dumps({"key": key, "result": result, "ts": ts}, sort_keys=True)
        with self._lock:
            append_owner_only_line(self.path, line)
            self._entries[key] = result
            self._ts[key] = ts

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

    def completed_step_count(self) -> int:
        """Total real agent-step entries across EVERY agent_key namespace
        (root and every spawned child), not just root's own.

        An audit found a resumed run's Budget.spent was reconstructed only
        from AgentLoop.run()'s own replay loop, which re-spends 1 unit per
        REPLAYED step for whichever single agent_key is calling it - correct
        for root's own steps, but a completed child is never re-run on
        resume (its own already-journaled spawn_agent step on the ROOT is
        adopted from cache, not re-dispatched), so every step that child
        itself spent was silently lost from the shared ceiling after a
        crash/resume. This is the single source of truth instead: every
        step key is shaped ``"{agent_key}:{step}"`` with an integer step
        suffix (``root:0``, ``agent-2:1``, ...) - the ``"{child_id}:spawned"``/
        ``"{child_id}:finished"`` breadcrumbs and the ``"review:{finding_id}"``
        namespace (see scan.py's own per-finding review journaling) are
        excluded since neither ever calls ``Budget.spend()``.

        A digit-suffixed "finish" entry (agent/loop.py's mid-loop and
        reserved-final-turn finish handling both journal under a normal
        step key) is excluded too, for the same reason: finish returns
        immediately, before the dispatch path's own ``budget.spend(1)``
        call, so counting it here would inflate the reconstructed spend
        above what was ever truly spent live.
        """
        return sum(
            1
            for key, result in self._entries.items()
            if key.rpartition(":")[2].isdigit()
            and not (isinstance(result, dict) and result.get("tool") == "finish")
        )
