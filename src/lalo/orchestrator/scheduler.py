"""Scan scheduling for continuous attack-surface monitoring (ASM).

Original — confirmed via each reference project's own comparison
documentation, across all five, that none schedules autonomous re-scans
(two reference platforms each run one CLI-triggered flow per invocation;
a reference agent's viewer/CLI has no repeat-scan concept). No reference
source to read here.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass


@dataclass
class ScanSchedule:
    scan_id: str
    target: str
    objective: str
    interval_s: float
    last_run: float | None = None

    def due(self, now: float) -> bool:
        return self.last_run is None or (now - self.last_run) >= self.interval_s

    def mark_run(self, now: float) -> None:
        self.last_run = now


def due_schedules(schedules: Sequence[ScanSchedule], now: float) -> list[ScanSchedule]:
    return [s for s in schedules if s.due(now)]
