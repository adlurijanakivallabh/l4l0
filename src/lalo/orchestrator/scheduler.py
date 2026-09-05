"""Scan scheduling for continuous attack-surface monitoring (ASM)."""

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
