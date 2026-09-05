"""Tests for the durable journal, budget bands, and scheduler."""

from __future__ import annotations

from lalo.orchestrator import (
    Budget,
    BudgetBand,
    DurableJournal,
    ScanSchedule,
    due_schedules,
)


def test_run_once_executes_then_caches(tmp_path) -> None:
    journal = DurableJournal(tmp_path / "j.jsonl")
    calls = {"n": 0}

    def step() -> dict[str, int]:
        calls["n"] += 1
        return {"fired": 1}

    assert journal.run_once("fire:1", step) == {"fired": 1}
    assert journal.run_once("fire:1", step) == {"fired": 1}
    assert calls["n"] == 1  # second call served from the journal, no re-execution


def test_resume_after_crash_skips_completed_steps(tmp_path) -> None:
    path = tmp_path / "j.jsonl"
    first = DurableJournal(path)
    first.run_once("fire:1", lambda: {"ok": True})
    # Simulate crash + restart: a fresh journal reloads the file.
    resumed = DurableJournal(path)
    calls = {"n": 0}

    def side_effecting() -> dict[str, bool]:
        calls["n"] += 1
        return {"ok": False}

    result = resumed.run_once("fire:1", side_effecting)
    assert result == {"ok": True}  # cached from before the crash
    assert calls["n"] == 0  # the side effect did NOT re-run


def test_torn_last_line_is_ignored(tmp_path) -> None:
    path = tmp_path / "j.jsonl"
    j = DurableJournal(path)
    j.run_once("a", lambda: 1)
    with path.open("a", encoding="utf-8") as fh:
        fh.write('{"key": "b", "resu')  # torn write from a crash
    reloaded = DurableJournal(path)
    assert reloaded.has("a")
    assert not reloaded.has("b")


def test_budget_bands() -> None:
    b = Budget(ceiling=100)
    assert b.band() is BudgetBand.OK
    b.spend(70)
    assert b.band() is BudgetBand.NOTICE
    b.spend(20)  # 90
    assert b.band() is BudgetBand.URGENT
    b.spend(6)  # 96
    assert b.band() is BudgetBand.CRITICAL
    b.spend(10)  # 106
    assert b.band() is BudgetBand.EXHAUSTED
    assert b.remaining() == 0


def test_subagent_reserve() -> None:
    b = Budget(ceiling=100, subagent_reserve=0.1)
    b.spend(85)
    assert b.can_spend_subagent(5)  # 90 <= 90 reserve line
    assert not b.can_spend_subagent(10)  # would cross into the reserve


def test_scheduler_due() -> None:
    s1 = ScanSchedule("1", "a.example.com", "scan", interval_s=60, last_run=None)
    s2 = ScanSchedule("2", "b.example.com", "scan", interval_s=60, last_run=100.0)
    due = due_schedules([s1, s2], now=140.0)
    assert s1 in due  # never run -> due
    assert s2 not in due  # ran at 100, interval 60, now 140 -> not yet
    assert s2 in due_schedules([s2], now=161.0)
