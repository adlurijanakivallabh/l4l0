"""Tests for the durable journal, budget bands, and scheduler."""

from __future__ import annotations

import os
import stat
import threading

import pytest

from lalo.orchestrator import (
    Budget,
    BudgetBand,
    DurableJournal,
    RunStatus,
    ScanSchedule,
    due_schedules,
)
from lalo.orchestrator.budget import BudgetExceededError, SubagentReserveExceededError


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
    resumed = DurableJournal(path)  # simulate crash + restart
    calls = {"n": 0}

    def side_effecting() -> dict[str, bool]:
        calls["n"] += 1
        return {"ok": False}

    result = resumed.run_once("fire:1", side_effecting)
    assert result == {"ok": True}
    assert calls["n"] == 0  # the side effect did NOT re-run


def test_a_failed_durable_write_never_updates_in_memory_state(tmp_path) -> None:
    # Before the fix, record() updated _entries BEFORE the durable write, so a
    # serialization failure left has()==True with nothing ever on disk -- the
    # step looked "done" in-process but a resumed process wouldn't see it at
    # all, and it would never be retried either. An unrecorded step must look
    # exactly like it never ran.
    path = tmp_path / "j.jsonl"
    journal = DurableJournal(path)
    calls = {"n": 0}

    def not_json_serializable() -> dict[str, object]:
        calls["n"] += 1
        return {"data": {1, 2}}  # a set -- json.dumps raises TypeError

    with pytest.raises(TypeError):
        journal.run_once("k", not_json_serializable)

    assert journal.has("k") is False
    # json.dumps() now runs before the file is ever opened, so a serialization
    # failure doesn't even create an empty file.
    assert path.exists() is False

    # A retry within the same process actually re-runs the step (it was never
    # recorded as done) rather than silently returning a stale cached value.
    def now_serializable() -> dict[str, int]:
        calls["n"] += 1
        return {"data": 1}

    assert journal.run_once("k", now_serializable) == {"data": 1}
    assert calls["n"] == 2
    assert journal.has("k") is True


def test_journal_file_is_owner_only_regardless_of_a_permissive_umask(tmp_path) -> None:
    path = tmp_path / "j.jsonl"
    old_umask = os.umask(0o000)
    try:
        DurableJournal(path).run_once("k", lambda: {"ok": True})
    finally:
        os.umask(old_umask)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_journal_tightens_permissions_even_on_a_pre_existing_looser_file(tmp_path) -> None:
    path = tmp_path / "j.jsonl"
    path.write_text("")
    path.chmod(0o644)
    DurableJournal(path).run_once("k", lambda: {"ok": True})
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_torn_last_line_is_ignored(tmp_path) -> None:
    path = tmp_path / "j.jsonl"
    j = DurableJournal(path)
    j.run_once("a", lambda: 1)
    with path.open("a", encoding="utf-8") as fh:
        fh.write('{"key": "b", "resu')  # torn write from a crash
    reloaded = DurableJournal(path)
    assert reloaded.has("a")
    assert not reloaded.has("b")


def test_highest_band_wins_not_first() -> None:
    # A sudden jump straight to 96% must read CRITICAL, not NOTICE.
    b = Budget(ceiling=100, spent=96)
    assert b.band() is BudgetBand.CRITICAL


def test_root_and_subagent_have_different_bands() -> None:
    b = Budget(ceiling=100, spent=72)
    assert b.band(is_root=True) is BudgetBand.NOTICE  # root band is 70
    assert b.band(is_root=False) is BudgetBand.OK  # subagent band is 75 -> not yet


def test_root_hard_ceiling_raises() -> None:
    b = Budget(ceiling=100, spent=100)
    with pytest.raises(BudgetExceededError):
        b.check_root()


def test_subagent_reserve_raises_before_root_ceiling() -> None:
    b = Budget(ceiling=100, spent=91)  # >= 90% reserve, but < 100% ceiling
    with pytest.raises(SubagentReserveExceededError):
        b.check_subagent()
    b.check_root()  # root ceiling not yet reached -> does not raise


def test_budget_exhausted_status_is_never_completed() -> None:
    # The exact fail-open gap a reference project's own CI docs disclose about
    # itself: a budget-capped run must never report as a clean "completed".
    exhausted = Budget(ceiling=100, spent=100)
    assert exhausted.outcome() is RunStatus.BUDGET_EXHAUSTED
    assert exhausted.outcome() is not RunStatus.COMPLETED
    running = Budget(ceiling=100, spent=50)
    assert running.outcome() is RunStatus.RUNNING


def test_resume_restores_true_cumulative_spend_not_zero() -> None:
    # A resumed run must not "earn a fresh budget" — construct from persisted spend.
    persisted_spend = 97
    resumed = Budget(ceiling=100, spent=persisted_spend)
    with pytest.raises(SubagentReserveExceededError):
        resumed.check_subagent()  # immediately over reserve, exactly as before the crash


def test_budget_spend_is_thread_safe_under_concurrent_calls() -> None:
    """Without the lock, self.spent += amount from N threads loses
    increments (multi-lane concurrent sub-agents share ONE Budget) - the
    budget would silently become MORE permissive than configured instead of
    raising a visible error once genuinely exhausted."""
    budget = Budget(ceiling=100_000)
    threads = [threading.Thread(target=lambda: budget.spend(1)) for _ in range(500)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert budget.spent == 500


def test_scheduler_due() -> None:
    s1 = ScanSchedule("1", "a.example.com", "scan", interval_s=60, last_run=None)
    s2 = ScanSchedule("2", "b.example.com", "scan", interval_s=60, last_run=100.0)
    due = due_schedules([s1, s2], now=140.0)
    assert s1 in due  # never run -> due
    assert s2 not in due  # ran at 100, interval 60, now 140 -> not yet
    assert s2 in due_schedules([s2], now=161.0)
