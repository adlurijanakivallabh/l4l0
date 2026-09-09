"""Tests for the durable journal, budget bands, and scheduler."""

from __future__ import annotations

import os
import stat
import threading
import time

import pytest

from lalo.orchestrator import (
    Budget,
    BudgetBand,
    Checkpoint,
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


def test_torn_last_line_logs_nothing(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A torn final line is an expected, routine crash artifact - it must
    stay silent, matching the existing test_torn_last_line_is_ignored
    behavior exactly."""
    import lalo.orchestrator.journal as journal_module

    warnings: list[str] = []
    monkeypatch.setattr(
        journal_module._log, "warning", lambda msg, *args, **kwargs: warnings.append(msg % args)
    )
    path = tmp_path / "j.jsonl"
    j = DurableJournal(path)
    j.run_once("a", lambda: 1)
    with path.open("a", encoding="utf-8") as fh:
        fh.write('{"key": "b", "resu')  # torn write from a crash
    DurableJournal(path)
    assert warnings == []


def test_a_malformed_middle_line_logs_a_warning_not_a_silent_drop(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Regression: _load() used to `continue` on ANY unparseable line, not
    just the final one - a corrupted MIDDLE record (not a crash-mid-write
    artifact) was dropped with zero trace anywhere. A dropped checkpoint
    here means a resumed step whose journal record didn't survive gets
    silently re-executed (re-firing a request, re-spawning a child)."""
    import lalo.orchestrator.journal as journal_module

    warnings: list[str] = []
    monkeypatch.setattr(
        journal_module._log, "warning", lambda msg, *args, **kwargs: warnings.append(msg % args)
    )
    path = tmp_path / "j.jsonl"
    j = DurableJournal(path)
    j.run_once("a", lambda: 1)
    j.run_once("c", lambda: 3)
    # Corrupt the FIRST line in place (not the last) - a real middle-record
    # corruption, not a crash-mid-write torn tail.
    lines = path.read_text(encoding="utf-8").splitlines()
    lines[0] = "not valid json at all {{{"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    reloaded = DurableJournal(path)
    assert not reloaded.has("a")  # the corrupted record really is gone
    assert reloaded.has("c")  # the rest of the file still loads
    assert any("unparseable" in w for w in warnings)


def test_completed_step_count_sums_every_agent_key_namespace(tmp_path) -> None:
    """A resumed run must reconstruct its TRUE cumulative Budget.spent
    across root AND every spawned child, not just root's own replayed
    steps - completed_step_count() is the single source of truth for that
    total, so it has to count real step entries in every namespace.

    agent-2:2 is a "finish" entry - agent/loop.py journals it under a
    digit-suffixed step key (like any other step) but never calls
    budget.spend() for it (finish returns immediately, before the
    dispatch path's spend(1) call). So it must NOT be counted here either,
    or a resumed Budget.spent would be inflated above what was ever truly
    spent live - see test_completed_step_count_excludes_finish_entries.
    """
    path = tmp_path / "j.jsonl"
    j = DurableJournal(path)
    j.record("root:0", {"tool": "recall", "args": {}, "observation": "x"})
    j.record("root:1", {"tool": "spawn_agent", "args": {}, "observation": "x"})
    j.record("agent-2:0", {"tool": "http", "args": {}, "observation": "x"})
    j.record("agent-2:1", {"tool": "record_finding", "args": {}, "observation": "x"})
    j.record("agent-2:2", {"tool": "finish", "args": {}, "observation": "x"})
    # Non-step breadcrumb/namespace keys must NOT be counted as steps.
    j.record("agent-2:spawned", {"name": "Child", "task": "x", "parent_id": "root", "depth": 1})
    j.record("agent-2:finished", {"stop_reason": "finished", "summary": "x"})
    j.record("review:finding-abc123", {"confidence_score": 80, "verdict": "confirmed"})

    assert j.completed_step_count() == 4


def test_completed_step_count_excludes_finish_entries(tmp_path) -> None:
    """agent/loop.py's finish handling (mid-loop and the reserved final
    turn) journals under a normal digit-suffixed step key but never spends
    budget for it - the only two live budget.spend(1) call sites are the
    dispatch path and the no-tool-call nudge path. A journal holding only
    a nudge followed by a finish must report 1 real spent step, not 2."""
    path = tmp_path / "j.jsonl"
    j = DurableJournal(path)
    j.record("agent-3:0", {"tool": "_nudge", "args": {}, "observation": "x"})
    j.record("agent-3:1", {"tool": "finish", "args": {"summary": "done"}, "observation": "done"})

    assert j.completed_step_count() == 1


def test_completed_step_count_on_a_fresh_journal_is_zero(tmp_path) -> None:
    assert DurableJournal(tmp_path / "j.jsonl").completed_step_count() == 0


def test_checkpoint_carries_a_wall_clock_timestamp() -> None:
    # Checkpoint is a standalone dataclass -- DurableJournal itself stores raw
    # (key -> result) pairs internally and never constructs one (confirmed:
    # no `Checkpoint(` call site anywhere in src/lalo), so this exercises the
    # dataclass's own default directly rather than via DurableJournal.get().
    before = time.time()
    checkpoint = Checkpoint(key="k", result={"ok": True})
    after = time.time()
    assert before <= checkpoint.ts <= after


def test_journal_records_a_real_wall_clock_timestamp_retrievable_via_ts_for(tmp_path) -> None:
    path = tmp_path / "j.jsonl"
    journal = DurableJournal(path)
    before = time.time()
    journal.record("fire:1", {"fired": 1})
    after = time.time()
    assert before <= journal.ts_for("fire:1") <= after


def test_journal_ts_for_an_unknown_key_is_none_not_an_error(tmp_path) -> None:
    journal = DurableJournal(tmp_path / "j.jsonl")
    assert journal.ts_for("nonexistent") is None


def test_journal_ts_survives_a_reload_after_a_crash(tmp_path) -> None:
    path = tmp_path / "j.jsonl"
    first = DurableJournal(path)
    first.record("fire:1", {"fired": 1})
    original_ts = first.ts_for("fire:1")
    reloaded = DurableJournal(path)  # simulate crash + restart
    assert reloaded.ts_for("fire:1") == original_ts


def test_durable_journal_record_is_thread_safe_under_concurrent_writers(tmp_path) -> None:
    journal = DurableJournal(tmp_path / "journal.jsonl")
    barrier = threading.Barrier(8)
    errors: list[BaseException] = []

    def _writer(agent_key: str) -> None:
        barrier.wait()
        for step in range(50):
            try:
                journal.record(f"{agent_key}:{step}", {"ok": True})
            except BaseException as exc:  # noqa: BLE001 - capture, don't hide, for the assertion below
                errors.append(exc)

    threads = [threading.Thread(target=_writer, args=(f"agent-{i}",)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors
    # Every one of the 8*50 keys must be present and independently readable -
    # a lost write under a race would show up as a missing key here.
    for i in range(8):
        for step in range(50):
            assert journal.has(f"agent-{i}:{step}")


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
