# Shannon Gap Closure — L4L0 Superset Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close every real capability gap between L4L0 and the "shannon" reference project identified in `/home/kali/Downloads/references/shannon/SHANNON_VS_L4L0_COMPARISON.md`, and add genuinely new tool/skill capability beyond it — all in the L4L0-native way (agent freedom + skill-library methodology, never a fixed detector pipeline), so L4L0 becomes a strict superset.

**Architecture:** Fourteen independently-shippable tasks. Most are small, additive changes to existing modules (new optional dataclass fields, new pure utility functions, new agent tools mirroring an existing tool's exact pattern). Two tasks (per-child journaling, multi-scan support) touch `scan.py`'s central orchestration and must be sequenced relative to each other; everything else is file-disjoint and safe to parallelize.

**Tech Stack:** Python 3.13, FastAPI, pytest — matches the existing L4L0 codebase exactly, no new dependencies.

**Spec:** `/home/kali/.claude/plans/glowing-bubbling-parasol.md` (the approved design plan — read it for the "why" behind each task; this plan is its "how"). Ground truth for shannon's own architecture: `/home/kali/Downloads/references/shannon/SHANNON_VS_L4L0_COMPARISON.md`.

## Global Constraints

- No fixed-code vulnerability-decision gate anywhere — every new tool adds capability the agent may use or ignore; no new skill file is ever mandatory; nothing new gates or withholds a finding. This was independently verified true of the existing codebase before this plan was written; every task must preserve it.
- Shared mutable state touched by concurrently-running `spawn_agents` children must be lock-protected, matching the existing `Budget._lock`/`Tracer._lock`/`ScanRunner._graph_lock`/`HttpFirer._breaker_lock` pattern (found and fixed 3 times already in this project's history — Task 1 below is the 4th instance).
- No reference-project names anywhere in new code/docs/commits — describe patterns generically (this project's standing clean-room rule).
- New dataclass fields are always additive with defaults — no existing construction call site may break.
- `ruff check`, `ruff format`, `mypy` (strict), and the relevant pytest file(s) must pass before every commit; run the full non-integration/non-live suite (`uv run pytest -q -m "not integration and not live"`) before each task's final commit.
- New skill playbooks match the exact existing structure in `src/lalo/skills/content/vulnerabilities/race-conditions.md` (frontmatter + Attack Surface/Recon/Techniques/Proof Ladder/Validation/Impact/Summary, `[[wiki-link]]` cross-refs) — read it before writing a new one.
- Three capability-gap items require no code, only documentation, because direct source reading during planning showed they are already closed or much narrower than first assumed: **finding reconciliation across producers** (L4L0's single-producer, record-time `dedup_key` model never creates the two-producer attribution problem shannon's separate pentest+SAST pipelines have to solve), **GUI auth hardening** (the token was already built once and explicitly removed by this same operator's own prior request; the server is loopback-only regardless — left as-is per the operator's explicit confirmation this session), and **usage accounting under replay** (the resume-replay loop never re-enters the step loop for an already-journaled step at all, so the real double-count window is a single narrow crash-timing edge case, not the broad "any resumed step" problem — verify this against the live code before writing the note, don't just restate the claim). Task 11 below writes all three notes into one place; no other task should re-litigate any of them.

---

## Task 1: Lock `DurableJournal` + wire per-child journaling for resume

**Files:**
- Modify: `src/lalo/orchestrator/journal.py`
- Modify: `src/lalo/scan.py:975` (the `child_loop.run(task)` call site inside `_run_child`)
- Test: `tests/lalo/test_orchestrator.py`, `tests/lalo/test_scan.py`

**Interfaces:**
- Consumes: `AgentLoop.run(mission, *, journal=None, agent_key="root")` (existing, unchanged signature) — its resume-replay loop (`src/lalo/agent/loop.py:616-627`, `while journal.has(f"{agent_key}:{start_step}")`) and step-dispatch caching (`loop.py:707-713`, `journal.run_once(f"{agent_key}:{step}", _dispatch_once)`) already namespace by `agent_key`; today only `root_loop.run(self.config.mission, journal=journal, agent_key="root")` (`scan.py:1044`) opts in, `child_loop.run(task)` (`scan.py:975`) never does.
- Produces: `DurableJournal.record()` becomes thread-safe (a `threading.Lock()` guarding the file-append + in-memory dict update); every spawned child now journals its own steps under `agent_key=child_id` (child ids are already unique, e.g. `"agent-2"`, minted by `AgentCoordinator` — zero collision risk with `"root"` or a sibling).

- [ ] **Step 1: Write the failing concurrency test for `DurableJournal`**

```python
# tests/lalo/test_orchestrator.py (add near the existing DurableJournal tests)
import threading

def test_durable_journal_record_is_thread_safe_under_concurrent_writers(tmp_path):
    from lalo.orchestrator.journal import DurableJournal

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
```

- [ ] **Step 2: Run it to verify it fails or is flaky**

Run: `uv run pytest tests/lalo/test_orchestrator.py::test_durable_journal_record_is_thread_safe_under_concurrent_writers -v --count=5` (or run it 5 times manually if `pytest-repeat` isn't installed — check `pyproject.toml`'s dev dependencies first; if absent, just run the single command 5 times in a loop)
Expected: intermittent failures or corrupted/missing keys without the lock — a genuine race, not always visibly failing on every run (that's why it's run multiple times).

- [ ] **Step 3: Add the lock to `DurableJournal`**

In `src/lalo/orchestrator/journal.py`, add `import threading` to the imports, then add a lock field and guard `record()`'s body:

```python
class DurableJournal:
    def __init__(self, path: str | os.PathLike[str]) -> None:
        self.path = Path(path)
        self._entries: dict[str, Any] = {}
        self._ts: dict[str, float] = {}
        self._lock = threading.Lock()
        self._load()
```

```python
    def record(self, key: str, result: Any) -> None:
        # Serialize and durably write FIRST, update in-memory state only after
        # that succeeds — see the existing docstring reasoning above this
        # method for why. Locked because spawn_agents' concurrent children
        # now all journal through this same instance (Task 1 of the
        # shannon-gap-closure plan) — matches this project's existing
        # Budget/Tracer/ScanRunner._graph_lock/HttpFirer._breaker_lock pattern.
        ts = time.time()
        line = json.dumps({"key": key, "result": result, "ts": ts}, sort_keys=True)
        with self._lock:
            append_owner_only_line(self.path, line)
            self._entries[key] = result
            self._ts[key] = ts
```

`has()`/`get()`/`ts_for()`/`completed_keys()` read `self._entries`/`self._ts` without a lock — plain dict reads are safe under the GIL and these are read-only, matching this codebase's own existing convention (e.g. `Tracer.span()`'s `self.spans.append()` is likewise left unlocked, only `counter()`'s read-modify-write is guarded).

- [ ] **Step 4: Run the concurrency test 5x to verify it's now clean**

Run: `uv run pytest tests/lalo/test_orchestrator.py::test_durable_journal_record_is_thread_safe_under_concurrent_writers -v` five times in a row.
Expected: PASS every time.

- [ ] **Step 5: Write the failing test for per-child journaling**

Follow `tests/lalo/test_scan.py`'s existing scripted-provider convention (the same one used for `test_scan_runner_emits_shell_events_for_a_real_run_command_call` and the sequential-spawn usage-delta test — read those two for the exact fixture shape before writing this one). Script a scan whose root makes exactly one `spawn_agent` call where the child does one `run_command` call then finishes:

```python
def test_scan_runner_journals_a_spawned_childs_own_steps(tmp_path, monkeypatch):
    monkeypatch.setattr(scan_module, "docker_available", lambda: True)
    monkeypatch.setattr(scan_module, "RuntimeContainer", _FakeContainer)
    router = ModelRouter(
        providers={"fake": _ScriptedProvider(_respond_with_a_sequential_spawn)},
        routes={"reasoning": ("fake",), "review": ("fake",)},
        default_route=("fake",),
    )
    monkeypatch.setattr(scan_module, "build_router", lambda _settings: router)

    run_dir = tmp_path / "run"
    event_log = EventLog()
    config = ScanConfig(mission="find a bug", target_specs=["example.com"], run_dir=run_dir)
    ScanRunner(config, env={"ANTHROPIC_API_KEY": "sk-test"}, event_log=event_log).run()

    from lalo.orchestrator.journal import DurableJournal
    journal = DurableJournal(run_dir / "journal.jsonl")  # confirm the real path via _journal_path if this guess is wrong
    # The root's own step(s) are already journaled under "root:0", "root:1", ...
    # (pre-existing behavior). The new requirement: the spawned child's own
    # step(s) must ALSO be present, under its own agent_id ("agent-2").
    assert journal.has("agent-2:0")
```

(Reuse `_respond_with_a_sequential_spawn` from the earlier sequential-spawn test in this same file if it already exists — if not, write it following that test's exact `_respond_*` dispatch pattern.)

- [ ] **Step 6: Run it to verify it fails**

Run: `uv run pytest tests/lalo/test_scan.py::test_scan_runner_journals_a_spawned_childs_own_steps -v`
Expected: FAIL — `journal.has("agent-2:0")` is `False` (the child never journaled).

- [ ] **Step 7: Wire the child to journal its own steps**

In `src/lalo/scan.py`, change line 975's `result = child_loop.run(task)` to:

```python
                result = child_loop.run(task, journal=journal, agent_key=child_id)
```

(`journal` is already an in-scope closed-over variable — defined at `scan.py:925`, `journal = DurableJournal(_journal_path(self.config.run_dir))`, before `_run_child` is ever called. `child_id` is already the parameter `_run_child` receives.)

- [ ] **Step 8: Run to verify it passes, then the full non-integration/non-live suite**

Run: `uv run pytest tests/lalo/test_scan.py::test_scan_runner_journals_a_spawned_childs_own_steps -v`
Expected: PASS

Run: `uv run ruff check src/lalo tests/lalo --fix && uv run ruff format src/lalo tests/lalo && uv run mypy && uv run pytest -q -m "not integration and not live"`

- [ ] **Step 9: Commit**

```bash
git add src/lalo/orchestrator/journal.py src/lalo/scan.py tests/lalo/test_orchestrator.py tests/lalo/test_scan.py
git commit -m "feat(L4L0): lock DurableJournal and journal spawned children's own steps"
```

---

## Task 2: Interval-union wall-clock accounting

**Files:**
- Modify: `src/lalo/observability/tracing.py`
- Modify: `src/lalo/scan.py` (surface it in the end-of-run report/usage summary)
- Test: `tests/lalo/test_tracing.py`

**Interfaces:**
- Produces: `wall_clock_union(spans: list[Span]) -> float` — total real-world seconds covered by the given spans, merging overlapping `(wall_start, wall_start + duration)` intervals (so concurrent `spawn_agents` work is never double-counted).

- [ ] **Step 1: Write the failing tests**

```python
# tests/lalo/test_tracing.py
def test_wall_clock_union_of_non_overlapping_spans_sums_durations():
    from lalo.observability.tracing import Span, wall_clock_union
    a = Span(name="a", start=0.0, end=1.0, wall_start=100.0)
    b = Span(name="b", start=1.0, end=2.0, wall_start=200.0)  # starts well after a ends
    assert wall_clock_union([a, b]) == a.duration_ms / 1000 + b.duration_ms / 1000


def test_wall_clock_union_of_fully_overlapping_spans_counts_once():
    from lalo.observability.tracing import Span, wall_clock_union
    a = Span(name="a", start=0.0, end=10.0, wall_start=100.0)  # covers [100, 110)
    b = Span(name="b", start=0.0, end=10.0, wall_start=102.0)  # covers [102, 112), overlaps a
    result = wall_clock_union([a, b])
    assert result == 12.0  # union of [100,110) and [102,112) is [100,112) = 12s, not 20s


def test_wall_clock_union_ignores_spans_with_no_end():
    from lalo.observability.tracing import Span, wall_clock_union
    unfinished = Span(name="a", start=0.0, end=None, wall_start=100.0)
    assert wall_clock_union([unfinished]) == 0.0


def test_wall_clock_union_of_empty_list_is_zero():
    from lalo.observability.tracing import wall_clock_union
    assert wall_clock_union([]) == 0.0
```

- [ ] **Step 2: Run to verify they fail**

Run: `uv run pytest tests/lalo/test_tracing.py -k wall_clock_union -v`
Expected: FAIL with `ImportError: cannot import name 'wall_clock_union'`

- [ ] **Step 3: Implement `wall_clock_union`**

In `src/lalo/observability/tracing.py`, add after the `Span` class:

```python
def wall_clock_union(spans: list[Span]) -> float:
    """Total real-world seconds actually covered by ``spans``, merging any
    overlapping intervals — a spawn_agents fan-out's several concurrent
    spans must not be summed independently (that overcounts wall time by
    however much they overlapped); this reports what a wall clock watching
    the whole run would actually have shown."""
    intervals = sorted(
        (span.wall_start, span.wall_start + span.duration_ms / 1000.0)
        for span in spans
        if span.end is not None
    )
    if not intervals:
        return 0.0
    total = 0.0
    current_start, current_end = intervals[0]
    for start, end in intervals[1:]:
        if start <= current_end:
            current_end = max(current_end, end)
        else:
            total += current_end - current_start
            current_start, current_end = start, end
    total += current_end - current_start
    return total
```

- [ ] **Step 4: Run to verify they pass**

Run: `uv run pytest tests/lalo/test_tracing.py -k wall_clock_union -v`
Expected: PASS (4 tests)

- [ ] **Step 5: Surface it in the end-of-run summary**

In `src/lalo/scan.py`, find the `scan_completed` event's payload construction (near `usage_delta`, `report_paths` — search for `"scan_completed"`). Add one more field:

```python
                "wall_clock_seconds": wall_clock_union(tracer.spans),
```

Add the import: `from .observability.tracing import wall_clock_union` (check the exact existing import style for this module in `scan.py` first).

- [ ] **Step 6: Full check and commit**

```bash
uv run ruff check src/lalo tests/lalo --fix && uv run ruff format src/lalo tests/lalo && uv run mypy && uv run pytest -q -m "not integration and not live"
git add src/lalo/observability/tracing.py src/lalo/scan.py tests/lalo/test_tracing.py
git commit -m "feat(L4L0): interval-union wall-clock accounting for concurrent agent work"
```

---

## Task 3: Multi-scan support — key the runner slot and usage ledger by run-id

**Files:**
- Modify: `src/lalo/gui/app.py`
- Modify: `src/lalo/core/usage.py` (no signature change — just how `scan.py` calls it)
- Modify: `src/lalo/scan.py` (pass a per-run usage path)
- Test: `tests/lalo/test_gui_app.py`

**Interfaces:**
- Produces: `build_app`'s `current_runner: dict[str, ScanRunner | None] = {"runner": None}` (the current single global slot, `src/lalo/gui/app.py`, inside `build_app()`) becomes `current_runners: dict[str, ScanRunner] = {}` keyed by `run_id`; `/scan` checks whether *this* `run_id` is already running, not whether *any* scan is; `ScanConfig.usage_path` for a fresh (non-resumed) launch becomes `run_dir / "usage.json"` instead of the global `DEFAULT_USAGE_PATH`, matching every other per-run artifact's existing convention (`events.jsonl`, `graph.json`, `journal.jsonl`, `resume_manifest.json`).

- [ ] **Step 1: Read the current `/scan`, `/scan/stop`, and `/runs` handlers in full**

Read `src/lalo/gui/app.py`'s `build_app()` end to end — every place `current_runner["runner"]` is read or written (the launch check, the stop endpoint, the run-completion callback that clears it, `_list_runs`'s `running_run_id` derivation) — before editing, since this touches several call sites that must all move to the new keyed-dict shape together.

- [ ] **Step 2: Write the failing test proving two different runs can be launched**

```python
# tests/lalo/test_gui_app.py
def test_two_different_scans_can_be_launched_concurrently(tmp_path, monkeypatch):
    monkeypatch.setattr(app_module, "ScanRunner", _FakeScanRunner)  # reuse the existing fake
    client, _ = _client(runs_dir=tmp_path)
    r1 = client.post("/scan", json={"mission": "find a bug", "targets": ["a.example.com"]})
    assert r1.status_code == 200
    r2 = client.post("/scan", json={"mission": "find another bug", "targets": ["b.example.com"]})
    assert r2.status_code == 200  # today this would 409 — that's the gap this task closes


def test_relaunching_the_same_run_id_while_it_is_active_is_still_rejected(tmp_path, monkeypatch):
    monkeypatch.setattr(app_module, "ScanRunner", _FakeScanRunner)
    client, _ = _client(runs_dir=tmp_path)
    r1 = client.post("/scan", json={"mission": "find a bug", "targets": ["a.example.com"]})
    run_id = r1.json()["run_id"]  # confirm the real response shape carries this
    r2 = client.post("/scan", json={"resume_run_id": run_id})
    assert r2.status_code == 409
```

(Match the exact existing `_FakeScanRunner`/`_client` test helpers' current behavior — read them first; the fake may need a small extension to track its own `run_id` if it doesn't already.)

- [ ] **Step 3: Run to verify they fail**

Run: `uv run pytest tests/lalo/test_gui_app.py -k "two_different_scans or relaunching_the_same_run_id" -v`
Expected: the first test FAILs with a 409 on `r2` today.

- [ ] **Step 4: Re-key the runner slot**

In `src/lalo/gui/app.py`'s `build_app()`, replace:
```python
    current_runner: dict[str, ScanRunner | None] = {"runner": None}
```
with:
```python
    current_runners: dict[str, ScanRunner] = {}
```

Update every call site (found in Step 1) to use `current_runners.get(run_id)`/`current_runners[run_id] = runner`/`del current_runners[run_id]` instead of the old single-slot reads/writes — the `/scan` launch check becomes `if run_id in current_runners: return JSONResponse({"error": f"run {run_id!r} is already running"}, status_code=409)`, and `_list_runs`'s `running_run_id` derivation becomes a set membership check (`entry.name in current_runners`) rather than a single equality check.

- [ ] **Step 5: Per-run usage path**

In `src/lalo/scan.py`, wherever a fresh (non-resume) `ScanConfig` is constructed with `usage_path=DEFAULT_USAGE_PATH` (in `gui/app.py`'s `start_scan`, per the earlier GUI v2 plan's Task 4), change it to `usage_path=run_dir / "usage.json"`. Leave `DEFAULT_USAGE_PATH` itself untouched (still the fallback for any direct/CLI construction that doesn't specify a run dir) — this is purely about what the GUI passes.

- [ ] **Step 6: Run to verify it passes, then the full suite**

Run: `uv run pytest tests/lalo/test_gui_app.py -v`
Expected: PASS, including all pre-existing tests (the single-runner-slot behavior for the SAME run-id is preserved; only cross-run-id concurrency is newly allowed).

Run: `uv run ruff check src/lalo tests/lalo --fix && uv run ruff format src/lalo tests/lalo && uv run mypy && uv run pytest -q -m "not integration and not live"`

- [ ] **Step 7: Verify live, with Playwright**

Launch two scans against two different fake/unreachable targets in quick succession via the GUI (or via direct `POST /scan` calls while watching the GUI) and confirm both proceed rather than the second being rejected with "a scan is already running."

- [ ] **Step 8: Commit**

```bash
git add src/lalo/gui/app.py src/lalo/scan.py tests/lalo/test_gui_app.py
git commit -m "feat(L4L0): key the GUI runner slot and usage ledger by run-id, allowing concurrent scans"
```

---

## Task 4: Report finalization manifest

**Files:**
- Create: `src/lalo/report/manifest.py`
- Modify: `src/lalo/scan.py` (call it right after `write_report`)
- Test: `tests/lalo/test_report_manifest.py`

**Interfaces:**
- Consumes: `write_report(...) -> dict[str, Path]` (existing, `src/lalo/report/writer.py:89-98`, returns `report_paths`).
- Produces: `write_report_manifest(run_dir: Path, report_paths: dict[str, Path]) -> Path` (writes `report_manifest.json`, returns its path), `verify_report_manifest(run_dir: Path) -> list[str]` (returns a list of drift descriptions, empty if everything matches).

- [ ] **Step 1: Write the failing tests**

```python
# tests/lalo/test_report_manifest.py
import json

def test_write_report_manifest_records_path_and_digest_per_format(tmp_path):
    from lalo.report.manifest import write_report_manifest

    (tmp_path / "report.md").write_text("hello", encoding="utf-8")
    (tmp_path / "report.json").write_text('{"a": 1}', encoding="utf-8")
    report_paths = {"md": tmp_path / "report.md", "json": tmp_path / "report.json"}

    manifest_path = write_report_manifest(tmp_path, report_paths)

    data = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert set(data["artifacts"]) == {"md", "json"}
    assert data["artifacts"]["md"]["path"] == "report.md"
    assert len(data["artifacts"]["md"]["sha256"]) == 64
    assert "written_at" in data


def test_verify_report_manifest_reports_no_drift_when_unchanged(tmp_path):
    from lalo.report.manifest import write_report_manifest, verify_report_manifest

    (tmp_path / "report.md").write_text("hello", encoding="utf-8")
    write_report_manifest(tmp_path, {"md": tmp_path / "report.md"})

    assert verify_report_manifest(tmp_path) == []


def test_verify_report_manifest_reports_drift_when_a_file_changed(tmp_path):
    from lalo.report.manifest import write_report_manifest, verify_report_manifest

    (tmp_path / "report.md").write_text("hello", encoding="utf-8")
    write_report_manifest(tmp_path, {"md": tmp_path / "report.md"})
    (tmp_path / "report.md").write_text("changed", encoding="utf-8")

    drift = verify_report_manifest(tmp_path)
    assert len(drift) == 1
    assert "md" in drift[0]


def test_verify_report_manifest_reports_drift_when_a_file_is_missing(tmp_path):
    from lalo.report.manifest import write_report_manifest, verify_report_manifest

    (tmp_path / "report.md").write_text("hello", encoding="utf-8")
    write_report_manifest(tmp_path, {"md": tmp_path / "report.md"})
    (tmp_path / "report.md").unlink()

    drift = verify_report_manifest(tmp_path)
    assert len(drift) == 1
```

- [ ] **Step 2: Run to verify they fail**

Run: `uv run pytest tests/lalo/test_report_manifest.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'lalo.report.manifest'`

- [ ] **Step 3: Implement**

```python
# src/lalo/report/manifest.py
"""A finalization manifest for a run's report artifacts — per-format path,
SHA-256 digest, and write time — so a later resumed or re-run scan can
detect whether its own prior report is still byte-identical (adopt it)
or has drifted (rewrite it), instead of always rewriting unconditionally.
"""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path

from ..core.atomic_io import atomic_write_verified

_MANIFEST_FILENAME = "report_manifest.json"


def _sha256_of(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_report_manifest(run_dir: Path, report_paths: dict[str, Path]) -> Path:
    manifest = {
        "written_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "artifacts": {
            fmt: {"path": path.name, "sha256": _sha256_of(path)}
            for fmt, path in report_paths.items()
        },
    }
    manifest_path = run_dir / _MANIFEST_FILENAME
    atomic_write_verified(manifest_path, json.dumps(manifest, indent=2, sort_keys=True).encode("utf-8"))
    return manifest_path


def verify_report_manifest(run_dir: Path) -> list[str]:
    """Every drift between the recorded manifest and the artifacts on disk
    right now — a missing file, or one whose digest no longer matches.
    Empty list means everything is still exactly as recorded."""
    manifest_path = run_dir / _MANIFEST_FILENAME
    if not manifest_path.exists():
        return ["no report_manifest.json exists in this run directory"]
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    drift: list[str] = []
    for fmt, entry in manifest.get("artifacts", {}).items():
        artifact_path = run_dir / entry["path"]
        if not artifact_path.exists():
            drift.append(f"{fmt}: {entry['path']} is missing")
            continue
        actual = _sha256_of(artifact_path)
        if actual != entry["sha256"]:
            drift.append(f"{fmt}: {entry['path']} digest changed")
    return drift
```

- [ ] **Step 4: Run to verify they pass**

Run: `uv run pytest tests/lalo/test_report_manifest.py -v`
Expected: PASS (4 tests)

- [ ] **Step 5: Wire it into `ScanRunner`**

In `src/lalo/scan.py`, right after `report_paths = write_report(...)` (line ~1108), add:

```python
        write_report_manifest(self.config.run_dir, report_paths)
```

Add the import: `from .report.manifest import write_report_manifest`.

- [ ] **Step 6: Full check and commit**

```bash
uv run ruff check src/lalo tests/lalo --fix && uv run ruff format src/lalo tests/lalo && uv run mypy && uv run pytest -q -m "not integration and not live"
git add src/lalo/report/manifest.py src/lalo/scan.py tests/lalo/test_report_manifest.py
git commit -m "feat(L4L0): write a per-run report finalization manifest (path + sha256 per format)"
```

---

## Task 5: `Finding.source_location` + SARIF physical locations

**Files:**
- Modify: `src/lalo/findings/model.py` (`Finding` dataclass)
- Modify: `src/lalo/report/collect.py` (`FindingRecord`, its construction site)
- Modify: `src/lalo/report/sarif.py` (`_build_result`)
- Test: `tests/lalo/test_findings_model.py` or wherever `Finding` is tested, `tests/lalo/test_report_collect.py`, `tests/lalo/test_sarif.py`

**Interfaces:**
- Produces: `Finding.source_location: str | None = None` (a `"path/to/file.py:123"`-shaped string, never required — `REQUIRED_TEXT_FIELDS` unchanged), `FindingRecord.source_location: str | None = None` (mirrored the same way `dedup_key`/`status` were added in an earlier phase of this project), SARIF results gain a `physicalLocation` alongside the existing `logicalLocations` when `source_location` is set and parses as `"path:line"`.

- [ ] **Step 1: Write the failing tests**

```python
# wherever Finding/validate_finding_fields is already tested
def test_finding_accepts_an_optional_source_location():
    from lalo.findings.model import Finding
    f = Finding(
        title="t", description="d", vuln_class="sql-injection", target="x", evidence=["e"],
        evidence_excerpt="e", counterevidence="c", severity_change_conditions="s",
        remediation="r", cvss_breakdown={}, source_location="app/routes.py:42",
    )
    assert f.source_location == "app/routes.py:42"


def test_finding_source_location_defaults_to_none():
    from lalo.findings.model import Finding
    f = Finding(
        title="t", description="d", vuln_class="sql-injection", target="x", evidence=["e"],
        evidence_excerpt="e", counterevidence="c", severity_change_conditions="s",
        remediation="r", cvss_breakdown={},
    )
    assert f.source_location is None
```

```python
# tests/lalo/test_sarif.py
def test_sarif_result_includes_physical_location_when_source_location_present():
    from lalo.report.sarif import render_sarif
    record = _finding(source_location="app/routes.py:42")  # extend the existing test helper
    doc = render_sarif([record])
    location = doc["runs"][0]["results"][0]["locations"][0]
    assert location["physicalLocation"]["artifactLocation"]["uri"] == "app/routes.py"
    assert location["physicalLocation"]["region"]["startLine"] == 42


def test_sarif_result_has_no_physical_location_when_source_location_absent():
    from lalo.report.sarif import render_sarif
    record = _finding(source_location=None)
    doc = render_sarif([record])
    location = doc["runs"][0]["results"][0]["locations"][0]
    assert "physicalLocation" not in location
```

- [ ] **Step 2: Run to verify they fail**

Run: `uv run pytest tests/lalo/test_sarif.py -k physical_location -v`
Expected: FAIL — `Finding()`/`FindingRecord()`/`_finding()` reject the unexpected `source_location` kwarg.

- [ ] **Step 3: Add the field to `Finding`**

In `src/lalo/findings/model.py`, add to the dataclass (after `identities_confirmed`, keeping it additive/optional):

```python
    source_location: str | None = None
```

- [ ] **Step 4: Add the field to `FindingRecord`, thread it through construction**

In `src/lalo/report/collect.py`: add `source_location: str | None = None` to `FindingRecord`. Find the single `FindingRecord(...)` construction site (confirmed to be exactly one site earlier this session) and pass `source_location=node.get("source_location")` (or however the node's other optional fields are already read — match the existing pattern exactly).

- [ ] **Step 5: Add physical-location rendering to SARIF**

In `src/lalo/report/sarif.py`'s `_build_result`, after the existing `logicalLocations` entry:

```python
def _build_result(record: FindingRecord, rule_index: int) -> dict[str, Any]:
    logical_name = record.target + (f"#{record.param}" if record.param else "")
    message = f"{record.title}\n\n{record.description}" if record.description else record.title
    locations: list[dict[str, Any]] = [
        {"logicalLocations": [{"fullyQualifiedName": logical_name, "kind": "target"}]}
    ]
    if record.source_location and ":" in record.source_location:
        path, _, line_str = record.source_location.rpartition(":")
        if line_str.isdigit():
            locations.append(
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": path},
                        "region": {"startLine": int(line_str)},
                    }
                }
            )
    return {
        "ruleId": _rule_id(record),
        "ruleIndex": rule_index,
        "level": _sarif_level(record),
        "message": {"text": message or record.finding_id, "markdown": _result_markdown(record)},
        "locations": locations,
        "partialFingerprints": {
            "lalo/dedupKey": dedup_key(record.vuln_class, record.target, record.param)
        },
        "properties": {
            "security-severity": _security_severity(record),
            "lalo": {
                "confidence": record.confidence.score,
                "cvss_vector": record.cvss_vector,
                "evidence_grounded": record.evidence_grounded,
                "review_verdict": record.review_verdict,
            },
        },
    }
```

(A malformed `source_location` — no `:`, or a non-numeric suffix — silently degrades to target-only location, never raises; this is a best-effort convenience field, never required.)

- [ ] **Step 6: Run to verify they pass, then the full suite**

Run: `uv run pytest tests/lalo/test_sarif.py -v` and whichever file has the `Finding` tests.
Expected: PASS

Run: `uv run ruff check src/lalo tests/lalo --fix && uv run ruff format src/lalo tests/lalo && uv run mypy && uv run pytest -q -m "not integration and not live"`

- [ ] **Step 7: Commit**

```bash
git add src/lalo/findings/model.py src/lalo/report/collect.py src/lalo/report/sarif.py tests/lalo/test_sarif.py
git commit -m "feat(L4L0): optional Finding.source_location, rendered as a real SARIF physicalLocation"
```

---

## Task 6: Source-aware review skill playbook

**Files:**
- Create: `src/lalo/skills/content/methodology/source-aware-review.md`
- Test: `tests/lalo/test_skills_recall.py` (retrievability, matching Task 18's pattern from the earlier plan)

**Interfaces:**
- Consumes: `recall()`'s existing retrieval mechanism (`src/lalo/skills/recall.py`) and this project's existing `methodology/` skill subdirectory (already holds `cli-tool-discipline.md`, `closure-discipline.md`, `semantic-confusion.md`, `severity-calibration.md` — read one of these, not a `vulnerabilities/` playbook, to confirm the exact frontmatter/structure convention this specific subdirectory actually uses before writing, since it may differ slightly from the vuln-class playbook shape).
- Produces: methodology content teaching the agent how to work when a target's source repository is available (already fully reachable via the existing free `run_command` shell — `git clone`/`grep`/read — no new tool needed): mapping attack surface from routes/handlers/models, framework-family dangerous-sink patterns, and explicitly stating this feeds the SAME `record_finding` tool everything else uses, optionally filling the new `source_location` field from Task 5.

- [ ] **Step 1: Read the exact structure convention for this subdirectory**

Read `src/lalo/skills/content/methodology/closure-discipline.md` in full (it's already referenced by every vulnerability playbook's Validation section, so it's a load-bearing, well-established example of this subdirectory's real shape) and match its frontmatter/heading structure exactly — do not assume it's identical to the `vulnerabilities/` playbooks without checking.

- [ ] **Step 2: Write the playbook**

Write real, substantive content (not filler) covering: when source is available (operator-declared repo URL/path in the mission text — the agent already has full shell access to `git clone`/read it), how to map attack surface from routes/handlers/ORM-models/middleware across common frameworks, dangerous-sink grep patterns (raw SQL string interpolation, `eval`/deserialize calls, unsanitized template rendering, missing authorization decorators) as *starting points the agent should verify against, never trust blindly*, cross-referencing a source finding with the SAME `record_finding` tool and its existing required fields, and how to fill the new optional `source_location` field (Task 5) with a real `"path:line"` when the evidence traces to a specific line. No reference-project names anywhere in the content.

- [ ] **Step 3: Write the retrievability test**

```python
def test_recall_surfaces_the_source_aware_review_skill_for_a_relevant_query():
    skills = load_skills(...)  # match whatever fixture the existing recall() tests already use
    results = recall("source code attack surface routes handlers dangerous sink", skills, top_k=3)
    assert any(r.skill.name == "source-aware-review" for r in results)
```

- [ ] **Step 4: Run to verify it passes**

Run: `uv run pytest tests/lalo/test_skills_recall.py -k source_aware -v`
Expected: PASS

- [ ] **Step 5: Full check and commit**

```bash
uv run ruff check src/lalo tests/lalo --fix && uv run ruff format src/lalo tests/lalo && uv run mypy && uv run pytest -q -m "not integration and not live"
git add src/lalo/skills/content/methodology/source-aware-review.md tests/lalo/test_skills_recall.py
git commit -m "feat(L4L0): add a source-aware code-review methodology skill playbook"
```

---

## Task 7: Opt-in tool-confinement infrastructure (unused by default)

**Files:**
- Modify: `src/lalo/scan.py` (`_build_registry`'s signature)
- Test: `tests/lalo/test_scan.py`

**Interfaces:**
- Produces: `_build_registry(graph, agent_id, *, tool_names: frozenset[str] | None = None)` — when `tool_names` is `None` (every existing call site, unchanged), behavior is byte-identical to today (the full tool list). When given, only tools whose registered name is in `tool_names` are included. Nothing in this codebase passes a non-`None` value yet — this task ships the mechanism only, per the design plan's explicit "infrastructure a future narrow, opt-in role could use, never applied automatically" scoping.

- [ ] **Step 1: Write the failing test**

```python
def test_build_registry_with_no_tool_names_filter_includes_everything(tmp_path):
    # existing behavior, unchanged - construct however the existing _build_registry tests do
    ...


def test_build_registry_with_a_tool_names_filter_only_includes_those_tools():
    registry = _build_registry(graph, "agent-1", tool_names=frozenset({"record_finding", "recall"}))
    tool_names = {t.name for t in registry.tools}  # or however ToolRegistry exposes this - check
    assert tool_names == {"record_finding", "recall"}
```

(Match whatever existing test already exercises `_build_registry` for the exact construction args/fixture shape — read it first rather than guessing.)

- [ ] **Step 2: Run to verify the filtered test fails**

Run: `uv run pytest tests/lalo/test_scan.py -k tool_names_filter -v`
Expected: FAIL — `_build_registry()` has no `tool_names` parameter yet.

- [ ] **Step 3: Add the optional filter**

In `src/lalo/scan.py`, find `_build_registry`'s definition and the `tools: list[Tool] = [...]` list construction. Add the parameter and a filter step right before `return ToolRegistry(tools)`:

```python
        def _build_registry(
            graph: ReachabilityGraph, self_id: str, *, tool_names: frozenset[str] | None = None
        ) -> ToolRegistry:
            ...
            tools: list[Tool] = [
                # ... unchanged, every existing entry ...
            ]
            if tool_names is not None:
                tools = [tool for tool in tools if tool.name in tool_names]
            return ToolRegistry(tools)
```

Do not change any existing call site (`_build_registry(graph, root_id)`, `_build_registry(child_graph, child_id)`) — both keep working exactly as before since `tool_names` defaults to `None`.

- [ ] **Step 4: Run to verify both pass, then the full suite**

Run: `uv run pytest tests/lalo/test_scan.py -k "tool_names_filter or build_registry" -v`
Expected: PASS

Run: `uv run ruff check src/lalo tests/lalo --fix && uv run ruff format src/lalo tests/lalo && uv run mypy && uv run pytest -q -m "not integration and not live"`

- [ ] **Step 5: Commit**

```bash
git add src/lalo/scan.py tests/lalo/test_scan.py
git commit -m "feat(L4L0): opt-in tool-name filtering in _build_registry (unused by default)"
```

---

## Task 8: `ws_fire` — scope-checked WebSocket tool

**Files:**
- Modify: `src/lalo/execution/tool.py`
- Modify: `src/lalo/scan.py` (register it in `_build_registry`'s tool list)
- Test: `tests/lalo/test_execution_tool.py`

**Interfaces:**
- Consumes: `ScopeGuard.check`/`.pin_for_connect` (existing, the same primitives `HttpFirer` already uses — do not build a second scope-check mechanism). Read `src/lalo/execution/firer.py`'s `fire()` in full for the exact pinned-dial pattern to mirror (resolve once, dial the pinned IP, preserve the original `Host` header, validate TLS SNI against the real hostname).
- Produces: `build_ws_fire_tool(scope: ScopeGuard) -> FunctionTool` — connects to a `ws://`/`wss://` URL (scope-checked and pinned-IP-dialed the same way), sends one message, reads back whatever arrives within a timeout, then closes. Requires a WebSocket client library — check `pyproject.toml`'s existing dependencies first; if `websockets` or `httpx`'s own WS support isn't already a dependency, this task must add exactly one (prefer `websockets` — the standard, actively-maintained choice — over rolling a raw WS handshake by hand).

- [ ] **Step 1: Confirm/add the dependency**

Check `pyproject.toml` for an existing WebSocket-capable dependency. If none exists, add `websockets` via `uv add websockets` (not raw pip) and note the exact version pinned.

- [ ] **Step 2: Write the failing test**

```python
def test_ws_fire_sends_a_message_and_returns_the_response(monkeypatch):
    class _FakeWSConnection:
        async def send(self, message): self.sent = message
        async def recv(self): return "pong"
        async def __aenter__(self): return self
        async def __aexit__(self, *exc): return False

    async def _fake_connect(url, **kwargs):
        return _FakeWSConnection()

    monkeypatch.setattr("lalo.execution.tool.websockets.connect", _fake_connect)
    scope = ScopeGuard(allowed=["example.com"])  # match this project's real ScopeGuard construction
    tool = build_ws_fire_tool(scope)
    result = tool.func({"url": "ws://example.com/socket", "message": "ping"})
    assert result.ok
    assert "pong" in result.observation


def test_ws_fire_rejects_an_out_of_scope_url():
    scope = ScopeGuard(allowed=["example.com"])
    tool = build_ws_fire_tool(scope)
    result = tool.func({"url": "ws://evil.example.org/socket", "message": "ping"})
    assert not result.ok
    assert "scope" in result.observation.lower()
```

(Match `ScopeGuard`'s exact real constructor and `HttpFirer`'s existing test file's mocking conventions — read `tests/lalo/test_firer.py` first for the established pattern.)

- [ ] **Step 3: Run to verify they fail**

Run: `uv run pytest tests/lalo/test_execution_tool.py -k ws_fire -v`
Expected: FAIL — `build_ws_fire_tool` doesn't exist.

- [ ] **Step 4: Implement `build_ws_fire_tool`**

In `src/lalo/execution/tool.py`, add `import asyncio` and `import websockets` to the imports, then, mirroring `build_http_tool`'s existing shape:

```python
def build_ws_fire_tool(scope: ScopeGuard) -> FunctionTool:
    """Connect to a WebSocket endpoint, send one message, read back whatever
    arrives — scope-checked and pinned-IP-dialed the same way HttpFirer's
    fire() already is, since many modern API targets (chat, live dashboards,
    GraphQL subscriptions) are WebSocket-native and were previously only
    reachable via the free shell writing a throwaway client script."""

    def _ws_fire(args: dict[str, object]) -> ToolResult:
        url = str_arg(args, "url", "")
        message = str_arg(args, "message", "")
        if not url:
            return ToolResult(observation="error: 'url' is required", ok=False)
        decision = scope.check(url.replace("ws://", "http://").replace("wss://", "https://"))
        if not decision.allowed:
            return ToolResult(observation=f"error: scope {decision.reason}", ok=False)
        timeout = float(args.get("timeout", 5.0) or 5.0)

        async def _run() -> str:
            async with websockets.connect(url, open_timeout=timeout) as conn:
                if message:
                    await conn.send(message)
                try:
                    return str(await asyncio.wait_for(conn.recv(), timeout=timeout))
                except (TimeoutError, asyncio.TimeoutError):
                    return "(no response within timeout)"

        try:
            response = asyncio.run(_run())
        except Exception as exc:  # noqa: BLE001 - report every connection failure, never crash the agent
            return ToolResult(observation=f"error: {type(exc).__name__}: {exc}", ok=False)
        return ToolResult(observation=response[:_MAX_BODY_CHARS], ok=True)

    return FunctionTool(
        name="ws_fire",
        description=(
            "Connect to a WebSocket endpoint, send one message, and return whatever comes "
            'back. args: {"url": str (ws:// or wss://), "message": str (optional), '
            '"timeout": number (optional, seconds, default 5.0)}'
        ),
        func=_ws_fire,
    )
```

(This does NOT pin the dial to a resolved IP the way `HttpFirer.fire()` does — `websockets.connect` doesn't expose the same low-level socket-injection seam `httpx` does. Note this honestly in the docstring as a real, smaller-but-still-real scope check than `HttpFirer`'s — the URL-level `scope.check()` still blocks an out-of-scope host from ever being dialed, just without the TOCTOU-closing pinned-IP guarantee HTTP gets. If a stronger guarantee is needed later, revisit with a lower-level WS-over-pinned-socket implementation.)

- [ ] **Step 5: Run to verify they pass**

Run: `uv run pytest tests/lalo/test_execution_tool.py -k ws_fire -v`
Expected: PASS

- [ ] **Step 6: Register the tool**

In `src/lalo/scan.py`'s `_build_registry`, add `build_ws_fire_tool(scope)` alongside the other firing tools in the `tools: list[Tool] = [...]` list.

- [ ] **Step 7: Full check and commit**

```bash
uv run ruff check src/lalo tests/lalo --fix && uv run ruff format src/lalo tests/lalo && uv run mypy && uv run pytest -q -m "not integration and not live"
git add pyproject.toml uv.lock src/lalo/execution/tool.py src/lalo/scan.py tests/lalo/test_execution_tool.py
git commit -m "feat(L4L0): ws_fire agent tool for WebSocket-native targets"
```

---

## Task 9: `dns_query` — scope-checked DNS resolver tool

**Files:**
- Modify: `src/lalo/execution/tool.py`
- Modify: `src/lalo/scan.py` (register it)
- Test: `tests/lalo/test_execution_tool.py`

**Interfaces:**
- Produces: `build_dns_query_tool(scope: ScopeGuard) -> FunctionTool` — direct resolver queries (A/AAAA/CNAME/TXT/NS/MX, plus a zone-transfer attempt) for a scope-checked hostname.

- [ ] **Step 1: Confirm/add the dependency**

Check `pyproject.toml` for `dnspython` (the standard choice for real DNS record types beyond what stdlib `socket.getaddrinfo` exposes — stdlib alone can't do TXT/NS/MX/zone-transfer). Add via `uv add dnspython` if absent.

- [ ] **Step 2: Write the failing tests**

```python
def test_dns_query_returns_records_for_an_in_scope_host(monkeypatch):
    class _FakeAnswer:
        def __init__(self, text): self._text = text
        def __str__(self): return self._text

    def _fake_resolve(host, record_type):
        return [_FakeAnswer("93.184.216.34")]

    monkeypatch.setattr("lalo.execution.tool.dns.resolver.resolve", _fake_resolve)
    scope = ScopeGuard(allowed=["example.com"])
    tool = build_dns_query_tool(scope)
    result = tool.func({"host": "example.com", "record_type": "A"})
    assert result.ok
    assert "93.184.216.34" in result.observation


def test_dns_query_rejects_an_out_of_scope_host():
    scope = ScopeGuard(allowed=["example.com"])
    tool = build_dns_query_tool(scope)
    result = tool.func({"host": "evil.example.org", "record_type": "A"})
    assert not result.ok
    assert "scope" in result.observation.lower()


def test_dns_query_reports_nxdomain_as_a_clean_non_error_result(monkeypatch):
    import dns.resolver

    def _raise_nxdomain(host, record_type):
        raise dns.resolver.NXDOMAIN()

    monkeypatch.setattr("lalo.execution.tool.dns.resolver.resolve", _raise_nxdomain)
    scope = ScopeGuard(allowed=["example.com"])
    tool = build_dns_query_tool(scope)
    result = tool.func({"host": "nonexistent.example.com", "record_type": "A"})
    assert result.ok  # a real, informative "no such record" answer, not a tool failure
    assert "no" in result.observation.lower()
```

- [ ] **Step 3: Run to verify they fail**

Run: `uv run pytest tests/lalo/test_execution_tool.py -k dns_query -v`
Expected: FAIL — `build_dns_query_tool` doesn't exist.

- [ ] **Step 4: Implement**

```python
# in src/lalo/execution/tool.py, add "import dns.resolver" to the imports

_ALLOWED_DNS_RECORD_TYPES = frozenset({"A", "AAAA", "CNAME", "TXT", "NS", "MX"})


def build_dns_query_tool(scope: ScopeGuard) -> FunctionTool:
    """Direct resolver queries for subdomain/DNS-based recon - scope-checked
    the same way every other firing tool is, closing the gap where DNS
    recon otherwise only happens if the agent thinks to shell out to
    dig/nslookup itself."""

    def _dns_query(args: dict[str, object]) -> ToolResult:
        host = str_arg(args, "host", "")
        record_type = str_arg(args, "record_type", "A").upper()
        if not host:
            return ToolResult(observation="error: 'host' is required", ok=False)
        if record_type not in _ALLOWED_DNS_RECORD_TYPES:
            return ToolResult(
                observation=f"error: 'record_type' must be one of {sorted(_ALLOWED_DNS_RECORD_TYPES)}",
                ok=False,
            )
        decision = scope.check(f"dns://{host}")
        if not decision.allowed:
            return ToolResult(observation=f"error: scope {decision.reason}", ok=False)
        try:
            answers = dns.resolver.resolve(host, record_type)
            records = [str(a) for a in answers]
        except dns.resolver.NXDOMAIN:
            return ToolResult(observation=f"no {record_type} record for {host} (NXDOMAIN)", ok=True)
        except dns.resolver.NoAnswer:
            return ToolResult(observation=f"no {record_type} record for {host} (no answer)", ok=True)
        except Exception as exc:  # noqa: BLE001 - report every resolver failure, never crash the agent
            return ToolResult(observation=f"error: {type(exc).__name__}: {exc}", ok=False)
        return ToolResult(observation="\n".join(records)[:_MAX_BODY_CHARS], ok=True)

    return FunctionTool(
        name="dns_query",
        description=(
            "Resolve a DNS record for an in-scope host. args: "
            '{"host": str, "record_type": "A"|"AAAA"|"CNAME"|"TXT"|"NS"|"MX" (optional, default "A")}'
        ),
        func=_dns_query,
    )
```

(`scope.check(f"dns://{host}")` reuses `ScopeGuard`'s existing generic scheme-agnostic hostname check — confirm this call shape against `ScopeGuard.check`'s actual signature first; if it strictly expects an `http(s)://` URL, adapt to whatever scheme-neutral check method it already exposes rather than fabricating a `dns://` scheme it doesn't understand.)

- [ ] **Step 5: Run to verify they pass**

Run: `uv run pytest tests/lalo/test_execution_tool.py -k dns_query -v`
Expected: PASS

- [ ] **Step 6: Register the tool, full check, commit**

Add `build_dns_query_tool(scope)` to `_build_registry`'s tool list in `src/lalo/scan.py`.

```bash
uv run ruff check src/lalo tests/lalo --fix && uv run ruff format src/lalo tests/lalo && uv run mypy && uv run pytest -q -m "not integration and not live"
git add pyproject.toml uv.lock src/lalo/execution/tool.py src/lalo/scan.py tests/lalo/test_execution_tool.py
git commit -m "feat(L4L0): dns_query agent tool for scope-checked DNS recon"
```

---

## Task 10: Three new skill playbooks — GraphQL, WebSocket issues, cloud-IAM privilege-escalation chains

**Files:**
- Create: `src/lalo/skills/content/vulnerabilities/graphql-abuse.md`
- Create: `src/lalo/skills/content/vulnerabilities/websocket-issues.md`
- Create: `src/lalo/skills/content/vulnerabilities/cloud-iam-privilege-escalation.md`
- Test: `tests/lalo/test_skills_recall.py`

**Interfaces:**
- Same playbook structure as `race-conditions.md` (frontmatter + Attack Surface/Recon/Techniques/Proof Ladder/Validation/Impact/Summary, `[[wiki-link]]` cross-refs).

- [ ] **Step 1: Check existing cloud coverage first**

Before writing the cloud-IAM playbook, list `src/lalo/skills/content/vulnerabilities/*.md` and read any filename suggesting existing cloud/IAM coverage in full, to write something genuinely distinct rather than duplicating it — per this project's own "verify against the live file" discipline.

- [ ] **Step 2: Write `graphql-abuse.md`**

Real content: introspection-query abuse for schema/attack-surface discovery, batching/aliasing query-cost attacks (a DoS-adjacent resource-exhaustion technique, not a data-exfiltration one — calibrate severity accordingly per `[[severity-calibration]]`), authorization bypass via nested resolvers (a field-level auth check present on a top-level query but missing on a nested/related-object resolver reachable a different way), and how a positive finding here still needs `[[closure-discipline]]`'s same evidence-provenance standard.

- [ ] **Step 3: Write `websocket-issues.md`**

Real content: missing/permissive `Origin` header validation on the WS handshake (cross-site WebSocket hijacking), message-level injection (a WS message body treated as trusted the way an HTTP body wouldn't be), missing per-message authorization (a connection authenticated once at handshake time but never re-checked per subsequent message/action). References the new `ws_fire` tool (Task 8) as the mechanism for testing these techniques.

- [ ] **Step 4: Write `cloud-iam-privilege-escalation.md`**

Real content distinct from whatever existing cloud coverage Step 1 found: chaining together individually-minor IAM permissions into privilege escalation (e.g. a role allowed to attach policies to itself, or pass an over-privileged role to a service it controls), cross-referencing the L4L0 access-control-matrix tool (`access_control_matrix`, already built) for tracking which identity/permission combinations have actually been tested versus assumed safe.

- [ ] **Step 5: Write the retrievability tests**

```python
def test_recall_surfaces_graphql_abuse_for_a_relevant_query():
    ...  # mirror Task 6's Step 3 pattern, one assertion per new playbook


def test_recall_surfaces_websocket_issues_for_a_relevant_query():
    ...


def test_recall_surfaces_cloud_iam_privilege_escalation_for_a_relevant_query():
    ...
```

- [ ] **Step 6: Run to verify they pass, full check, commit**

```bash
uv run pytest tests/lalo/test_skills_recall.py -k "graphql or websocket_issues or cloud_iam" -v
uv run ruff check src/lalo tests/lalo --fix && uv run ruff format src/lalo tests/lalo && uv run mypy && uv run pytest -q -m "not integration and not live"
git add src/lalo/skills/content/vulnerabilities/graphql-abuse.md src/lalo/skills/content/vulnerabilities/websocket-issues.md src/lalo/skills/content/vulnerabilities/cloud-iam-privilege-escalation.md tests/lalo/test_skills_recall.py
git commit -m "feat(L4L0): 3 new skill playbooks (GraphQL abuse, WebSocket issues, cloud-IAM privilege escalation)"
```

---

## Task 11: Document the three already-closed/narrowed gaps (no code)

**Files:**
- Modify: `docs/OPERATING.md` (or wherever this project's operator-facing architecture notes already live — check first)

**Interfaces:** None — documentation only.

- [ ] **Step 1: Write the three notes**

Add a short section (or three) stating plainly, for a future reader comparing L4L0 against any reference project again:

(a) **Finding reconciliation across producers** is a non-issue for L4L0's architecture, since `dedup_key(vuln_class, target, param)` at record time is the only producer this project has — the attribution-leak problem a multi-pipeline architecture has to solve with a dedicated reconciliation stage doesn't arise here.

(b) **GUI auth** was deliberately removed (not merely never built) — the server binds to `127.0.0.1` only regardless, and re-adding it was explicitly declined by the operator when directly asked, so it should not be re-proposed as a "gap" without a fresh, explicit ask.

(c) **Usage accounting under replay** is narrower than it first looks: read `src/lalo/agent/loop.py`'s `run()` method once more to confirm this before writing the note — the resume-replay loop (`while journal.has(f"{agent_key}:{start_step}")`) never re-enters the main step loop for an already-journaled step, so `_complete()` (and the `record_usage()` call inside it) is never re-invoked for a step whose result is already in the journal. The only real double-count window is narrower still: a crash between `_complete()` recording usage and `journal.run_once` finishing the tool-dispatch write for that SAME step — on resume, that step re-runs in full (a genuinely new LLM call), double-recording that one step's usage. Document this precisely (not the broader "any resumed step might double-count" assumption an earlier draft of this project's own design plan made before checking the real code) and, matching this project's own existing precedent for a structurally similar narrow race in `core/usage.py`'s own module docstring, explicitly accept it rather than building extra machinery for a single-step, low-probability edge case.

- [ ] **Step 2: Commit**

```bash
git add docs/OPERATING.md
git commit -m "docs(L4L0): record why finding reconciliation, GUI auth, and most of usage-replay are non-gaps"
```

---

## Task 12: Complete the benchmark harness — live coverage for all 4 lab targets + a real results writeup

**Files:**
- Create: `tests/lalo/test_eval_live_crapi.py`, `tests/lalo/test_eval_live_juice_shop.py`, `tests/lalo/test_eval_live_dvwa.py` (mirroring `tests/lalo/test_eval_live_vampi.py`'s exact existing structure — read it first)
- Create: `docs/BENCHMARK.md`

**Interfaces:**
- Consumes: `src/lalo/eval/cases.py` (`run_case`), `src/lalo/eval/scoring.py` (`recall`, `precision`, `calibration_gap`, `score_composite`, `append_composite_history`), `src/lalo/eval/targets.py` (`VAMPI`, `CRAPI`, `JUICE_SHOP`, `DVWA`, `LAB_TARGETS`) — all already fully built and tested this project. This task is completing live coverage and publishing real numbers, not building a scorer from scratch.

- [ ] **Step 1: Read the existing VAmPI live test in full**

Read `tests/lalo/test_eval_live_vampi.py` and `tests/lalo/test_eval_live_vampi_agent.py` end to end — the `@pytest.mark.live` + `skipif(not reachable, ...)` pattern, how the target container is expected to already be running (not spun up by the test itself — per this project's own "bring targets up on-demand, tear down immediately after" convention), and exactly how a real scan's resulting graph gets fed into `run_case(CRAPI, graph)`/`score_composite(...)`.

- [ ] **Step 2: Write the analogous live tests for crAPI, Juice Shop, and DVWA**

Mirror the VAmPI test's exact structure for each of the other three `LAB_TARGETS` entries — same `@pytest.mark.live` marker, same reachability-skip pattern, same `run_case`/`score_composite` usage, targeting each one's own `BenchmarkCase` from `eval/targets.py`.

- [ ] **Step 3: Bring up each target on-demand, run the live suite once, tear down immediately**

For each of the four targets in turn: bring the container up (`docker compose`/`docker run`, whichever this project's own eval-target convention already uses), run `uv run pytest tests/lalo/test_eval_live_<target>.py -v -m live`, record the real `CompositeScore` output, tear the container down immediately after. Do this for all four before writing the results doc — the numbers must be real, not estimated.

- [ ] **Step 4: Call `append_composite_history` once per target run**

Confirm (from Step 1's reading) whether the existing live tests already call `append_composite_history` themselves; if not, add one call per test recording that target's own `CompositeScore` into a durable history file (check `eval/scoring.py`'s own docstring/existing callers for the conventional path).

- [ ] **Step 5: Write `docs/BENCHMARK.md`**

A short, honest results writeup: one row per target (VAmPI/crAPI/Juice Shop/DVWA) with its real recall/precision/calibration-gap numbers from Step 3, the exact commit this was run against, and a short methodology paragraph (recall AND precision measured, never gated — matching this project's own confidence-not-gates design, explicitly contrasted with a reference CTF-style benchmark's binary win-rate-only convention, described generically without naming it).

- [ ] **Step 6: Commit**

```bash
git add tests/lalo/test_eval_live_crapi.py tests/lalo/test_eval_live_juice_shop.py tests/lalo/test_eval_live_dvwa.py docs/BENCHMARK.md
git commit -m "feat(L4L0): live benchmark coverage for all 4 lab targets + a published results writeup"
```

---

## Final check (after all 12 tasks)

Run: `uv run ruff check src/lalo tests/lalo && uv run ruff format --check src/lalo tests/lalo && uv run mypy && uv run pytest -q -m "not integration and not live"`

Then a full live walkthrough: launch two concurrent scans via the GUI (Task 3) and confirm both proceed independently with separate usage ledgers; kill one mid-flight after it has spawned at least one child, resume it, and confirm the child resumes from its last journaled step rather than restarting (Task 1); confirm the end-of-run summary shows a real wall-clock number distinct from summed span durations for a run with concurrent `spawn_agents` work (Task 2); open a generated report's SARIF output and confirm a source-review finding (if one was recorded with `source_location` set) carries a real `physicalLocation` (Task 5); confirm `report_manifest.json` exists in a completed run's directory and `verify_report_manifest` reports no drift immediately after (Task 4). Finally, run the completed benchmark suite (Task 12) end to end one more time as its own regression proof.
