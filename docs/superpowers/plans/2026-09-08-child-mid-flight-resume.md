# Per-Child Mid-Flight Resume Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A child that was genuinely mid-execution when the process
crashed resumes from its own last completed step on the next run, via one
explicit, agent-chosen `spawn_agent` call — instead of silently restarting
under a brand-new id.

**Architecture:** Two small journal breadcrumbs (`{child_id}:spawned` /
`{child_id}:finished`), written by `_run_child`, distinguish "genuinely
orphaned" from "reached a terminal result" without any changes to
`AgentLoop.run()`'s core step loop. On resume, `scan.py` reconstructs
orphaned nodes into a fresh `AgentCoordinator` with a new `ORPHANED`
status; `spawn_agent` gains an optional `resume_agent_id` that reuses an
orphan's own id/task instead of minting a new child.

**Tech Stack:** Python 3.13, the existing `DurableJournal`
(`orchestrator/journal.py`, unchanged — only new *keys*, no new methods),
`AgentCoordinator` (`agent/spawn.py`, gains `AgentStatus.ORPHANED`,
`register_orphan`, `has_node`).

**Spec:** `docs/superpowers/specs/2026-09-08-child-mid-flight-resume-design.md`

## Global Constraints

- `AgentLoop.run()` (`agent/loop.py`) is NOT modified by this plan at all
  — its existing per-agent-key replay loop already does everything a
  resumed child needs once it's re-entered under its own original
  `agent_key`.
- The two new breadcrumb keys use the *exact* `"{agent_key}:{suffix}"`
  shape `_max_spawned_agent_number` (`scan.py`) already parses — a
  non-numeric suffix (`"spawned"`, `"finished"`) never collides with a
  real numbered step and needs zero changes to that function.
- A resumed orphan's *task* always comes from the coordinator's own node
  (set from the original `:spawned` breadcrumb) — never from whatever
  `task` text a later `spawn_agent` call happens to include alongside
  `resume_agent_id`, mirroring `/scan`'s own `resume_run_id` precedent.
- `resume_agent_id` lands on `spawn_agent` only, not `spawn_agents` (the
  parallel fan-out) — bulk-resuming several orphans from one crashed batch
  is explicitly deferred, not required for this plan.

---

## Task 1: `AgentStatus.ORPHANED` + `AgentCoordinator.register_orphan`/`has_node`

**Files:**
- Modify: `src/lalo/agent/spawn.py` (`AgentStatus`; `AgentCoordinator`)
- Test: `tests/lalo/test_spawn.py`

**Interfaces:**
- Produces: `AgentStatus.ORPHANED`;
  `AgentCoordinator.register_orphan(agent_id: str, name: str, task: str, *,
  parent_id: str | None, depth: int, role: str) -> None`;
  `AgentCoordinator.has_node(agent_id: str) -> bool`.

- [ ] **Step 1: Write the failing tests**

```python
def test_register_orphan_creates_a_node_with_orphaned_status() -> None:
    coord = AgentCoordinator(max_depth=5)
    coord.register_orphan(
        "agent-7", "Source Reviewer", "read the repo",
        parent_id="agent-1", depth=1, role="source_reviewer",
    )
    node = coord.node("agent-7")
    assert node.status is AgentStatus.ORPHANED
    assert node.name == "Source Reviewer"
    assert node.task == "read the repo"
    assert node.parent_id == "agent-1"
    assert node.depth == 1
    assert node.role == "source_reviewer"


def test_has_node_reports_existence() -> None:
    coord = AgentCoordinator(max_depth=5)
    root = coord.register_root("root", "mission")
    assert coord.has_node(root) is True
    assert coord.has_node("agent-999") is False


def test_render_tree_shows_an_orphaned_node() -> None:
    coord = AgentCoordinator(max_depth=5)
    coord.register_orphan(
        "agent-7", "Source Reviewer", "read the repo",
        parent_id=None, depth=0, role="full",
    )
    tree = coord.render_tree()
    assert "Source Reviewer (agent-7) [orphaned]" in tree
```

- [ ] **Step 2: Run to verify they fail**

Run: `uv run pytest tests/lalo/test_spawn.py -k "register_orphan or has_node_reports_existence or shows_an_orphaned_node" -v`
Expected: FAIL — `AttributeError: 'AgentCoordinator' object has no attribute 'register_orphan'`

- [ ] **Step 3: Implement**

In `src/lalo/agent/spawn.py`, `AgentStatus` (currently):

```python
class AgentStatus(StrEnum):
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
```

gains one member:

```python
class AgentStatus(StrEnum):
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    ORPHANED = "orphaned"
```

Add two methods to `AgentCoordinator`, near `node`/`children_of`:

```python
    def has_node(self, agent_id: str) -> bool:
        return agent_id in self._nodes

    def register_orphan(
        self,
        agent_id: str,
        name: str,
        task: str,
        *,
        parent_id: str | None,
        depth: int,
        role: str,
    ) -> None:
        """Reconstruct a child that was genuinely mid-execution when the
        process crashed - its own journal entries survive under its
        original agent_id, but nothing durable ever recorded it as a node
        in THIS coordinator (a fresh instance every process start). Called
        once per detected orphan, before any live dispatch, from
        scan.py's own resume path - see _find_orphaned_children there.
        """
        with self._lock:
            self._nodes[agent_id] = AgentNode(
                agent_id,
                name,
                task,
                parent_id=parent_id,
                depth=depth,
                status=AgentStatus.ORPHANED,
                role=role,
            )
```

- [ ] **Step 4: Run to verify they pass, then the full existing spawn suite**

Run: `uv run pytest tests/lalo/test_spawn.py -v`
Expected: PASS, every test.

- [ ] **Step 5: Full check and commit**

```bash
uv run ruff check src/lalo tests/lalo --fix && uv run ruff format src/lalo tests/lalo && uv run mypy && uv run pytest -q -m "not integration and not live"
git add src/lalo/agent/spawn.py tests/lalo/test_spawn.py
git commit -m "feat(L4L0): AgentStatus.ORPHANED + AgentCoordinator.register_orphan/has_node"
```

---

## Task 2: `spawn_agent` gains `resume_agent_id`

**Files:**
- Modify: `src/lalo/agent/spawn.py` (`build_spawn_tools`'s `_spawn`; its
  tool description)
- Test: `tests/lalo/test_spawn.py`

**Interfaces:**
- Consumes: `AgentCoordinator.has_node`/`register_orphan` (Task 1).
- Produces: `spawn_agent` accepts an optional `"resume_agent_id"` arg;
  when given and it names a real `ORPHANED` node, `run_child` is called
  with that exact id and the node's own recorded `task` (never the new
  call's `task` text), and `coordinator.spawn(...)` is never called for
  it (no new id minted).

- [ ] **Step 1: Write the failing tests**

```python
def test_spawn_agent_resumes_a_real_orphan_using_its_original_task() -> None:
    coord = AgentCoordinator(max_depth=5)
    root = coord.register_root("root", "mission")
    coord.register_orphan(
        "agent-7", "Source Reviewer", "the ORIGINAL task text",
        parent_id=root, depth=1, role="source_reviewer",
    )
    calls: list[tuple[str, str, str]] = []

    def run_child(child_id: str, name: str, task: str) -> tuple[str, list[str], bool]:
        calls.append((child_id, name, task))
        return "continued and confirmed", ["f-1"], True

    spawn_tool, _ = build_spawn_tools(coord, run_child, self_id=root)
    registry = ToolRegistry([spawn_tool])
    result = registry.dispatch(
        "spawn_agent",
        {"resume_agent_id": "agent-7", "task": "a DIFFERENT task the model tried to give"},
    )
    assert result.ok is True
    assert calls == [("agent-7", "Source Reviewer", "the ORIGINAL task text")]
    assert coord.node("agent-7").status is AgentStatus.COMPLETED


def test_spawn_agent_rejects_a_resume_agent_id_that_is_not_a_known_orphan() -> None:
    coord = AgentCoordinator(max_depth=5)
    root = coord.register_root("root", "mission")
    spawn_tool, _ = build_spawn_tools(coord, lambda *_a: ("", [], True), self_id=root)
    registry = ToolRegistry([spawn_tool])
    result = registry.dispatch("spawn_agent", {"resume_agent_id": "agent-999"})
    assert result.ok is False


def test_spawn_agent_rejects_resuming_a_node_that_is_not_orphaned() -> None:
    coord = AgentCoordinator(max_depth=5)
    root = coord.register_root("root", "mission")
    child = coord.spawn(root, "child", "subtask")
    coord.record_result(child, summary="done", finding_ids=[])  # now COMPLETED, not orphaned
    spawn_tool, _ = build_spawn_tools(coord, lambda *_a: ("", [], True), self_id=root)
    registry = ToolRegistry([spawn_tool])
    result = registry.dispatch("spawn_agent", {"resume_agent_id": child})
    assert result.ok is False
```

- [ ] **Step 2: Run to verify they fail**

Run: `uv run pytest tests/lalo/test_spawn.py -k "resumes_a_real_orphan or rejects_a_resume_agent_id or rejects_resuming_a_node_that_is_not_orphaned" -v`
Expected: FAIL — the first test's `calls` list stays empty (nothing named
`resume_agent_id` is read yet, so `_spawn` falls through its normal
required-`name`/`task` validation and rejects the call outright).

- [ ] **Step 3: Implement**

In `src/lalo/agent/spawn.py`, `_spawn` (currently, after Task 2 of the
source-reviewer-agent-role plan already added `role` handling):

```python
    def _spawn(args: dict[str, object]) -> ToolResult:
        name = str_arg(args, "name").strip()
        task = str_arg(args, "task").strip()
        role = str_arg(args, "role", "full").strip() or "full"
        if not name or not task:
            return ToolResult(observation="error: 'name' and 'task' are required", ok=False)
        if role not in valid_roles:
            return ToolResult(
                observation=f"error: 'role' must be one of {sorted(valid_roles)}", ok=False
            )
        warning = _duplicate_task_warning(coordinator, self_id, task)
        try:
            child_id = coordinator.spawn(self_id, name, task, role=role)
        except SpawnDepthExceededError as exc:
            return ToolResult(observation=f"error: {exc}", ok=False)
        try:
            summary, finding_ids, success = run_child(child_id, name, task)
        except Exception as exc:  # noqa: BLE001 - a crashed child must still reach a terminal
            ...
```

becomes (a resume branch checked first, returning early — the existing
fresh-spawn path below it is completely untouched):

```python
    def _spawn(args: dict[str, object]) -> ToolResult:
        resume_agent_id = str_arg(args, "resume_agent_id", "").strip()
        if resume_agent_id:
            if not coordinator.has_node(resume_agent_id):
                return ToolResult(
                    observation=(
                        f"error: {resume_agent_id!r} is not a known agent - "
                        "call view_agent_graph to see valid ids"
                    ),
                    ok=False,
                )
            node = coordinator.node(resume_agent_id)
            if node.status is not AgentStatus.ORPHANED:
                return ToolResult(
                    observation=(
                        f"error: {resume_agent_id!r} is not orphaned (status: "
                        f"{node.status.value}) - only an orphaned agent can be resumed"
                    ),
                    ok=False,
                )
            try:
                summary, finding_ids, success = run_child(resume_agent_id, node.name, node.task)
            except Exception as exc:  # noqa: BLE001 - a crashed child must still reach a
                # terminal status, matching the fresh-spawn path's own crash handling.
                error = f"child crashed: {type(exc).__name__}: {exc}"
                coordinator.record_result(
                    resume_agent_id, summary=error, finding_ids=[], success=False
                )
                return ToolResult(observation=f"error resuming {resume_agent_id}: {error}", ok=False)
            coordinator.record_result(
                resume_agent_id, summary=summary, finding_ids=finding_ids, success=success
            )
            report = {
                "agent_id": resume_agent_id,
                "success": success,
                "summary": summary,
                "filed_finding_ids": finding_ids,
            }
            return ToolResult(observation=json.dumps(report), ok=success)

        name = str_arg(args, "name").strip()
        task = str_arg(args, "task").strip()
        role = str_arg(args, "role", "full").strip() or "full"
        if not name or not task:
            return ToolResult(observation="error: 'name' and 'task' are required", ok=False)
        if role not in valid_roles:
            return ToolResult(
                observation=f"error: 'role' must be one of {sorted(valid_roles)}", ok=False
            )
        warning = _duplicate_task_warning(coordinator, self_id, task)
        try:
            child_id = coordinator.spawn(self_id, name, task, role=role)
        except SpawnDepthExceededError as exc:
            return ToolResult(observation=f"error: {exc}", ok=False)
        try:
            summary, finding_ids, success = run_child(child_id, name, task)
        except Exception as exc:  # noqa: BLE001 - a crashed child must still reach a terminal
            ...
```

(Everything from `warning = _duplicate_task_warning(...)` onward in the
fresh-spawn path is completely unchanged — only reproduced above to show
exactly where the new early-return branch is inserted relative to it.)

Update the `spawn_agent` tool's description to add the new arg
(everything else verbatim):

```python
            'args: {"name": str, "task": str, "role": "full"|"source_reviewer" (optional, '
            'default "full" - source_reviewer confines the child to run_command/'
            "record_finding/recall/query_graph/note only, no live-firing tools and no "
            "further spawning - use it for a subtask that's purely reading and reasoning "
            'about source code), "resume_agent_id": str (optional - resume an orphaned '
            "agent shown by view_agent_graph as [orphaned] (interrupted by a crash on a "
            "prior run) instead of starting a new one; when set, 'name'/'task'/'role' are "
            "ignored and the agent's own original task continues from its last completed "
            'step)}'
        ),
        func=_spawn,
    )
```

- [ ] **Step 4: Run to verify they pass, then the full existing spawn suite**

Run: `uv run pytest tests/lalo/test_spawn.py -v`
Expected: PASS, every test.

- [ ] **Step 5: Full check and commit**

```bash
uv run ruff check src/lalo tests/lalo --fix && uv run ruff format src/lalo tests/lalo && uv run mypy && uv run pytest -q -m "not integration and not live"
git add src/lalo/agent/spawn.py tests/lalo/test_spawn.py
git commit -m "feat(L4L0): spawn_agent can resume a real orphaned agent by id"
```

---

## Task 3: `_run_child` writes the spawn/finish breadcrumbs

**Files:**
- Modify: `src/lalo/scan.py` (`_run_child`)
- Test: `tests/lalo/test_scan.py`

**Interfaces:**
- Produces: two new journal keys per spawned child —
  `f"{child_id}:spawned"` (written before `child_loop.run(...)` starts) and
  `f"{child_id}:finished"` (written after it returns).

- [ ] **Step 1: Write the failing test**

```python
def test_run_child_journals_a_spawned_breadcrumb_before_running_and_a_finished_one_after(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(scan_module, "docker_available", lambda: True)
    monkeypatch.setattr(scan_module, "RuntimeContainer", _FakeContainer)
    router = ModelRouter(
        providers={"fake": _ScriptedProvider(_respond_with_a_sequential_spawn)},
        routes={"reasoning": ("fake",), "review": ("fake",)},
        default_route=("fake",),
    )
    monkeypatch.setattr(scan_module, "build_router", lambda _settings: router)

    run_dir = tmp_path / "run"
    config = ScanConfig(
        mission="find a bug, spawning one child for a focused subtask",
        target_specs=["c.example.com"],
        run_dir=run_dir,
        usage_path=tmp_path / "usage.json",
    )
    ScanRunner(config, env={"ANTHROPIC_API_KEY": "sk-test"}).run()

    journal = DurableJournal(run_dir / "journal.jsonl")
    assert journal.has("agent-2:spawned")
    spawned = journal.get("agent-2:spawned")
    assert spawned["name"] == "Child C"
    assert spawned["task"] == "CHILD-C-TASK: test host c.example.com"
    assert spawned["parent_id"] == "agent-1"
    assert spawned["depth"] == 1
    assert spawned["role"] == "full"
    assert journal.has("agent-2:finished")
```

(`_respond_with_a_sequential_spawn`/`ScanConfig`/`ScanRunner`/
`_ScriptedProvider`/`_FakeContainer`/`ModelRouter`/`DurableJournal`/
`scan_module` are all already imported/defined in `tests/lalo/test_scan.py`
— confirmed this session, every one is already used by a neighboring test
in this same file.)

- [ ] **Step 2: Run to verify it fails**

Run: `uv run pytest tests/lalo/test_scan.py -k journals_a_spawned_breadcrumb -v`
Expected: FAIL — `assert journal.has("agent-2:spawned")` is `False`.

- [ ] **Step 3: Implement**

In `src/lalo/scan.py`'s `_run_child` (currently, after the source-reviewer
role's own Task 3 already added the `role`/`tool_names` lookup):

```python
            def _run_child(child_id: str, _name: str, task: str) -> tuple[str, list[str], bool]:
                # Locked: spawn_agents can run several _run_child calls for
                ...
                with self._graph_lock:
                    before = set(agent_graph.nodes_of_kind(NodeKind.FINDING))
                    child_graph = isolate_for_child(agent_graph)
                role = coordinator.node(child_id).role
                child_registry = _build_registry(
                    child_graph, child_id, tool_names=_ROLE_TOOL_NAMES[role]
                )
                child_loop = AgentLoop(
                    router,
                    child_registry,
                    system_prompt=system_prompt,
                    config=AgentConfig(max_steps=self.config.max_steps, is_root=False),
                    tracer=tracer,
                    budget=budget,
                    on_event=lambda ev, pl: self._on_agent_event(child_id, ev, pl),
                    should_stop=self._should_stop,
                    usage_path=self.config.usage_path,
                    agent_id=child_id,
                    get_steering=self._pending_steering,
                    pricing_table=self.config.pricing_table,
                )
                result = child_loop.run(task, journal=journal, agent_key=child_id)
                after = set(child_graph.nodes_of_kind(NodeKind.FINDING))
                new_ids = list(after - before)
                with self._graph_lock:
                    merge_finding_nodes(agent_graph, child_graph, new_ids)
                return result.summary, new_ids, result.stop_reason in _TERMINAL_SUCCESS
```

becomes (two new lines: one right before `child_loop.run(...)`, one right
after):

```python
            def _run_child(child_id: str, _name: str, task: str) -> tuple[str, list[str], bool]:
                # Locked: spawn_agents can run several _run_child calls for
                ...
                with self._graph_lock:
                    before = set(agent_graph.nodes_of_kind(NodeKind.FINDING))
                    child_graph = isolate_for_child(agent_graph)
                node = coordinator.node(child_id)
                role = node.role
                child_registry = _build_registry(
                    child_graph, child_id, tool_names=_ROLE_TOOL_NAMES[role]
                )
                child_loop = AgentLoop(
                    router,
                    child_registry,
                    system_prompt=system_prompt,
                    config=AgentConfig(max_steps=self.config.max_steps, is_root=False),
                    tracer=tracer,
                    budget=budget,
                    on_event=lambda ev, pl: self._on_agent_event(child_id, ev, pl),
                    should_stop=self._should_stop,
                    usage_path=self.config.usage_path,
                    agent_id=child_id,
                    get_steering=self._pending_steering,
                    pricing_table=self.config.pricing_table,
                )
                # Durable breadcrumbs for orphan detection on a future resume
                # (see _find_orphaned_children) - a crash between these two
                # journal.record calls leaves ":spawned" with no matching
                # ":finished", the unambiguous signal that this specific
                # child never reached ANY terminal AgentResult (finished,
                # budget-exhausted, cancelled all return normally from
                # run() below and DO get ":finished" - only a genuine
                # process-level crash mid-run skips it).
                journal.record(
                    f"{child_id}:spawned",
                    {
                        "name": node.name,
                        "task": task,
                        "parent_id": node.parent_id,
                        "depth": node.depth,
                        "role": role,
                    },
                )
                result = child_loop.run(task, journal=journal, agent_key=child_id)
                journal.record(
                    f"{child_id}:finished",
                    {"stop_reason": result.stop_reason, "summary": result.summary},
                )
                after = set(child_graph.nodes_of_kind(NodeKind.FINDING))
                new_ids = list(after - before)
                with self._graph_lock:
                    merge_finding_nodes(agent_graph, child_graph, new_ids)
                return result.summary, new_ids, result.stop_reason in _TERMINAL_SUCCESS
```

(`node = coordinator.node(child_id)` replaces the single
`role = coordinator.node(child_id).role` line from the source-reviewer
plan's own Task 3 - same lookup, reused for `node.name`/`node.parent_id`/
`node.depth` too, rather than calling `coordinator.node(child_id)` three
more times.)

- [ ] **Step 4: Run to verify it passes, then the full existing scan suite**

Run: `uv run pytest tests/lalo/test_scan.py -v`
Expected: PASS, every test.

- [ ] **Step 5: Full check and commit**

```bash
uv run ruff check src/lalo tests/lalo --fix && uv run ruff format src/lalo tests/lalo && uv run mypy && uv run pytest -q -m "not integration and not live"
git add src/lalo/scan.py tests/lalo/test_scan.py
git commit -m "feat(L4L0): journal spawned/finished breadcrumbs for every child"
```

---

## Task 4: Reconstruct orphans on resume

**Files:**
- Modify: `src/lalo/scan.py` (new `_find_orphaned_children`; wired in
  right after `coordinator.seed_counter(...)`)
- Test: `tests/lalo/test_scan.py`

**Interfaces:**
- Produces: `_find_orphaned_children(journal: DurableJournal) ->
  list[tuple[str, dict[str, object]]]` — `(child_id, spawned_payload)` for
  every `:spawned` breadcrumb with no matching `:finished` one.

- [ ] **Step 1: Write the failing tests**

```python
def test_find_orphaned_children_returns_a_spawned_with_no_matching_finished(
    tmp_path: Path,
) -> None:
    journal = DurableJournal(tmp_path / "journal.jsonl")
    journal.record("agent-2:spawned", {"name": "n", "task": "t", "parent_id": "agent-1", "depth": 1, "role": "full"})
    orphans = scan_module._find_orphaned_children(journal)
    assert [child_id for child_id, _ in orphans] == ["agent-2"]


def test_find_orphaned_children_excludes_one_with_a_matching_finished(tmp_path: Path) -> None:
    journal = DurableJournal(tmp_path / "journal.jsonl")
    journal.record("agent-2:spawned", {"name": "n", "task": "t", "parent_id": "agent-1", "depth": 1, "role": "full"})
    journal.record("agent-2:finished", {"stop_reason": "finished", "summary": "done"})
    assert scan_module._find_orphaned_children(journal) == []


def test_a_crashed_mid_child_scan_can_be_resumed_under_the_same_agent_id(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(scan_module, "docker_available", lambda: True)
    monkeypatch.setattr(scan_module, "RuntimeContainer", _FakeContainer)

    def _crash_mid_child(call_index: int, prompt: str) -> str:
        if "MISSION:" not in prompt:
            return "ok"
        if prompt.startswith("MISSION:\nCHILD-C-TASK"):
            # The child's very first turn - simulate an unrecoverable process
            # kill while child_loop.run() is still in progress. Deliberately
            # a BaseException, NOT a plain Exception: agent/spawn.py's own
            # _spawn wraps its run_child(...) call in "except Exception as
            # exc" (comment: "a crashed child must still reach a terminal
            # status") specifically so an ordinary child failure never takes
            # the whole scan down - so an ordinary RuntimeError here would be
            # caught right there and the scan would finish normally, proving
            # nothing about orphan detection. Only something outside
            # Exception's hierarchy models a real, uncatchable process death.
            raise BaseException("simulated crash mid-child")  # noqa: TRY002, BLE001
        if "HISTORY (most recent last):" not in prompt:
            return _spawn_agent_call()
        return _finish_call()

    router1 = ModelRouter(
        providers={"fake": _ScriptedProvider(_crash_mid_child)},
        routes={"reasoning": ("fake",), "review": ("fake",)},
        default_route=("fake",),
    )
    monkeypatch.setattr(scan_module, "build_router", lambda _settings: router1)

    run_dir = tmp_path / "run"
    config = ScanConfig(
        mission="find a bug, spawning one child", target_specs=["c.example.com"], run_dir=run_dir
    )
    with pytest.raises(BaseException, match="simulated crash mid-child"):  # noqa: PT011
        ScanRunner(config, env={"ANTHROPIC_API_KEY": "sk-test"}).run()

    crashed_journal = DurableJournal(run_dir / "journal.jsonl")
    assert crashed_journal.has("agent-2:spawned")
    assert not crashed_journal.has("agent-2:finished")

    def _respond_after_resume(call_index: int, prompt: str) -> str:
        if "FINDING TO REVIEW" in prompt:
            return '{"verdict": "confirmed", "proof_level": "L3", "reasoning": "grounded"}'
        if prompt.startswith("MISSION:\nCHILD-C-TASK"):
            if "HISTORY (most recent last):" not in prompt:
                return _record_finding_call_for("https://c.example.com/search")
            return _finish_call()
        # The root's OWN turns after resume. "root:0" (the crashed spawn
        # step) was never journaled - the crash happened before that whole
        # tool dispatch (spawn + run the child to completion) ever
        # returned, and a step only gets journaled once its dispatch
        # returns (see _max_spawned_agent_number's own docstring) - so the
        # root's first LIVE turn here has NO history at all, exactly like a
        # fresh run's very first turn. It must explicitly resume the orphan
        # (a real agent would call view_agent_graph first and see agent-2
        # as [orphaned]; this scripted turn already "knows" to resume it).
        # Its SECOND turn (now WITH history, since the successful resume
        # just journaled "root:0") finishes.
        if "HISTORY (most recent last):" not in prompt:
            return json.dumps({"tool": "spawn_agent", "args": {"resume_agent_id": "agent-2"}})
        return _finish_call()

    router2 = ModelRouter(
        providers={"fake": _ScriptedProvider(_respond_after_resume)},
        routes={"reasoning": ("fake",), "review": ("fake",)},
        default_route=("fake",),
    )
    monkeypatch.setattr(scan_module, "build_router", lambda _settings: router2)

    outcome = ScanRunner(config, env={"ANTHROPIC_API_KEY": "sk-test"}).run()
    assert outcome.status is RunStatus.COMPLETED

    final_journal = DurableJournal(run_dir / "journal.jsonl")
    # The SAME id as before the crash - never a fresh "agent-3".
    assert final_journal.has("agent-2:0")
    assert final_journal.has("agent-2:finished")
```

(`_ScriptedProvider`/`_spawn_agent_call`/`_finish_call`/
`_record_finding_call_for`/`RunStatus` are all already imported/defined in
`tests/lalo/test_scan.py` — confirmed this session. This test deliberately
does NOT use the existing `_CrashingProvider` fixture: that class only ever
raises `RuntimeError` (an `Exception` subclass), which `agent/spawn.py`'s
own `_spawn`/`_run_one` always catch ("a crashed child must still reach a
terminal status") — a `RuntimeError` from a CHILD's own turn would be
swallowed right there and the scan would finish normally, proving nothing.
Raising a bare `BaseException` directly from the scripted respond function
is the only way to model a real, uncatchable process death happening
specifically while a child (not the root) is running — verified against
`agent/spawn.py`'s exact `except Exception` clauses and `agent/tools.py`'s
`ToolRegistry.dispatch`'s own `except Exception` this session before
writing this test. Otherwise this mirrors
`test_resume_reseeds_the_spawn_counter_so_a_second_child_gets_a_fresh_agent_id`'s
established two-router crash-then-resume pattern.)

- [ ] **Step 2: Run to verify they fail**

Run: `uv run pytest tests/lalo/test_scan.py -k "find_orphaned_children or a_crashed_mid_child_scan_can_be_resumed" -v`
Expected: FAIL — `AttributeError: module 'lalo.scan' has no attribute
'_find_orphaned_children'` for the first two; the third fails differently
once that's fixed (see Step 4's own note) - run them one substep at a time
rather than assuming a single failure mode covers all three.

- [ ] **Step 3: Implement `_find_orphaned_children` and wire it into resume**

Near `_max_spawned_agent_number` in `src/lalo/scan.py`, add:

```python
def _find_orphaned_children(journal: DurableJournal) -> list[tuple[str, dict[str, object]]]:
    """Every child whose own ``:spawned`` breadcrumb has no matching
    ``:finished`` one - genuinely still mid-execution when the process
    crashed, per _run_child's own two-breadcrumb discipline. Order is not
    significant (see the design spec: depth is stored directly in the
    breadcrumb, never derived by looking up a parent during
    reconstruction), so this returns whatever order completed_keys()
    itself iterates in.
    """
    orphans: list[tuple[str, dict[str, object]]] = []
    for key in journal.completed_keys():
        if not key.endswith(":spawned"):
            continue
        child_id = key.removesuffix(":spawned")
        if not journal.has(f"{child_id}:finished"):
            orphans.append((child_id, journal.get(key)))
    return orphans
```

In `ScanRunner.run()`, right after the existing:

```python
        coordinator.seed_counter(_max_spawned_agent_number(journal))
```

add:

```python
        for orphan_id, spawned in _find_orphaned_children(journal):
            coordinator.register_orphan(
                orphan_id,
                str(spawned["name"]),
                str(spawned["task"]),
                parent_id=spawned.get("parent_id"),  # type: ignore[arg-type]
                depth=int(spawned["depth"]),  # type: ignore[arg-type]
                role=str(spawned["role"]),
            )
```

(`register_orphan` is a no-op-producing loop on a fresh run - the journal
has no `:spawned` keys yet, so `_find_orphaned_children` returns `[]`.)

- [ ] **Step 4: Run to verify they pass, then the full existing scan suite**

Run: `uv run pytest tests/lalo/test_scan.py -v`
Expected: PASS, every test. If the third test's crash-then-resume flow
doesn't reach `RunStatus.COMPLETED`, read the resumed run's own emitted
events (`event_log.snapshot()`) to see exactly which step failed before
concluding the wiring itself is wrong - this test exercises more moving
parts (two full `ScanRunner.run()` calls, a real crash, a real resume)
than any other in this plan, so a first-attempt failure is more likely to
be a test-scripting mismatch (a prompt-matching branch not firing when
expected) than a real bug — verify which one before changing production
code.

- [ ] **Step 5: Full check and commit**

```bash
uv run ruff check src/lalo tests/lalo --fix && uv run ruff format src/lalo tests/lalo && uv run mypy && uv run pytest -q -m "not integration and not live"
git add src/lalo/scan.py tests/lalo/test_scan.py
git commit -m "feat(L4L0): reconstruct orphaned children on resume from journal breadcrumbs"
```

---

## Task 5: Document the closed gap

**Files:**
- Modify: `docs/OPERATING.md`

**Interfaces:** None — documentation-only.

- [ ] **Step 1: Correct the existing "child restarts from scratch" note**

`docs/OPERATING.md`'s "Resuming a crashed or stopped scan" section
currently states (added by the shannon-gap-closure plan's Task 11, after
that same plan's Task 1 was found to overclaim granular child resume):

```
A child that was still genuinely mid-execution when the crash happened
is *not* resumed granularly: the root's own not-yet-completed spawn step
simply re-runs in full on resume, spawning a brand-new child under a
fresh id (never the abandoned one) that redoes that task from scratch.
```

This claim is now **only true if the agent doesn't act on it** - the
capability to resume that exact child now exists, opt-in. Replace the
paragraph with:

```
A child that was still genuinely mid-execution when the crash happened
does NOT resume automatically the way the root does - the root's own
not-yet-completed spawn step still re-runs in full on the next live turn.
But `view_agent_graph` now shows that child as `[orphaned]` (durably
detected from the journal, not guessed), and the agent can explicitly
continue it with `spawn_agent`'s `resume_agent_id` argument instead of
starting a new one - the orphan's own original task and every step it
already completed carry forward under its own unchanged agent id, at no
extra LLM cost for the replayed portion. Nothing does this automatically;
an agent that doesn't call `view_agent_graph` after a resume, or chooses
not to resume a shown orphan, gets the old fresh-restart behavior exactly
as before - a deliberate choice, not an oversight, matching this
project's "the agent decides" design center.
```

- [ ] **Step 2: Full check and commit**

```bash
uv run pytest -q -m "not integration and not live"
git add docs/OPERATING.md
git commit -m "docs(L4L0): document the real (opt-in) child mid-flight resume capability"
```

---

## Final Check (after all 5 tasks)

1. Full check: `uv run ruff check src/lalo tests/lalo && uv run ruff format --check src/lalo tests/lalo && uv run mypy && uv run pytest -q -m "not integration and not live"` — must be fully green.
2. Whole-branch review: confirm a FRESH (non-resumed) scan's behavior is
   byte-identical to before this plan (no `:spawned`/`:finished` breadcrumb
   ever causes a fresh run to behave differently - they're purely additive
   journal entries a fresh run never reads back); confirm
   `_find_orphaned_children` genuinely returns `[]` on a journal with no
   crash history; confirm the `spawn_agents` (parallel) tool is
   deliberately untouched by this plan, per the spec's own scoping.
3. No live Playwright check needed — backend-only, no GUI surface change
   (an orphaned agent is visible only via `view_agent_graph`, an agent-facing
   tool, not a GUI element).
