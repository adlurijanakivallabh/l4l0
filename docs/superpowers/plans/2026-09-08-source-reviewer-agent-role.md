# Confined Source-Reviewer Agent Role Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let an agent opt into spawning a genuinely confined child for pure
source-code review — a real `_filter_tools`-backed toolset restriction,
wired up for the first time since Task 7 of the shannon-gap-closure plan
built the mechanism.

**Architecture:** `role` is stored on the spawn tree itself (`AgentNode`),
not threaded through `ChildRunner`'s call signature — the less invasive of
two designs, chosen specifically to avoid breaking every existing
`run_child` fake in `tests/lalo/test_spawn.py`. `scan.py`'s `_run_child`
looks the role up from the coordinator and maps it to a tool-name preset.

**Tech Stack:** Python 3.13, the existing `AgentCoordinator`/spawn-tool
machinery (`agent/spawn.py`), `_build_registry`'s existing `tool_names`
parameter (`scan.py`, from Task 7 of the shannon-gap-closure plan).

**Spec:** `docs/superpowers/specs/2026-09-08-source-reviewer-agent-role-design.md`

## Global Constraints

- Every existing call site of `AgentCoordinator.spawn()`, `ChildRunner`,
  `build_spawn_tools`, and `build_parallel_spawn_tool` must keep working
  completely unchanged — `role`/`valid_roles` are additive keyword
  parameters with defaults (`"full"` / `frozenset({"full"})`), never
  required.
- `ChildRunner`'s type and call signature (`Callable[[str, str, str],
  tuple[str, list[str], bool]]`) does NOT change in this plan.
- An invalid `role` is rejected BEFORE `coordinator.spawn(...)` is ever
  called — no ghost child node left registered for a rejected spawn call,
  matching the existing depth-ceiling check's own behavior exactly.
- `spawn_agents`' existing "validate the whole batch before spawning any of
  it" atomicity (see its own comment: "Registered up front, sequentially,
  before any thread starts... no partial batch to reconcile") extends to
  role validation too — one bad role in a batch of N rejects all N, none
  spawn.
- The `source_reviewer` tool preset is exactly:
  `frozenset({"run_command", "record_finding", "recall", "query_graph", "note"})`
  — verified against the real `name=` string in every tool builder
  (`runtime/tool.py`, `findings/tool.py`, `skills/tool.py`,
  `graph/tool.py` ×2) before writing this plan.

---

## Task 1: `AgentNode`/`AgentCoordinator.spawn()` gain an optional `role`

**Files:**
- Modify: `src/lalo/agent/spawn.py` (`AgentNode` dataclass;
  `AgentCoordinator.spawn()`)
- Test: `tests/lalo/test_spawn.py`

**Interfaces:**
- Produces: `AgentNode.role: str = "full"` (new field);
  `AgentCoordinator.spawn(parent_id: str, name: str, task: str, *,
  role: str = "full") -> str` (new keyword parameter, stored on the
  resulting node).

- [ ] **Step 1: Write the failing tests**

```python
def test_spawn_stores_the_full_role_by_default() -> None:
    coord = AgentCoordinator(max_depth=5)
    root = coord.register_root("root", "mission")
    child = coord.spawn(root, "child", "subtask")
    assert coord.node(child).role == "full"


def test_spawn_stores_an_explicit_role() -> None:
    coord = AgentCoordinator(max_depth=5)
    root = coord.register_root("root", "mission")
    child = coord.spawn(root, "child", "subtask", role="source_reviewer")
    assert coord.node(child).role == "source_reviewer"


def test_register_root_defaults_to_the_full_role() -> None:
    coord = AgentCoordinator()
    root = coord.register_root("root", "mission")
    assert coord.node(root).role == "full"
```

- [ ] **Step 2: Run to verify they fail**

Run: `uv run pytest tests/lalo/test_spawn.py -k "stores_the_full_role or stores_an_explicit_role or register_root_defaults_to_the_full_role" -v`
Expected: FAIL — `AttributeError: 'AgentNode' object has no attribute 'role'`

- [ ] **Step 3: Add the field and the parameter**

In `src/lalo/agent/spawn.py`, `AgentNode` (currently):

```python
@dataclass
class AgentNode:
    id: str
    name: str
    task: str
    parent_id: str | None
    depth: int
    status: AgentStatus = AgentStatus.RUNNING
    summary: str = ""
    finding_ids: list[str] = field(default_factory=list)
```

add one field at the end:

```python
    finding_ids: list[str] = field(default_factory=list)
    role: str = "full"
```

`AgentCoordinator.spawn()` (currently):

```python
    def spawn(self, parent_id: str, name: str, task: str) -> str:
        with self._lock:
            parent = self._nodes[parent_id]
            child_depth = parent.depth + 1
            if child_depth > self.max_depth:
                raise SpawnDepthExceededError(
                    f"spawn depth {child_depth} exceeds ceiling {self.max_depth}"
                )
            self._counter += 1
            child_id = f"agent-{self._counter}"
            self._nodes[child_id] = AgentNode(
                child_id, name, task, parent_id=parent_id, depth=child_depth
            )
            return child_id
```

becomes:

```python
    def spawn(self, parent_id: str, name: str, task: str, *, role: str = "full") -> str:
        with self._lock:
            parent = self._nodes[parent_id]
            child_depth = parent.depth + 1
            if child_depth > self.max_depth:
                raise SpawnDepthExceededError(
                    f"spawn depth {child_depth} exceeds ceiling {self.max_depth}"
                )
            self._counter += 1
            child_id = f"agent-{self._counter}"
            self._nodes[child_id] = AgentNode(
                child_id, name, task, parent_id=parent_id, depth=child_depth, role=role
            )
            return child_id
```

`register_root` needs no change — `AgentNode(agent_id, name, task,
parent_id=None, depth=0)` already gets `role="full"` from the new field's
own default.

- [ ] **Step 4: Run to verify they pass, then the full existing spawn suite**

Run: `uv run pytest tests/lalo/test_spawn.py -v`
Expected: PASS, every test (proves adding the field/parameter broke nothing
existing).

- [ ] **Step 5: Full check and commit**

```bash
uv run ruff check src/lalo tests/lalo --fix && uv run ruff format src/lalo tests/lalo && uv run mypy && uv run pytest -q -m "not integration and not live"
git add src/lalo/agent/spawn.py tests/lalo/test_spawn.py
git commit -m "feat(L4L0): AgentNode/AgentCoordinator.spawn() carry an optional role"
```

---

## Task 2: `spawn_agent`/`spawn_agents` validate and pass through `role`

**Files:**
- Modify: `src/lalo/agent/spawn.py` (`build_spawn_tools`'s `_spawn`;
  `build_parallel_spawn_tool`'s `_spawn_agents`; both tool descriptions)
- Test: `tests/lalo/test_spawn.py`

**Interfaces:**
- Consumes: `AgentCoordinator.spawn(..., role=...)` (Task 1).
- Produces: `build_spawn_tools(coordinator, run_child, *, self_id,
  valid_roles: frozenset[str] = frozenset({"full"})) -> tuple[Tool, Tool]`;
  `build_parallel_spawn_tool(coordinator, run_child, *, self_id,
  valid_roles: frozenset[str] = frozenset({"full"})) -> Tool` (both gain the
  new keyword parameter, defaulting to today's exact behavior).

- [ ] **Step 1: Write the failing tests**

```python
def test_spawn_agent_rejects_an_unknown_role_without_registering_a_child() -> None:
    coord = AgentCoordinator(max_depth=5)
    root = coord.register_root("root", "mission")
    spawn_tool, _ = build_spawn_tools(
        coord, lambda *_a: ("", [], True), self_id=root,
        valid_roles=frozenset({"full", "source_reviewer"}),
    )
    registry = ToolRegistry([spawn_tool])
    result = registry.dispatch(
        "spawn_agent", {"name": "x", "task": "y", "role": "not-a-real-role"}
    )
    assert result.ok is False
    assert coord.children_of(root) == []


def test_spawn_agent_passes_a_valid_role_through_to_the_coordinator() -> None:
    coord = AgentCoordinator(max_depth=5)
    root = coord.register_root("root", "mission")
    spawn_tool, _ = build_spawn_tools(
        coord, lambda *_a: ("", [], True), self_id=root,
        valid_roles=frozenset({"full", "source_reviewer"}),
    )
    registry = ToolRegistry([spawn_tool])
    registry.dispatch(
        "spawn_agent", {"name": "x", "task": "y", "role": "source_reviewer"}
    )
    child_id = coord.children_of(root)[0]
    assert coord.node(child_id).role == "source_reviewer"


def test_spawn_agent_role_defaults_to_full_when_omitted() -> None:
    coord = AgentCoordinator(max_depth=5)
    root = coord.register_root("root", "mission")
    spawn_tool, _ = build_spawn_tools(coord, lambda *_a: ("", [], True), self_id=root)
    registry = ToolRegistry([spawn_tool])
    registry.dispatch("spawn_agent", {"name": "x", "task": "y"})
    child_id = coord.children_of(root)[0]
    assert coord.node(child_id).role == "full"


def test_spawn_agents_rejects_the_whole_batch_when_any_role_is_invalid() -> None:
    coord = AgentCoordinator(max_depth=5)
    root = coord.register_root("root", "mission")
    parallel_tool = build_parallel_spawn_tool(
        coord, lambda *_a: ("", [], True), self_id=root,
        valid_roles=frozenset({"full", "source_reviewer"}),
    )
    registry = ToolRegistry([parallel_tool])
    result = registry.dispatch(
        "spawn_agents",
        {
            "tasks": [
                {"name": "a", "task": "task a", "role": "full"},
                {"name": "b", "task": "task b", "role": "not-a-real-role"},
            ]
        },
    )
    assert result.ok is False
    assert coord.children_of(root) == []


def test_spawn_agents_passes_each_tasks_own_role_through() -> None:
    coord = AgentCoordinator(max_depth=5)
    root = coord.register_root("root", "mission")
    parallel_tool = build_parallel_spawn_tool(
        coord, lambda *_a: ("", [], True), self_id=root,
        valid_roles=frozenset({"full", "source_reviewer"}),
    )
    registry = ToolRegistry([parallel_tool])
    registry.dispatch(
        "spawn_agents",
        {
            "tasks": [
                {"name": "a", "task": "task a", "role": "full"},
                {"name": "b", "task": "task b", "role": "source_reviewer"},
            ]
        },
    )
    roles = {coord.node(cid).role for cid in coord.children_of(root)}
    assert roles == {"full", "source_reviewer"}
```

- [ ] **Step 2: Run to verify they fail**

Run: `uv run pytest tests/lalo/test_spawn.py -k "rejects_an_unknown_role or passes_a_valid_role or role_defaults_to_full or rejects_the_whole_batch or passes_each_tasks_own_role" -v`
Expected: FAIL — `TypeError: build_spawn_tools() got an unexpected keyword argument 'valid_roles'`

- [ ] **Step 3: Wire `role` through `_spawn`**

In `src/lalo/agent/spawn.py`, `build_spawn_tools`'s signature (currently
`def build_spawn_tools(coordinator, run_child, *, self_id) -> tuple[Tool, Tool]:`)
gains `valid_roles: frozenset[str] = frozenset({"full"})`:

```python
def build_spawn_tools(
    coordinator: AgentCoordinator,
    run_child: ChildRunner,
    *,
    self_id: str,
    valid_roles: frozenset[str] = frozenset({"full"}),
) -> tuple[Tool, Tool]:
```

Inside it, `_spawn` (currently):

```python
    def _spawn(args: dict[str, object]) -> ToolResult:
        name = str_arg(args, "name").strip()
        task = str_arg(args, "task").strip()
        if not name or not task:
            return ToolResult(observation="error: 'name' and 'task' are required", ok=False)
        warning = _duplicate_task_warning(coordinator, self_id, task)
        try:
            child_id = coordinator.spawn(self_id, name, task)
        except SpawnDepthExceededError as exc:
            return ToolResult(observation=f"error: {exc}", ok=False)
```

becomes:

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
```

Update the `spawn_agent` tool's description (only add the new arg
documentation, keep everything else verbatim):

```python
    spawn_tool = FunctionTool(
        name="spawn_agent",
        description=(
            "Spawn a child agent for a focused subtask; runs to completion and returns its "
            "authoritative filed finding ids — never trust its own prose as evidence. "
            "Call view_agent_graph first to confirm no existing agent already covers this "
            "scope — a duplicate specialist wastes turns. In 'task', state what is ALREADY "
            "KNOWN (what recon already mapped, which surfaces are already covered) so the "
            "child builds on it instead of rediscovering it from scratch. "
            'args: {"name": str, "task": str, "role": "full"|"source_reviewer" (optional, '
            'default "full" - source_reviewer confines the child to run_command/'
            "record_finding/recall/query_graph/note only, no live-firing tools and no "
            "further spawning - use it for a subtask that's purely reading and reasoning "
            'about source code)}'
        ),
        func=_spawn,
    )
```

- [ ] **Step 4: Wire `role` through `_spawn_agents`**

`build_parallel_spawn_tool`'s signature gains the same `valid_roles`
parameter. Inside `_spawn_agents`, the per-task parsing loop (currently):

```python
        parsed: list[tuple[str, str]] = []
        for item in raw_tasks:
            if not isinstance(item, dict):
                return ToolResult(
                    observation="error: each task must be an object with 'name' and 'task'",
                    ok=False,
                )
            name = str_arg(item, "name").strip()
            task = str_arg(item, "task").strip()
            if not name or not task:
                return ToolResult(
                    observation="error: every task needs a non-empty 'name' and 'task'", ok=False
                )
            parsed.append((name, task))
```

becomes (parsed now carries role too, and every role is validated in this
SAME pass — before any spawn call, matching the existing "no partial
batch" discipline):

```python
        parsed: list[tuple[str, str, str]] = []
        for item in raw_tasks:
            if not isinstance(item, dict):
                return ToolResult(
                    observation="error: each task must be an object with 'name' and 'task'",
                    ok=False,
                )
            name = str_arg(item, "name").strip()
            task = str_arg(item, "task").strip()
            role = str_arg(item, "role", "full").strip() or "full"
            if not name or not task:
                return ToolResult(
                    observation="error: every task needs a non-empty 'name' and 'task'", ok=False
                )
            if role not in valid_roles:
                return ToolResult(
                    observation=f"error: 'role' must be one of {sorted(valid_roles)}", ok=False
                )
            parsed.append((name, task, role))
```

The duplicate-task-warning comprehension and the up-front spawn loop both
unpack 3-tuples now — update:

```python
        warnings = [
            _duplicate_task_warning(
                coordinator,
                self_id,
                task,
                extra_tasks=tuple(t for j, (_, t, _r) in enumerate(parsed) if j != i),
            )
            for i, (_, task, _role) in enumerate(parsed)
        ]

        # Registered up front, sequentially, before any thread starts: every
        # task in one batch shares the exact same parent (self_id), so they
        # all pass or all fail the depth ceiling identically - no partial
        # batch to reconcile if one raised partway through.
        try:
            child_ids = [
                coordinator.spawn(self_id, name, task, role=role)
                for name, task, role in parsed
            ]
        except SpawnDepthExceededError as exc:
            return ToolResult(observation=f"error: {exc}", ok=False)
```

`_run_one`'s own zip with `child_ids` unpacks the 3-tuples too — its call
site:

```python
        with ThreadPoolExecutor(max_workers=min(len(parsed), _MAX_PARALLEL_WORKERS)) as pool:
            futures = [
                pool.submit(_run_one, child_id, name, task)
                for child_id, (name, task) in zip(child_ids, parsed, strict=True)
            ]
```

becomes:

```python
        with ThreadPoolExecutor(max_workers=min(len(parsed), _MAX_PARALLEL_WORKERS)) as pool:
            futures = [
                pool.submit(_run_one, child_id, name, task)
                for child_id, (name, task, _role) in zip(child_ids, parsed, strict=True)
            ]
```

(`_run_one` itself is unchanged — it still only needs `child_id, name,
task`, exactly matching `ChildRunner`'s own untouched signature.)

Update the `spawn_agents` tool's description the same way as
`spawn_agent`'s:

```python
    return FunctionTool(
        name="spawn_agents",
        description=(
            "Spawn 2+ independent child agents to run CONCURRENTLY, then wait for all of "
            "them and get every result back at once - for genuinely independent lines of "
            "investigation (e.g. the same vuln class across several distinct hosts) that "
            "don't depend on each other's findings. Use spawn_agent instead for a single "
            "child, or when a later child's task depends on an earlier one's result. "
            'args: {"tasks": [{"name": str, "task": str, "role": "full"|"source_reviewer" '
            '(optional, default "full", same meaning as spawn_agent\'s own role arg)}, ...]} '
            "(at least 2 entries)"
        ),
        func=_spawn_agents,
    )
```

- [ ] **Step 5: Run to verify they pass, then the full existing spawn suite**

Run: `uv run pytest tests/lalo/test_spawn.py -v`
Expected: PASS, every test.

- [ ] **Step 6: Full check and commit**

```bash
uv run ruff check src/lalo tests/lalo --fix && uv run ruff format src/lalo tests/lalo && uv run mypy && uv run pytest -q -m "not integration and not live"
git add src/lalo/agent/spawn.py tests/lalo/test_spawn.py
git commit -m "feat(L4L0): spawn_agent/spawn_agents accept and validate an opt-in role"
```

---

## Task 3: Wire the `source_reviewer` preset into `scan.py`

**Files:**
- Modify: `src/lalo/scan.py` (`_run_child`; the `build_spawn_tools`/
  `build_parallel_spawn_tool` call sites)
- Test: `tests/lalo/test_scan.py`

**Interfaces:**
- Consumes: `coordinator.node(child_id).role` (Task 1),
  `build_spawn_tools(..., valid_roles=...)`/
  `build_parallel_spawn_tool(..., valid_roles=...)` (Task 2),
  `_build_registry(..., tool_names=...)` (existing, Task 7 of the
  shannon-gap-closure plan).
- Produces: `_ROLE_TOOL_NAMES: dict[str, frozenset[str] | None]` (module
  level in `scan.py`) — the single source of truth mapping a role name to
  its tool-name preset.

- [ ] **Step 1: Write the failing test**

```python
def _spawn_source_reviewer_call() -> str:
    return json.dumps(
        {
            "tool": "spawn_agent",
            "args": {
                "name": "Source Reviewer",
                "task": "SOURCE-REVIEW-TASK: read the repo for injection sinks",
                "role": "source_reviewer",
            },
        }
    )


def _respond_with_a_source_reviewer_spawn(
    captured_child_prompts: list[str],
) -> Callable[[int, str], str]:
    def _respond(call_index: int, prompt: str) -> str:
        if "MISSION:" not in prompt:
            return "ok"  # the preflight verify_router() health-check call
        if "SOURCE-REVIEW-TASK" in prompt:
            captured_child_prompts.append(prompt)
            return _finish_call()
        # the root's own turns
        if "HISTORY (most recent last):" not in prompt:
            return _spawn_source_reviewer_call()
        return _finish_call()

    return _respond


def test_a_source_reviewer_child_gets_a_confined_toolset(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(scan_module, "docker_available", lambda: True)
    monkeypatch.setattr(scan_module, "RuntimeContainer", _FakeContainer)
    captured_child_prompts: list[str] = []
    router = ModelRouter(
        providers={"fake": _ScriptedProvider(_respond_with_a_source_reviewer_spawn(captured_child_prompts))},
        routes={"reasoning": ("fake",), "review": ("fake",)},
        default_route=("fake",),
    )
    monkeypatch.setattr(scan_module, "build_router", lambda _settings: router)

    config = ScanConfig(
        mission="find a bug, spawning a source reviewer",
        target_specs=["c.example.com"],
        run_dir=tmp_path / "run",
        usage_path=tmp_path / "usage.json",
    )
    ScanRunner(config, env={"ANTHROPIC_API_KEY": "sk-test"}).run()

    assert len(captured_child_prompts) == 1
    child_prompt = captured_child_prompts[0]
    assert "run_command" in child_prompt
    assert "record_finding" in child_prompt
    assert "recall" in child_prompt
    assert "http:" not in child_prompt  # the http tool's own name-colon form in the tool list
    assert "spawn_agent:" not in child_prompt
```

`json`/`pytest`/`ModelRouter`/`ScanConfig`/`ScanRunner`/`_FakeContainer`/
`_ScriptedProvider`/`_finish_call`/`scan_module` are all already imported/
defined in `tests/lalo/test_scan.py` (verified this session — every one is
already used by a neighboring test in this same file). `Callable` is NOT
currently imported there (only `Iterator` is, from `collections.abc`) —
add it to that same existing import line:

```python
from collections.abc import Callable, Iterator
```

- [ ] **Step 2: Run to verify it fails**

Run: `uv run pytest tests/lalo/test_scan.py -k source_reviewer_child_gets_a_confined_toolset -v`
Expected: FAIL — `assert len(captured_child_prompts) == 1` fails with
`0 == 1`. `scan.py`'s own spawn-tool construction still doesn't pass
`valid_roles=...` after Task 2 alone (it defaults to
`frozenset({"full"})`), so the root's scripted `role: "source_reviewer"`
spawn call gets rejected as an unknown role (a normal failed tool-call
observation, not an exception) and the root's own next scripted turn
finishes without ever spawning a child — confirm the failure is genuinely
this missing wiring, not a typo in the test itself, before moving on.

- [ ] **Step 3: Add the role→tool-names mapping and wire it into `_run_child`**

In `src/lalo/scan.py`, near `_filter_tools` (added in the
shannon-gap-closure plan's Task 7), add:

```python
_SOURCE_REVIEWER_TOOL_NAMES = frozenset(
    {"run_command", "record_finding", "recall", "query_graph", "note"}
)

# The single source of truth for what each opt-in spawn role's toolset is.
# "full" (tool_names=None) is every existing agent's only role today -
# unaffected by this addition.
_ROLE_TOOL_NAMES: dict[str, frozenset[str] | None] = {
    "full": None,
    "source_reviewer": _SOURCE_REVIEWER_TOOL_NAMES,
}
```

Inside `_build_registry`, `_run_child` (currently):

```python
            def _run_child(child_id: str, _name: str, task: str) -> tuple[str, list[str], bool]:
                # Locked: spawn_agents can run several _run_child calls for
                ...
                with self._graph_lock:
                    before = set(agent_graph.nodes_of_kind(NodeKind.FINDING))
                    child_graph = isolate_for_child(agent_graph)
                child_registry = _build_registry(child_graph, child_id)
```

becomes:

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
```

(`coordinator` is already in this closure's enclosing scope — confirmed:
it's constructed earlier in the same `ScanRunner.run()` method, before
`_build_registry` is even defined.)

Finally, the two spawn-tool construction call sites (currently):

```python
            spawn_tool, view_graph_tool = build_spawn_tools(
                coordinator, _run_child, self_id=self_id
            )
            parallel_spawn_tool = build_parallel_spawn_tool(
                coordinator, _run_child, self_id=self_id
            )
```

become:

```python
            spawn_tool, view_graph_tool = build_spawn_tools(
                coordinator, _run_child, self_id=self_id,
                valid_roles=frozenset(_ROLE_TOOL_NAMES),
            )
            parallel_spawn_tool = build_parallel_spawn_tool(
                coordinator, _run_child, self_id=self_id,
                valid_roles=frozenset(_ROLE_TOOL_NAMES),
            )
```

- [ ] **Step 4: Run to verify it passes, then the full existing scan suite**

Run: `uv run pytest tests/lalo/test_scan.py -v`
Expected: PASS, every test (proves this is additive — every other spawn
path, which never names a role, still gets `tool_names=None`, i.e. the
full toolset, unchanged).

- [ ] **Step 5: Full check and commit**

```bash
uv run ruff check src/lalo tests/lalo --fix && uv run ruff format src/lalo tests/lalo && uv run mypy && uv run pytest -q -m "not integration and not live"
git add src/lalo/scan.py tests/lalo/test_scan.py
git commit -m "feat(L4L0): wire the source_reviewer role to a real confined toolset"
```

---

## Task 4: Point the source-aware-review skill at the new capability

**Files:**
- Modify: `src/lalo/skills/content/methodology/source-aware-review.md`

**Interfaces:** None — documentation-only addition, no code.

- [ ] **Step 1: Add one paragraph**

Read the current file in full first (it was written in the
shannon-gap-closure plan's Task 6 this same session — confirm its exact
current section headings before picking an insertion point rather than
guessing). Add a short paragraph near the end of its "Step Three: File It
the Same Way Everything Else Gets Filed" section (or wherever the file's
real current structure makes it read naturally — the goal is one
integrated paragraph, not a bolted-on afterthought):

```
When source review is genuinely a separate, focused subtask - not
something you're doing inline as part of a broader mission - consider
spawning it as its own child with `role: "source_reviewer"` on
`spawn_agent`. That child gets a confined toolset (the free shell,
`record_finding`, `recall`, `query_graph`, `note` - no live-firing tools,
no further spawning): a genuinely narrower blast radius for a task that's
purely reading and reasoning about code, matching this project's own
opt-in confinement design. This is optional, not a requirement - a source
review folded into a normal full-toolset agent's own turn is just as
valid when the task doesn't warrant spawning a dedicated child at all.
```

- [ ] **Step 2: Verify the skill still loads and validates**

Run: `uv run pytest tests/lalo/test_skills_recall.py -k source_aware -v`
Expected: PASS (the existing retrievability test from the shannon-gap-closure
plan's Task 6 — this new paragraph doesn't change the file's frontmatter,
so no other test is affected).

- [ ] **Step 3: Full check and commit**

```bash
uv run ruff check src/lalo tests/lalo && uv run pytest -q -m "not integration and not live"
git add src/lalo/skills/content/methodology/source-aware-review.md
git commit -m "docs(L4L0): point source-aware-review at the new confined spawn role"
```

---

## Final Check (after all 4 tasks)

1. Full check: `uv run ruff check src/lalo tests/lalo && uv run ruff format --check src/lalo tests/lalo && uv run mypy && uv run pytest -q -m "not integration and not live"` — must be fully green.
2. Whole-branch review of every file this plan touched: confirm no
   existing agent's toolset changed (every current spawn call site still
   defaults to `"full"`/`tool_names=None`); confirm the invalid-role
   rejection genuinely never registers a child node in either the serial
   or parallel path; confirm `_run_one`'s untouched 3-arg call to
   `run_child` still matches `ChildRunner`'s own unchanged type exactly.
3. No live Playwright check needed — this is a backend-only agent-loop
   capability with no GUI surface change.
