# Confined Source-Reviewer Agent Role — Design Spec

**Status:** approved for planning (operator granted full autonomy for this
and the remaining queued sub-projects — "you only inspect, you only build
plans, you only execute, you only review till everything is done properly"
— design decisions below are mine, made and recorded rather than asked).

## Why

The shannon-gap-closure plan's Task 7 built the *infrastructure* for
tool-name confinement (`_filter_tools()` in `scan.py`) but wired it to
nothing — every agent, root and every spawned child, still gets the
identical full toolset. The original design plan's gap #10 named the
concrete use case this exists for: "a future source reviewer, or an
evidence re-verification child." This closes that gap for the first of
those two: a genuinely confined child an agent can *choose* to spawn when
a subtask is purely reading and reasoning about source code, rather than
live-firing anything.

This is opt-in, not a restriction imposed on any existing agent — matching
the operator's own stated "maximum freedom, no restrictions" principle for
this project. Every existing agent (root and every child) is completely
unaffected: the default role is still "full," unchanged. What's new is that
an agent can *itself* decide "this subtask doesn't need live-firing tools,
let me spawn something narrower" — the agent's own judgment call, not a
system-imposed gate.

## Scope

One feature: a `role` parameter on `spawn_agent`/`spawn_agents`
(`"full"` default, `"source_reviewer"` new), threaded through to
`_build_registry`'s existing `tool_names` parameter. The `source_reviewer`
preset gets exactly: `run_command` (the free shell — `git clone`/`grep`/
read, already how `source-aware-review.md` says to read source),
`record_finding` (it must be able to file what it finds — a source reviewer
that can't record a finding at all isn't a reviewer, it's a dead end),
`recall` (retrieve the source-aware-review and vuln-class playbooks),
`query_graph`/`note` (check what's already been found, avoid duplicate
work). Excluded: every live-firing tool (`http`, `fire_concurrent`,
`diff_responses`, `raw_tcp`, `ws_fire`, `dns_query`, `browser`, `jwt`,
`login_as`, `session_check`, OAST tools, `access_control_matrix`) and
further spawning (`spawn_agent`/`spawn_agents`/`view_agent_graph`) — a
narrow role should stay a narrow leaf worker, not fork its own unpredictable
sub-tree.

**Explicitly not this pass**: the "evidence re-verification child" example
from the same gap — a distinct role with its own toolset question (likely
needs `http`/`fire_concurrent` to re-fire something, but not `record_finding`
if its job is only to confirm, not to file new findings). Worth its own
design if the operator wants it later; not folded in here since it's a
genuinely different tool profile, not a variant of this one.

## Architecture — the less invasive of two designs, and why

**Rejected first design:** thread `role` as a new positional parameter on
`ChildRunner` (`Callable[[str, str, str, str], ...]`). Rejected because
`ChildRunner`'s call convention is exercised by a large number of existing
tests in `tests/lalo/test_spawn.py` via fixed-arity fakes
(`def run_child(child_id, name, task): ...`) — changing the call arity
would break every one of them for a change that doesn't need to touch that
seam at all.

**Chosen design:** store `role` on the spawn tree itself, where the
parent/child relationship already lives, and have the child-runner closure
look it up from there instead of receiving it as a parameter.

- `AgentNode` (`agent/spawn.py`) gains `role: str = "full"` (a new field
  with a default placed after the existing `finding_ids` field, so every
  existing positional `AgentNode(...)` construction across the test suite
  stays valid unchanged).
- `AgentCoordinator.spawn()` gains `role: str = "full"` (keyword-only
  default) — every existing call site (`coord.spawn(root, "child",
  "subtask")`, dozens of them) stays valid unchanged; only call sites that
  want a role pass it.
- `ChildRunner`'s type and every call site of it (`run_child(child_id, name,
  task)`) are **completely untouched**.
- `build_spawn_tools`/`build_parallel_spawn_tool` gain an optional
  `valid_roles: frozenset[str] = frozenset({"full"})` keyword parameter,
  used only to validate an incoming `role` argument *before* calling
  `coordinator.spawn(...)` at all (so an invalid role never even registers
  a child node — no ghost entry in the spawn tree to clean up). Every
  existing call site that doesn't pass `valid_roles` keeps today's exact
  behavior: only `"full"` (or an omitted role, which defaults to `"full"`)
  is ever accepted.
- `scan.py`'s `_run_child(child_id, _name, task)` — **signature unchanged**
  — gains one line: `role = coordinator.node(child_id).role`, then passes
  `tool_names=_ROLE_TOOL_NAMES[role]` to the existing `_build_registry(...)`
  call instead of the current implicit `None`.
- `scan.py` registers the real role set:
  `build_spawn_tools(coordinator, _run_child, self_id=self_id,
  valid_roles=frozenset(_ROLE_TOOL_NAMES))` (same for the parallel tool) —
  this is the one place that knows both "what roles exist" and "what each
  one maps to," matching this project's existing pattern of `agent/spawn.py`
  staying generic while the caller injects domain-specific configuration
  (mirrors the existing `Isolatable`/`ChildRunner` injection pattern
  exactly).

## Data flow

1. The calling agent's `spawn_agent` tool call includes an optional
   `"role"` key: `{"name": "Source Reviewer", "task": "...", "role":
   "source_reviewer"}`. Omitted entirely = `"full"`, today's exact
   behavior.
2. `_spawn(args)` parses `role` (default `"full"`), and — **before**
   calling `coordinator.spawn(...)`, keeping the existing "no ghost node on
   a rejected call" property the depth-ceiling check already has — checks
   `role in valid_roles`; a bad role returns
   `error: 'role' must be one of [...]` without ever touching the spawn
   tree.
3. `coordinator.spawn(self_id, name, task, role=role)` stores it on the new
   child's own `AgentNode`.
4. `run_child(child_id, name, task)` runs exactly as today; inside it,
   `scan.py`'s `_run_child` reads `coordinator.node(child_id).role` and
   builds that child's registry with the matching `tool_names`.
5. `spawn_agents` (the parallel fan-out) mirrors this per task in its
   `"tasks"` list, with the SAME "validate every task's role in the whole
   batch before spawning any of them" atomicity the existing depth-ceiling
   check already has (`# Registered up front, sequentially, before any
   thread starts... no partial batch to reconcile`).

## Discoverability

The tool's own `description` string (already the sole mechanism every
other tool capability is discovered through — no capability is duplicated
into `agent.txt`) documents the new `role` parameter and what
`source_reviewer` means. `source-aware-review.md` (the skill an agent
recalls when thinking about source review) gets one added paragraph
pointing at this: when the agent decides source review is a genuinely
separate, focused subtask, it now has a concrete, narrower way to spawn it.

## Testing

- `tests/lalo/test_spawn.py`: role stored correctly on the child node and
  defaults to `"full"` when omitted; an unknown role is rejected with no
  child node registered (`coordinator.children_of(self_id)` stays empty);
  the same two checks for `spawn_agents`, plus whole-batch rejection when
  any one task in the batch names an invalid role (no task in the batch
  spawns).
- `tests/lalo/test_scan.py`: one scripted end-to-end test — the root spawns
  a `role: "source_reviewer"` child via a real `ScanRunner.run()`, and the
  child's own first-turn rendered prompt (captured via the existing
  `_ScriptedProvider(respond)` pattern, matching
  `_respond_with_a_sequentially_spawned_child_running_a_command`'s own
  style) is asserted to list `run_command`/`record_finding`/`recall` in its
  `AVAILABLE TOOLS` section and NOT list `http`/`spawn_agent` — proving the
  confinement is real end to end, not just a unit-level tool-name filter.
- Full existing `test_spawn.py`/`test_scan.py` suites green, unchanged —
  proves the "less invasive design" claim above is actually true.

## Related work (not in this spec)

Two more items remain queued after this one, per the operator's own
sequencing: per-child mid-flight journaling for crash resume, and
recompute-from-attempts usage accounting under replay.
