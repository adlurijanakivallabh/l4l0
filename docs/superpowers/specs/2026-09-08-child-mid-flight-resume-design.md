# Per-Child Mid-Flight Resume — Design Spec

**Status:** approved for planning (operator's standing autonomy grant
applies — design decisions below are mine, made and recorded).

## Why

A studied reference agent's own comparison's real, still-open finding: "a spawned child that's
still mid-execution when the process crashes restarts from scratch,
re-spending on any child that was running at crash time." Task 1 of the
an earlier gap-closure round added per-child journaling (a completed child's own
steps land durably, under its own `agent_key`) but — as documented in this
project's own memory and in `docs/OPERATING.md` — that only helps a child
that had *already fully finished* before a later, unrelated crash. A child
that is genuinely still running when the crash happens is never resumed:
`_run_child` runs a whole spawn (dispatch → run to completion → graph merge)
synchronously inside ONE of the root's own journaled steps, so if the crash
lands mid-child, the root's own journal entry for that step was never
written, and on resume the *entire spawn re-runs*, minting a brand-new
child under a fresh id. The old child's own partial journal entries
(`agent-N:0`, `agent-N:1`, ...) exist on disk but nothing ever looks at
them again.

## Why this is genuinely harder than sub-projects 1 and 2

Making the *root's own step loop* automatically detect "step N was a
spawn that started but never finished" and transparently re-enter the
same child would require `AgentLoop.run()`'s generic step loop to become
aware of tool semantics it has zero knowledge of today (which tool calls
are "spawn-shaped" versus ordinary). That is real, Temporal-replay-grade
complexity — closer to the machinery this project's own comparison
explicitly said L4L0 should *not* adopt.

## Chosen design: durable breadcrumbs + an explicit, agent-chosen resume

Move the *decision* to resume a specific interrupted child into the
agent's own hands — matching this project's "the agent decides" design
center exactly, and needing zero changes to `AgentLoop.run()`'s core loop.

1. `_run_child` (in `scan.py`) writes two small journal breadcrumbs of its
   own, using the *exact same* `"{agent_key}:{suffix}"` key shape
   `_max_spawned_agent_number` already parses (a non-numeric suffix like
   `"spawned"`/`"finished"` never collides with a real numbered step, and
   needs zero changes to that function to be counted correctly):
   - `f"{child_id}:spawned"` — recorded right before `child_loop.run(...)`
     starts: `{"name": ..., "task": ..., "parent_id": ..., "depth": ...,
     "role": ...}`. This is everything needed to reconstruct the node.
   - `f"{child_id}:finished"` — recorded right after `child_loop.run(...)`
     returns (before or after the graph merge — order doesn't matter for
     this purpose): `{"stop_reason": ..., "summary": ...}`.
   A crash mid-child-execution durably leaves the `:spawned` breadcrumb
   with no matching `:finished` one — an unambiguous, journal-only signal
   that this specific child never reached any terminal `AgentResult`,
   distinct from a child that *did* reach one (finished, budget-exhausted,
   cancelled — all of these still return normally from `child_loop.run()`
   and get a `:finished` breadcrumb; only a genuine process-level crash
   mid-run skips it).
2. On a resumed run, before the root agent's own loop starts, `scan.py`
   scans the journal for every `:spawned` breadcrumb lacking a matching
   `:finished` one — each is a real orphan from a previous crash — and
   registers it into the (otherwise fresh) `AgentCoordinator` with a new
   `AgentStatus.ORPHANED` status, using the breadcrumb's own recorded
   name/task/parent_id/depth/role. Processing order doesn't matter: `depth`
   comes from the breadcrumb itself (computed live, at spawn time, when the
   coordinator genuinely had that information) rather than being derived
   from looking up the parent's own node during reconstruction, so an
   orphaned grandchild registers correctly even if processed before its own
   orphaned parent.
3. `spawn_agent` gains an optional `resume_agent_id` argument. When given
   (and it names a real, currently `ORPHANED` node), the tool skips minting
   a new id entirely and calls `run_child` with that *exact* id and its
   *original* recorded task (read from the coordinator's own node — never
   from whatever `task` text this new tool call happened to include,
   mirroring `/scan`'s own `resume_run_id` precedent: locked fields come
   from the persisted record, never from the new request). `run_child`
   then constructs `AgentLoop(..., agent_key=child_id)` exactly as for any
   other child, and `AgentLoop.run()`'s *already-existing, already-tested*
   per-agent-key replay loop (Task 1 of an earlier gap-closure round)
   naturally resumes from that child's own last completed step — no new
   replay mechanism needed there at all.
4. `view_agent_graph`'s existing generic `render_tree` (`[{node.status.value}]`)
   needs zero code changes to show `[orphaned]` — it already renders
   whatever status a node has.

## What this does and does not close

**Closes:** the exact case named in the comparison — a single child (at
any depth) that was genuinely mid-execution when the process crashed now
resumes from its own last completed step via one explicit, agent-chosen
`spawn_agent` call, instead of silently restarting under a new id.

**Deliberately deferred, not silently dropped:** bulk-resuming several
orphans from one crashed `spawn_agents` (parallel) batch in a single call.
`resume_agent_id` lands on `spawn_agent` only for this pass — an agent
recovering from a multi-orphan crash calls `spawn_agent` once per orphan
(serially; each resume still replays that child's own steps with no model
call for them, so the "no re-spending" property holds, it just loses the
*concurrency* of the original batch on the resumed portion). Worth its own
follow-up if it matters in practice; not required for the core gap.

**Not attempted:** automatic, model-free resume. The agent must actually
notice the orphan (via `view_agent_graph`, which it's already instructed to
check before spawning) and choose to resume it — matching "the agent
decides" over baking a resume protocol into the core loop.

## Testing

- `orchestrator/journal.py`: no changes, no new tests needed — the two new
  breadcrumbs use its existing `record`/`has`/`get`/`ts_for`/
  `completed_keys` API exactly as-is.
- `agent/spawn.py`: `AgentStatus.ORPHANED` exists and renders correctly in
  `render_tree`; a new `AgentCoordinator.register_orphan(...)` and
  `has_node(...)`; `spawn_agent`'s `_spawn` resumes a real orphan (reusing
  its id, its original task, never the new call's task text) and rejects
  a `resume_agent_id` that doesn't name a real orphan.
- `scan.py`: the orphan-detection function (`:spawned` without a matching
  `:finished`) tested directly against a `DurableJournal` fixture; one
  real end-to-end scripted test — crash a `ScanRunner.run()` mid-child
  (raise partway through the child's own second turn), confirm the
  `:spawned` breadcrumb exists with no `:finished` counterpart, then run a
  **second** `ScanRunner` against the same `run_dir` whose scripted root
  turn calls `spawn_agent` with `resume_agent_id` set to the orphan and
  confirm the child's own journal shows its later steps continuing under
  the *same* `agent_id`, never a new one.

## Related work (not in this spec)

One more item remains queued after this: recompute-from-attempts usage
accounting under replay.
