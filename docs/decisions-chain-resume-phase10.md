# Phase 10 decision record — multi-hop chaining and durable resume

Date: 2026-08-30  
Status: complete  
Implementation commit: `eebd5b8`

## Invariants and authorization boundary

- The LLM may propose an order or a next hop, but only a committed
  `confirmed_violation` finding can advance a chain. `ReachabilityGraph.add_finding`
  remains the independent store gate; `add_enables` and
  `add_derived_credential` accept only committed findings.
- A derived credential is represented only after the deterministic finding has
  yielded a usable `Session`/`Identity` node. Session nodes contain an opaque
  `token_ref`; token values stay in the private identity store.
- A resume is continue-not-replay. Existing `can_call` statuses (including
  `INCONCLUSIVE`) remain decisions and are filtered before selection. An errored
  attempt has no verdict edge and remains retryable.
- Durable state is an atomic JSON replacement. It contains structural graph
  facts, solver ledgers, a bounded audit tail, and a bounded phase projection;
  it does not contain request bodies, cookies, credentials, fire handles, or
  verdict handles.
- Scope, read-only-first, and audit gates are rebuilt by `scan_target` on every
  resume. No persistence helper imports an oracle, validator, or token store.

## Licenses recorded before deep reading

The six reference checkouts were recorded as neutral aliases: **R1 MIT; R2
dual (MIT for the agent-origin subtree and research-use-only for authored core);
R3 MIT; R4 MIT; R5 MIT; R6 Apache-2.0**. ReachAgent artifacts use only these
aliases and do not identify the checkouts.

## Files read in full

### ReachAgent

- `src/reachagent/graph/chain_solver.py`
- `src/reachagent/graph/persistence.py`
- `src/reachagent/graph/neo4j_store.py`
- `src/reachagent/graph/store.py`
- `src/reachagent/graph/edges.py`
- `src/reachagent/graph/nodes.py`
- `src/reachagent/graph/cypher_executor.py`
- `src/reachagent/tools/coordinator_support.py`
- `src/reachagent/tools/coordinator.py`
- `src/reachagent/tools/payload_chain.py` (the complete chain/result and loop
  sections used by the scan path)
- `src/reachagent/scan/agentic_loop.py`
- `src/reachagent/scan/entrypoint.py`
- `src/reachagent/oracles/evidence.py`
- `src/reachagent/gui/app.py`

### R1 (MIT)

- `backend/pkg/controller/context.go`
- `backend/pkg/controller/task.go`
- `backend/pkg/controller/subtask.go`
- `backend/pkg/controller/subtasks.go`
- `backend/pkg/controller/flow.go`
- `backend/pkg/tools/browser.go`

### R2 (dual license stated above)

- `api/sessions.py`
- `continuous_ops/session_snapshot.py`
- `continuous_ops/task_queue.py`
- `continuous_ops/loop_runner.py`
- `util/session_compact.py`
- `repl/session_resume.py` (loader, resume, statistics, and history sections
  reached by the session-resume path)

### R3 (MIT)

- `unified_agent/task.py`
- `unified_agent/events.py`
- `unified_agent/tools.py`
- `unified_agent/agent.py`

### R4 (MIT)

- `tools/auth_session.py`
- `agents/chain-builder.md`
- `commands/chain.md`
- `docs/auth-sessions.md`

### R5 (MIT)

- `MCP client module` lines 1–280 and 5135–5335 (client, wrappers, browser and
  proxy registrations)
- `MCP client module` lines 1550–2200, 4440–4875, 4870–5565, and 6783–6990
  (cache, recovery, process lifecycle, bounded output, timeout, and partial
  completion paths)
- `HTTP server module` lines 13260–14025 (HTTP framework, scope, repeater,
  browser lifecycle, and response inspection)

### R6 (Apache-2.0)

- `runtime/session_manager.py`
- `runtime/status.py`
- `runtime/backends.py`
- `core/sessions.py`
- `core/runner.py`
- `report/state.py`
- `report/dedupe.py`
- `report/writer.py`

## Concrete techniques learned

- **R1:** restore incomplete task/subtask status from durable records; use
  cancellation-aware worker cleanup, mutexes, wait groups, and idempotent
  finalization rather than replaying completed work.
- **R2:** write snapshots/queues through temporary files plus replacement,
  protect mutable sessions with locks, bound histories, and make recovery a
  retry tick over due work instead of replaying old messages.
- **R3:** represent lifecycle state as normalized events with bounded folding;
  keep one task/tool surface while separating execution from event projection.
- **R4:** chain only after an independently confirmed prerequisite and a
  different mechanism; use hashed/opaque session identifiers and never place raw
  authentication material in history or object representations.
- **R5:** retain bounded output/progress and explicit timeout/partial states;
  process registries and TTL/LRU caches help recovery, but external tool claims
  are observations rather than confirmation authority.
- **R6:** isolate per-run session state, restore it under a lock, write terminal
  status independently from report rendering, and deduplicate report artifacts
  before durable export.

## Gap and smallest safe design

Before this phase, persistence wrote only at the end of a live scan, copied edge
evidence and the entire audit list, and a resumed run with no replacement path
could not update its own state. Solver snapshots did not record a durable chain
advance. The smallest safe design was therefore:

1. `graph.persistence` now projects node fields, edge attributes, solver state,
   audit entries, and phase state through bounded secret/ephemeral-handle
   scrubbing; keeps the last 2,000 audit entries; creates the parent directory;
   and retains temp-file + `os.replace` atomicity. `load_phase_state` exposes only
   the allowlisted scheduling projection.
2. `ChainSolver` rejects non-confirmed or missing findings, rejects a non-positive
   path budget, and records advances. A live process may intentionally explore
   multiple identities from one finding; an advance restored from a checkpoint
   is not replayed. Budgets and spawned nodes remain per-path and deterministic.
3. `scan_target` checkpoints before/after surface mapping, each recon tool,
   authentication, API discovery, recovery, every payload iteration, and final
   completion. `state_path or resume_path` is the write target, so resume without
   a replacement path is durable. Errors persist a bounded exception type before
   propagating; raw payloads, responses, and handles are never included.

## Confirmation-authority proof

The chain path cannot mint a finding: `ChainSolver.advance` checks
`FindingStatus.CONFIRMED_VIOLATION`, while `ReachabilityGraph.add_finding` and
the two relationship writers enforce the same boundary. `scan_target` calls
`run_payload_chain` only through the existing MCP Explorer → deterministic
oracle → Validator path; persistence contains no validator/oracle import. Thus
LLM scheduling and resume metadata can change what is attempted, but cannot
change a finding or oracle status.

## Validation

- Focused Phase 10 and related chain/persistence/coordinator gate:
  `uv run pytest -q tests/phase10/test_durable_resume.py
  tests/phase3/test_graph_persistence.py tests/phase2/test_chain_solver.py
  tests/phase2/test_graph_chain_layer.py tests/phase5/test_coordinator.py` —
  **57 passed**.
- `uv run ruff check` on all changed source/tests — **passed**.
- `uv run mypy src --strict-optional` across the full source tree (152 files) —
  **passed**.
- Reference-name leakage scan on changed code/docs — **no matches**.
- The whole-tree pytest suite was intentionally not run; it remains reserved for
  the final release gate in Phase 14.

## Files changed and deletion review

Changed: `graph/chain_solver.py`, `graph/persistence.py`,
`scan/entrypoint.py`, and `tests/phase10/test_durable_resume.py`.

No files were deleted. The pre-existing untracked `docs/payload.json` was
explicitly left untouched because it is outside Phase 10.

## Remaining weakness

The current entrypoint deliberately treats a loaded graph as the source of truth
and does not re-run cold-start recon on resume; an interruption during a recon
tool therefore needs an operator to restart that tool selection explicitly. A
future GUI phase may consume `phase_state.pending_tools` to present that retry
without replaying completed tools.
