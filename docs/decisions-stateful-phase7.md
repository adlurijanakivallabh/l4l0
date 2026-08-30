---
title: Phase 7 stateful API and property-based exploration decisions
---

# Phase 7 — stateful API and property-based exploration

Date: 2026-08-29. Scope: explicitly authorized web/API targets and intentionally
vulnerable laboratories only.

## Invariants and authorization boundary

The model proposes only a bounded sequence of graph endpoint/parameter ids,
schema value selectors, roles, and an explanation. It cannot emit a URL, body,
credential, payload, command, status verdict, or finding. Sequence observations
and controls collect facts; only a `probe` paired with an existing deterministic
differential or business-rule oracle may produce an oracle outcome. The outcome
is returned to the caller and audited, never written as a `Finding` by this
module.

Every generated request follows one path:

`StatefulExecution._request` → `RequestFirer.fire` → scope enforcement →
read-only-first → transport → audit.

Mutating HTTP methods and GraphQL mutation operations receive a read-only
preflight through the same firer. Scope refusals, read-only-first refusals, and
transport failures are safe observations, not clean results. The only runtime
values held are short-lived bindings used to construct a later request; graph,
result, prompt, persistence, and audit projections retain only SHA-256 handles,
lengths, hashes, and bounded provenance. There is no manual/non-LLM execution
path.

## Licenses recorded before deep reference reading

The aliases below keep source names out of ReachAgent-owned artifacts.

| Alias | License | Phase-7 posture |
|---|---|---|
| R1 | MIT | Technique-level reuse; no verbatim code |
| R2 | dual: MIT for the agent-origin subtree; research-use-only for authored core | Paraphrased ideas only |
| R3 | MIT | Technique-level reuse; no verbatim code |
| R4 | MIT | Technique-level reuse; no verbatim code |
| R5 | MIT | Technique-level reuse; no verbatim code |
| R6 | Apache-2.0 | Technique-level reuse; no verbatim code |

## Full reference read inventory and techniques

The following files were read fully, including the called helpers needed for
their task/event, API, request, and state paths.

### R1

- `R1/backend/pkg/server/services/graphql.go`
- `R1/backend/pkg/server/services/tasks.go`
- `R1/backend/pkg/server/services/flows.go`
- `R1/backend/pkg/tools/flow_manager.go`
- `R1/backend/pkg/server/models/tasks.go`
- `R1/backend/pkg/server/models/flows.go`
- `R1/backend/pkg/server/models/subtasks.go`

The service layer separates GraphQL queries, mutations, and subscriptions;
flow/task records expose explicit lifecycle states and bounded output; and the
flow manager keeps step dependencies and progress in one stateful execution
record. These informed typed sequence roles, bounded plans, replay signatures,
and response-derived dependencies without trusting a tool's claim.

### R2

- `R2/api/commands.py`
- `R2/api/sessions.py`
- `R2/api/schemas.py`
- `R2/api/streaming.py`
- `R2/continuous_ops/task_queue.py`
- `R2/continuous_ops/session_snapshot.py`
- `R2/app.py`

Per-session locks, cancellation, typed request/response schemas, event streams,
bounded task queues, and atomic snapshots informed the immutable plan, bounded
sequence length, and secret-free result projection.

### R3

- `R3/unified_agent/task.py`
- `R3/unified_agent/types.py`
- `R3/unified_agent/events.py`
- `R3/unified_agent/tools.py`
- `R3/unified_agent/tool_server.py`
- `R3/agent/audit.py`
- `R3/agent/trace.py`
- `R3/agent/memory.py`
- `R3/agent/execution.py`

Typed task envelopes, normalized events, registry validation, stdio tool
boundaries, durable revisions, and immutable traces informed strict model
proposal validation and the decision to keep runtime values outside durable
state.

### R4

- `R4/tools/param_discovery.sh`
- `R4/tools/zero_day_fuzzer.py`
- `R4/tools/graphql_audit.sh`

Response-difference parameter discovery, GraphQL introspection/suggestion and
batch/depth probes informed schema-backed parameter shapes and GraphQL field
arguments. The unsafe scripts' self-reported findings were not reused as
confirmation; all claims remain inert inputs to the existing oracle seam.

### R5

- `R5/mcp.py`
- `R5/server.py`

The HTTP framework's bounded history, repeater/match-replace request shapes,
status/body deltas, and browser inspection informed captured-traffic ingestion
and explicit transport-neutral request templates. Its passive claims remain
untrusted evidence.

### R6

- `R6/utils/api_spec.py`
- `R6/tests/test_api_spec.py`
- `R6/tests/test_api_spec_targets.py`

OpenAPI/Swagger/Postman format recognition, server-variable resolution, strict
path handling, and explicit parse errors informed the API-spec ingestion
boundary and same-authority observed-traffic check.

### ReachAgent callers and helpers

- `src/reachagent/graphql/module.py`
- `src/reachagent/recon/api_discovery.py`
- `src/reachagent/recon/mapper.py`
- `src/reachagent/business_logic/templates.py`
- `src/reachagent/business_logic/runner.py`
- `src/reachagent/graph/chain_solver.py`
- `src/reachagent/identity/store.py`
- `src/reachagent/execution/firer.py`
- `src/reachagent/execution/scope.py`
- `src/reachagent/execution/audit.py`
- `src/reachagent/graph/nodes.py`
- `src/reachagent/graph/edges.py`
- `src/reachagent/graph/store.py`
- `src/reachagent/graph/persistence.py`
- `src/reachagent/graph/neo4j_store.py`
- `src/reachagent/mcp/server.py`
- `src/reachagent/eval/mcp_session.py`
- `src/reachagent/llm/planner.py`
- `src/reachagent/report/llm_report.py`
- `src/reachagent/report/renderer.py`

These established the existing graph node/edge contract, fire gates, identity
boundary, GraphQL field materialization, business-rule evidence, persistence
format, and registry oracle runner. Phase 7 adds only a structural dependency
edge and reuses those seams.

## Gap and smallest safe design

Before this phase, the graph had endpoint/parameter shapes and isolated
single-request probes, but no bounded sequence representation, response-derived
identifier binding, observed-traffic ingestion, or producer→consumer graph
fact. The smallest design adds:

1. immutable `StatefulPlan`/`StatefulStep` records with allowlisted selectors;
2. deterministic boundary/negative values and a replay-shape SHA-256 key;
3. OpenAPI, GraphQL, Postman, and same-authority observed-request template
   ingestion;
4. local identifier extraction plus hash-only `RuntimeBindings` and
   `data_dependency` structural edges;
5. one executor that delegates every request to `RequestFirer`, then invokes
   only the existing differential or business-rule oracle for a declared probe.

The `enables` edge remains finding→finding only; dependency facts use the new
structural edge so an unconfirmed sequence cannot enter the attack-chain layer.

## Safety and oracle proof

Static inspection of `src/reachagent/stateful/explorer.py` shows no import of
`Finding` or the Validator writer. The only oracle call is
`self.oracle_runner(check.mechanism, evidence)` in `_check_oracle`, after two
successful `FireResult` objects have been collected. `StatefulOracleCheck` limits
the mechanism to the existing differential/business-rule families, and
`StatefulPlan` requires a check for every probe role. No branch constructs a
verdict or finding, and no graph method other than the fact-only
`add_dependency` is called by the executor.

The runtime path is covered by focused tests for in-scope firing, scope refusal,
read-only-first refusal, mutating preflight, differential oracle routing,
identifier harvesting, and secret-free graph/audit projections. Generated
observe/control requests are deliberately not findings: they are baseline/state
facts; when a probe is requested, the paired existing oracle is mandatory.

## Implementation and verification

Implemented in:

- `src/reachagent/stateful/explorer.py`
- `src/reachagent/stateful/__init__.py`
- `src/reachagent/graph/edges.py`
- `src/reachagent/graph/store.py`
- `src/reachagent/graph/neo4j_store.py`
- `tests/phase7/test_stateful_exploration.py`

No files were deleted. The pre-existing untracked `docs/payload.json` was left
untouched. Ponytail review found no safe deletion: the schema/traffic ingestion,
state executor, and structural edge each have a distinct Phase-7 caller; the
shared graph/firer/oracle seams are reused rather than duplicated. A changed-file
reference-name scan was clean.

Focused checks:

```text
uv run pytest -q tests/phase7/test_stateful_exploration.py  # 17 passed
uv run ruff format --check ...                             # passed
uv run ruff check ...                                      # passed
uv run mypy src/reachagent/stateful src/reachagent/graph/... # passed
uv run mypy src                                           # 151 files, passed
```

The whole-tree pytest suite was not run; it remains reserved for the plan's
final release gate. Remaining weakness: generated stateful sequences are an
explicit API primitive, not yet selected by the top-level scan orchestrator;
that integration belongs to a later approved phase so this phase does not add a
second planning loop or bypass the existing one.

Feature commit: `824b69a`.
