---
title: Phase 4 LLM planning and adaptive control decisions
---

# Phase 4 — LLM planning and adaptive control

Date: 2026-08-28. Scope: explicitly authorized web/API targets and intentionally
vulnerable laboratories only.

## Invariants and authorization boundary

The scan remains LLM-driven, scope-gated, read-only-first, bounded, and
resumable. Model output is a proposal for phase scheduling and prioritization;
it cannot fire a request, call an oracle, set a verdict, or write a finding.
Only the existing Validator seam can turn a deterministic oracle violation into
a graph Finding. Cancellation and provider errors are visible terminal states,
not silent unauthenticated or unverified continuation.

## Licenses recorded before deep reading

| Alias | License | Phase-4 posture |
|---|---|---|
| R1 | MIT | Technique-level reuse only |
| R2 | MIT for the agent-origin subtree; research-use-only for authored core | Paraphrased ideas only |
| R3 | MIT | Technique-level reuse only |
| R4 | MIT | Paraphrased ideas only |
| R5 | MIT | Technique-level reuse only |
| R6 | Apache-2.0 | Technique-level reuse only |

## Full reference reads and techniques

The Phase 4 read covered the controller/provider and subscription flow in R1;
the orchestration, handoff, model factory, run/stream/result, tool execution,
compaction, and parallel-tool paths in R2; normalized agent/task/event and
durable plan/execution paths in R3; the ReAct loop, bounded memory, trace,
loop detector, phase assessment, time budget, and watchdog paths in R4; the
process/recovery/resource lifecycle in R5; and the runner, coordinator,
execution, budget hooks, and per-scan session lifecycle in R6. ReachAgent's
planner, adaptive loop, provider runtime, coordinator support, and scan
entrypoints were read with their callers and tests.

Full files read (including called helpers) were:

- **R1:** `backend/pkg/controller/flow.go`, `assistant.go`, `task.go`,
  `subtask.go`, `backend/pkg/providers/performer.go`, `provider.go`,
  `providers.go`, and `backend/pkg/graph/subscriptions/{controller,publisher,subscriber}.go`.
- **R2:** `agents/{orchestration_agent,operational_handoffs,factory}.py`,
  `sdk/agents/{agent,handoffs,run,_run_impl,result,stream_events,parallel_tool_executor,orchestration_mas_hint}.py`,
  `sdk/agents/models/chatcompletions/auto_compactor.py`, and
  `api/streaming.py`.
- **R3:** `unified_agent/{agent,task,types,events}.py` and
  `pentest_agent/{plan,execution,agents,trial,loop}.py`.
- **R4:** `agent.py`, the planning/watchdog sections of `brain.py`,
  `memory/schemas.py`, `tools/auth_session.py`, `tools/_spray_http_form.py`,
  `tools/_spray_oauth.py`, and `tools/credential_store.py`.
- **R5:** `mcp_client.py` and `server.py` process, recovery,
  resource, and status paths.
- **R6:** `core/{runner,execution,agents,hooks,sessions}.py`,
  `runtime/session_manager.py`, and viewer authentication/setup helpers.
- **ReachAgent:** `llm/{planner,runtime,client}.py`,
  `scan/{agentic_loop,entrypoint,orchestrator}.py`,
  `tools/coordinator_support.py`, graph/audit/identity helpers, and the focused
  planner, adaptive-recon, agentic-loop, orchestrator, and entrypoint tests.

The concrete techniques carried forward are: immutable validated proposals with
revision checks (R3), observe→think→act turns with compact context and retry
feedback (R1/R2/R4), normalized event types (R2/R3), bounded repetition and
time guards (R4), atomic resumable snapshots (R3/R6), and explicit budget,
cancellation, and provider-vs-target error states (R1/R5/R6).

## Gap and smallest safe design

Before this phase, ReachAgent had an upfront plan and three advisory calls. The
advisory result did not carry a state revision, had no `revisit` action, no
durable control checkpoint, no idle/cancel guard, and only the endpoint `skip`
branch changed execution. The smallest safe design is a stdlib-only control
state in `scan.agentic_loop`: bounded deterministic snapshots, SHA-256 state
revisions, four allowlisted actions (`continue`, `skip`, `revise`, `revisit`),
loop/revisit limits, monotonic idle checks, cancellation checks, and atomic JSON
checkpoint load/save. The orchestrator applies only scheduling, hint, and
priority changes; all firing and confirmation paths stay untouched.

## Oracle-boundary proof

`PhaseDecision` and `AdaptiveControlState` contain strings, counters, and phase
names only. The decision application path never imports `validator`,
`OracleMechanism`, `Finding`, MCP firing, or graph write methods. The only
finding path remains detector → `_ValidatorSeam.run` → `validator.run_oracle`
→ `_ValidatorSeam.write` → `validator.write_finding`; a malicious model field
such as `status` or `finding` is rejected as an unsupported decision field and
cannot reach that seam.

## Implementation and focused verification

Implemented in `src/reachagent/scan/agentic_loop.py`, with cancellation wiring
and safe discovery-event handling in `src/reachagent/scan/entrypoint.py`, and
phase snapshots/adaptive scheduling in `src/reachagent/scan/orchestrator.py`.
The focused gate passed 37 tests across the control loop, planner, and adaptive
recon suites. The whole repository suite is intentionally deferred to Phase 10.
Feature commit: `97a54f7`; cancellation persistence follow-up: `a95de3d`.
