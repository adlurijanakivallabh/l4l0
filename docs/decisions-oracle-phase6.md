---
title: Phase 6 deterministic evidence and oracle hardening decisions
---

# Phase 6 — deterministic evidence and oracle hardening

Date: 2026-08-29. Scope: explicitly authorized web/API targets and intentionally
vulnerable laboratories only. This phase changes evidence handling and reporting
provenance; it does not add an oracle family or delegate confirmation to the LLM.

## Invariants and authorization boundary

The model can propose a stimulus, transport, or ordering, but it cannot select a
verdict, construct an `OracleVerdict`, set a finding status, or write a finding.
The six registered deterministic families remain the only confirmation authority.
Raw request/response bodies, cookies, bearer values, and credentials remain in the
server-side fire/session store. Only bounded opaque handles and safe projections
can be returned with a verdict or copied into graph metadata. Scope, read-only-first,
and audit gates are unchanged.

## Licenses recorded before deep reference reading

| Alias | License | Phase-6 posture |
|---|---|---|
| R1 | MIT | Technique-level reuse only |
| R2 | dual: MIT for the agent-origin subtree; research-use-only for authored core | Paraphrased ideas only |
| R3 | MIT | Technique-level reuse only |
| R4 | MIT | Technique-level reuse only |
| R5 | MIT | Technique-level reuse only |
| R6 | Apache-2.0 | Technique-level reuse only |

## Full reference reads and concrete techniques

The validator/reporting/error read was completed before implementation. R1's
validator parser and tests use typed errors, AST extraction, deterministic
ordering, and mock rendering; its result/report writers separate pass/fail,
unsupported, latency, and durable markdown output. R2's typed error hierarchy,
streaming result object, reporter with no execution tools, and trace lifecycle
separate provider failure from final output and keep live events consumable. R3
persists append-only episode events, exact grounding receipts, atomic JSON/SQLite
state, revision checks, and explicit failure settlement. R4's validation tool
requires concrete reproduction and impact gates, validates structured audit
entries, keeps a rate/circuit guard, and persists rejection reasons. R5's HTTP
framework keeps proxy history, bounded response content, scope/match-replace,
repeater and sniper actions, but its passive vulnerability strings are claims,
not confirmation. R6's report state hydrates corruption loudly, writes artifacts
atomically, emits a fresh machine-readable report even when empty, validates
required evidence/CVSS/location fields, keeps listing responses metadata-first,
and fingerprints reports from stable primitives rather than prose.

Files read in full for this phase:

- **R1:** `backend/pkg/templates/validator/validator.go`,
  `backend/pkg/templates/validator/validator_test.go`,
  `backend/pkg/providers/tester/result.go`,
  `backend/pkg/providers/tester/testdata/result.go`,
  `backend/cmd/ctester/report.go`,
  `backend/pkg/server/response/errors.go`,
  `frontend/src/lib/report/report.ts`,
  `frontend/src/lib/report/report-pdf.tsx`, and `frontend/src/lib/errors.ts`.
- **R2:** `src/errors.py`, `src/agents/reporter.py`,
  `src/sdk/agents/result.py`, `src/sdk/agents/tracing/traces.py`, and
  `src/sdk/agents/util/_error_tracing.py`.
- **R3:** `agent/audit.py`, `agent/trace.py`, `agent/memory.py`, and
  `agent/execution.py`.
- **R4:** `tools/validate.py`, `memory/audit_log.py`, `memory/schemas.py`,
  `commands/validate.md`, `commands/report.md`, and `agents/validator.md`.
- **R5:** `mcp.py` client/session/error wrappers, the HTTP framework
  and browser-inspection classes plus their `/api/tools/http-framework`,
  `/api/tools/browser-agent`, and `/api/tools/burpsuite-alternative` handlers
  in `server.py`.
- **R6:** `report/__init__.py`, `report/state.py`, `report/writer.py`,
  `report/dedupe.py`, `report/sarif.py`, `report/usage.py`,
  `tools/reporting/tool.py`, `interface/viewer/transcript.py`, and
  `runtime/status.py`.

ReachAgent files read in full before editing were `oracles/__init__.py`,
`oracles/base.py`, `oracles/registry.py`, all six files under `oracles/`,
`detection/oracle_gateway.py`, `tools/validator.py`,
`tools/validator_support.py`, `tools/explorer.py`, `mcp/server.py`,
`execution/audit.py`, `graph/nodes.py`, `graph/edges.py`,
`graph/store.py`, `graph/persistence.py`, `eval/mcp_session.py`,
`report/llm_report.py`, `report/renderer.py`, and the existing focused oracle,
MCP, graph, detector, and race tests. The new focused file is
`tests/phase6/test_oracle_hardening.py`.

## Gap and smallest safe design

The six oracles already had pure status decisions and opaque fire handles, but
their evidence records had no common typed projection, no bounded validation for
status/latency/ref fields, no deterministic explanation for an inconclusive
result, and no negative-result audit hook. Finding metadata was also an unchecked
path into graph/report state. The smallest safe design adds one immutable
`EvidenceMetadata` projection, validates it at each oracle seam, adds a stable
reason string to the existing verdict, and records negative decisions only via
the existing audit object. Raw bodies remain untouched for deterministic matches
and never appear in the projection.

## Implementation

- Added `oracles/evidence.py` with bounded opaque handles, non-sensitive headers,
  body-projection labels, finite timing samples, OOB channel labels, and strict
  secret-bearing metadata rejection.
- Extended each existing evidence dataclass with optional typed metadata. Timing
  samples and OOB observed channels are copied into the safe projection when the
  caller did not provide an equivalent projection; structural response headers
  are copied only from the non-secret framing/CORS set.
- Extended the frozen verdict with deterministic `reason` and
  `evidence_metadata`; `OracleOutcome` and MCP `VerdictOut` expose only that safe
  projection. Inconclusive reasons distinguish missing controls, absent markers,
  equivalent responses, and ambiguous actions.
- Hardened status, body, label, signature, nonce, flow, and timing validation.
  `validator.write_finding` and `ReachabilityGraph.add_finding` now reject
  secret-bearing metadata before persistence and stamp the deterministic oracle
  reason for confirmed findings.
- Added negative-result audit records to `mark_inconclusive`, optional audited
  `run_oracle`, and the MCP oracle wrapper. Audit text is bounded and redacted;
  no body/header/token value is included.
- Fixed the existing Explorer manifest leak by aliasing its annotation-only
  `Mapping` import; the public Explorer surface now remains exactly the intended
  five tools.
- No files were deleted. The pre-existing untracked `docs/payload.json` was not
  touched and is not part of this phase.

## Registry-count and oracle-boundary proof

The six-family registry count is unchanged: `OracleMechanism` has exactly six
members (`differential`, `execution_confirmation`, `oob_callback`,
`timing_statistical`, `structural`, and `business_rule_invariant`), and the
registry keys equal that set. No architecture decision expanded the registry.

`tests/phase6/test_oracle_hardening.py::test_verdict_constructors_are_confined_to_the_six_oracle_modules`
AST-walks the whole source tree and finds exactly six `OracleVerdict(...)` calls,
one in each concrete oracle. Its detector-package scan rejects both
`OracleVerdict(...)` and `Finding(...)` calls in detector modules. The runtime
tests pass only oracle-returned `confirmed_violation` verdicts to the Validator,
verify an inconclusive verdict cannot create a graph finding, and reject a direct
secret-bearing graph metadata write. Together these are the AST/runtime proof:
detectors emit evidence/candidates; the Validator seam alone can commit a
finding, and the graph's final status guard rejects every other status.

## Focused verification

Ponytail review kept the shared metadata type because it is used by all six
families and both MCP/in-process boundaries; no dependency or duplicate registry
was added. The Explorer public-surface leak found during review was fixed at its
single import site. Reference-name leakage scanning of changed source, tests,
and this decision record found none.

Focused command:

```text
uv run pytest -q tests/phase6/test_oracle_hardening.py tests/phase1/test_differential_oracle.py tests/phase1/test_validator_tools.py tests/phase1/test_mcp_server.py tests/phase1/test_explorer_pipeline.py tests/phase2/test_business_logic_templates.py tests/phase3/test_timing_statistical_oracle.py tests/phase3/test_oob_multichannel.py tests/phase3/test_file_upload.py tests/phase3/test_clickjacking.py tests/phase3/test_cors.py tests/phase3/test_csrf.py tests/phase3/test_dom_execution_marker.py tests/phase3/test_graph_persistence.py tests/phase6/test_race.py
```

Result: **240 passed, 2 skipped** (the existing crAPI availability and live
race-lab skips; no failures). Focused Ruff and mypy checks passed for all changed
modules. A whole-tree suite was intentionally not run; it remains reserved for
the plan's final release gate.

## Remaining weakness

The in-process caller must opt into the new `audit=` keyword on `run_oracle` or
call `mark_inconclusive`; the MCP wrapper records it automatically. This keeps
the pure default dispatcher side-effect free while making the production MCP
path fully auditable. A future phase can thread one shared audit object through
the long-running coordinator if a single process-wide negative-result stream is
needed.
