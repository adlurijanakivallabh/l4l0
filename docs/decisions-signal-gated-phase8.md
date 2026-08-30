---
title: Phase 8 signal-gated adapter decisions
---

# Phase 8 — signal-gated external adapters

Date: 2026-08-29. Scope: explicitly authorized web/API targets and intentionally
vulnerable laboratories only.

## Invariants and authorization boundary

External tools are optional evidence sources, never detection authorities. The
LLM may choose only the registered signal-tool names and ordering. A tool's
output is parsed into bounded, inert `Candidate` records; it cannot write graph
nodes, call an oracle, or create a finding. A candidate can reach the writer
only through the injected Validator-side reconfirmation callback and a real,
registered, mechanism-matching `OracleVerdict` whose status is
`confirmed_violation`.

Live execution is off unless `REACHAGENT_RECON_LIVE` is explicitly set. When it
is on, the runner enforces signal → scope → binary presence before spawning an
argument array with `shell=False`; output and candidate counts are bounded and
every outcome is audited. Claim URLs are scope-checked again, sensitive text is
redacted, and no query string is written to the audit target. There is no
manual/non-LLM execution path and no new oracle family.

## Licenses recorded before deep reference reading

| Alias | License | Phase-8 posture |
|---|---|---|
| R1 | MIT | Technique-level reuse; no verbatim code |
| R2 | dual: MIT for the agent-origin subtree; research-use-only for authored core | Paraphrased ideas only |
| R3 | MIT | Technique-level reuse; no verbatim code |
| R4 | MIT | Technique-level reuse; no verbatim code |
| R5 | MIT | Technique-level reuse; no verbatim code |
| R6 | Apache-2.0 | Technique-level reuse; no verbatim code |

## Full reference read inventory and techniques

The following files were read fully for the Phase-8 concern, including called
helpers. R5 is a large all-in-one server/client file; the listed HTTP/MCP and
error/recovery sections were read in full because unrelated cloud/tool handlers
do not participate in this phase.

### R1

- `R1/backend/pkg/tools/registry.go`
- `R1/backend/pkg/tools/executor.go`
- `R1/backend/pkg/tools/args.go`
- `R1/backend/pkg/tools/context.go`
- `R1/backend/pkg/tools/tools.go`
- `R1/backend/pkg/tools/searchers/errors.go`
- `R1/backend/pkg/tools/searchers/errors_test.go`
- `R1/backend/pkg/tools/registry_test.go`
- `R1/backend/pkg/providers/registry.go`
- `R1/backend/pkg/server/response/errors.go`
- `R1/backend/pkg/server/models/toolcalls.go`
- `R1/backend/pkg/server/services/toolcalls.go`

Typed tool registries, descriptions, category gating, strict argument schemas,
bounded result summarization, transient-versus-fatal error classes, and tool
call lifecycle records informed the shared metadata contract and refusal/skip
outcomes.

### R2

- `R2/api/app.py`
- `R2/api/commands.py`
- `R2/api/sessions.py`
- `R2/api/schemas.py`
- `R2/api/streaming.py`
- `R2/tool_registry.py`
- `R2/agents/available_tools.py`
- `R2/agents/reporter.py`
- `R2/errors.py`
- `R2/repl/exception_recovery.py`
- `R2/repl/commands/replay.py`
- `R2/tools/common.py`
- `R2/tools/container.py`
- `R2/tools/executor.py`
- `R2/tools/streaming.py`
- `R2/tools/plan.py`
- `R2/tools/evidence/inventory_check.py`
- `R2/tools/evidence/capture_notice.py`
- `R2/sdk/agents/util/_error_tracing.py`

The registry's category/API-key filtering, typed provider/tool errors, bounded
streaming events, cancellation/replay, and explicit error notices informed
strict selection validation, live execution metadata, and graceful optional-tool
degradation. The reporter's no-execution-tool boundary reinforced that reports
must not become a second execution path.

### R3

- `R3/unified_agent/tools.py`
- `R3/unified_agent/tool_server.py`
- `R3/unified_agent/task.py`
- `R3/unified_agent/types.py`
- `R3/unified_agent/events.py`
- `R3/agent/execution.py`
- `R3/agent/agents.py`
- `R3/agent/plan.py`
- `R3/agent/loop.py`
- `R3/agent/audit.py`
- `R3/agent/trace.py`
- `R3/agent/memory.py`

Name/description validation, one shared MCP registry, normalized tool events,
exact evidence receipts, revision-checked state, and retry/recovery settlement
informed candidate caps, explicit reconfirmation handoff, and the rule that
operational failures never become evidence.

### R4

- `R4/agent.py`
- `R4/brain.py`
- `R4/tools/recon_adapter.py`
- `R4/tools/validate.py`
- `R4/tools/target_selector.py`
- `R4/tools/scope_checker.py`
- `R4/memory/audit_log.py`
- `R4/memory/schemas.py`
- `R4/memory/rotation.py`

The ReAct dispatcher and normalized recon adapter taught a distinction between
tool claims and canonical findings, bounded observation windows, scope filtering,
and candidate ranking. Typed validation gates, audit rotation, rate limiting,
circuit breaking, and explicit recovery alternatives informed the safe parser
normalization and non-fatal missing/timeout paths. Passive scanner strings were
not reused as verdicts.

### R5

- `R5/mcp.py` — HTTP/MCP wrapper section read in full (lines 5120–5475)
- `R5/server.py` — HTTP framework/browser handlers (lines 13281–14500) and
  error/recovery implementations (lines 1540–1865, 4440–4555,
  4820–4890, 8640–8895) read in full

The HTTP framework's bounded response history, repeater/sniper request shapes,
status/body deltas, browser inspection, and explicit error-recovery strategies
informed result metadata and the requirement to treat passive claims as inert
until independently re-fired.

### R6

- `R6/report/__init__.py`
- `R6/report/state.py`
- `R6/report/writer.py`
- `R6/report/dedupe.py`
- `R6/report/sarif.py`
- `R6/report/usage.py`
- `R6/tools/reporting/tool.py`
- `R6/tools/output_store.py`
- `R6/runtime/status.py`
- `R6/config/tool_call_limits.py`
- `R6/config/tool_call_ids.py`

Metadata-first report listings, atomic artifact writes, safe code-location
normalization, dedupe identity, bounded tool output spill, unique call IDs, and
per-turn tool-call limits informed the audit metadata, bounded previews, and
non-destructive candidate handoff.

### ReachAgent signal-gated callers and tests

- `src/reachagent/recon/tools/signal_gated.py`
- `src/reachagent/recon/tools/sqlmap.py`
- `src/reachagent/recon/tools/nuclei.py`
- `src/reachagent/recon/tools/nikto.py`
- `src/reachagent/recon/tools/dalfox.py`
- `src/reachagent/recon/tools/commix.py`
- `src/reachagent/recon/tools/jwt_tool.py`
- `src/reachagent/recon/signal_dispatch.py`
- `src/reachagent/recon/signal_tuning.py`
- `src/reachagent/tools/candidate.py`
- `src/reachagent/tools/validator.py`
- `src/reachagent/tools/validator_support.py`
- `src/reachagent/detection/oracle_gateway.py`
- `src/reachagent/execution/firer.py`
- `src/reachagent/execution/scope.py`
- `src/reachagent/execution/audit.py`
- `src/reachagent/scan/orchestrator.py`
- `tests/phase3/test_signal_gated_tools.py`
- `tests/recon/test_signal_gated_expand3.py`
- `tests/recon/test_signal_tuning.py`
- `tests/phase1/test_tool_boundaries.py`

These establish the existing six adapters, signal gates, candidate shape, six
oracle registry, Validator seam, and top-level dispatch path.

## Gap and smallest safe design

Before this phase, adapters emitted unbounded/unvalidated candidates, audit
entries lacked command/duration/exit/partial-output metadata, selection accepted
extra model fields, and the dispatcher discarded candidate objects after showing
only a count. The reconfirmation helper accepted any truthy object as a verdict.

The smallest safe design was to harden the shared base rather than duplicate
guards in six adapters:

1. validate/redact/scope-check candidate fields and cap candidates at 100;
2. cap aggregate stdout/file output at 1 MiB and expose partial state;
3. add immutable `SignalGatedMetadata` and include execution metadata in audit
   events and GUI previews;
4. return dispatcher results, expose bounded candidate previews, and hand every
   candidate to an injected reconfirmation callback when supplied;
5. require a registered, mechanism-matching `OracleVerdict` with
   `confirmed_violation` before the injected writer can run;
6. reject malformed LLM selector objects and force live-off dispatch to pass an
   empty environment.

No adapter gained a new finding path, command string, or oracle family.

## Explicit independent-reconfirmation proof

The six adapter modules contain no import of Validator, `run_oracle`, or
`write_finding`. The new AST test
`test_all_six_adapters_have_no_validator_import_and_emit_no_findings` passed.
The runtime test confirms an emitted candidate leaves `graph.findings()` empty;
the reconfirmation test rejects both a forged truthy object and a real verdict
whose mechanism does not match the candidate. `run_signal_tools` only invokes
the optional injected callback and never imports or calls the writer itself.
Therefore no adapter output can create a finding without independent
ReachAgent re-confirmation.

## Implementation and verification

Implemented in:

- `src/reachagent/recon/tools/signal_gated.py`
- `src/reachagent/recon/tools/__init__.py`
- `src/reachagent/recon/signal_dispatch.py`
- `src/reachagent/recon/signal_tuning.py`
- `tests/phase8/test_signal_gated_adapters.py`
- `docs/build-plan.md`

No files were deleted. The pre-existing untracked `docs/payload.json` was left
untouched. Ponytail review found no safe deletion: the shared runner, dispatch,
selection, and focused tests each have independent load-bearing responsibilities.

Focused checks:

```text
uv run pytest -q tests/phase8/test_signal_gated_adapters.py       # 8 passed
uv run pytest -q tests/phase3/test_signal_gated_tools.py \
  tests/recon/test_signal_gated_expand3.py tests/recon/test_signal_tuning.py # 62 passed
uv run ruff format --check <changed Phase-8 files>               # passed
uv run ruff check <changed Phase-8 files>                         # passed
uv run mypy <changed ReachAgent modules>                         # passed
```

Whole-tree pytest was not run; it remains reserved for the final release gate.
Remaining weakness: the top-level scan currently emits an explicit
`reconfirmation_required` event when no Validator callback is supplied; wiring a
class-specific independent evidence builder belongs to a later approved phase,
not to the adapter boundary itself.

Feature commit: `5a91e24`.
