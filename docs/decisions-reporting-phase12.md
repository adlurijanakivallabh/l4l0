# Phase 12 decision record — reporting, evidence export, and operational history

Date: 2026-08-30
Status: complete
Implementation commit: `7201978`

## Invariants and scope

- Reporting is read-only over confirmed graph state. It never fires a request,
  calls an oracle, creates a finding, or promotes model prose.
- Only `FindingStatus.CONFIRMED_VIOLATION` nodes are exported. Unconfirmed,
  inconclusive, and candidate states cannot appear in findings, evidence, or
  SARIF results.
- Exported values are bounded and redacted. Credentials, bearer values, cookie
  values, raw request/response bodies, raw payloads, and execution handles are
  never included.
- Report generation may fail or fall back without changing graph findings.
- Snapshot comparison loads persisted graph/audit facts only; it does not replay
  requests or re-run confirmation.
- No files were deleted.

## Licenses recorded before reference reads

Neutral aliases: **R1 MIT; R2 dual (agent-origin MIT plus research-use-only
core); R3 MIT; R4 MIT; R5 MIT; R6 Apache-2.0**.

## Full reads

### ReachAgent

- `src/reachagent/report/renderer.py`
- `src/reachagent/report/llm_report.py`
- `src/reachagent/report/__init__.py`
- `src/reachagent/gui/app.py`
- `src/reachagent/gui/static/index.html`
- `src/reachagent/graph/persistence.py`
- `src/reachagent/graph/store.py`
- `src/reachagent/graph/nodes.py`
- `src/reachagent/graph/edges.py`
- `src/reachagent/graph/chain_solver.py`
- `src/reachagent/execution/audit.py`
- `src/reachagent/oracles/evidence.py`
- `src/reachagent/scan/entrypoint.py`
- `tests/phase12/test_reporting.py`
- `tests/report/test_llm_report.py`
- `tests/gui/test_gui.py`
- `tests/gui/test_gui_slices.py`
- `tests/phase11/test_gui_workspace.py`
- `tests/phase11/test_gui_static.py`
- `tests/phase3/test_graph_persistence.py`

### R1

- `backend/pkg/csum/chain_summary.go`
- `backend/pkg/server/services/analytics.go`
- `backend/pkg/server/models/analytics.go`
- `backend/pkg/database/analytics.sql.go`
- `backend/pkg/database/converter/analytics.go`
- `backend/sqlc/models/analytics.sql`
- `frontend/src/lib/report/report.ts`
- `frontend/src/lib/report/index.ts`
- `frontend/src/lib/report/report-pdf.tsx`
- `frontend/src/pages/flows/flow-report.tsx`
- `frontend/src/pages/flows/flow-report.test.tsx`
- `frontend/src/pages/dashboard/dashboard.tsx`
- `frontend/src/pages/dashboard/dashboard-analytics.tsx`
- `frontend/src/pages/dashboard/dashboard-overview.tsx`
- `frontend/src/components/dashboard/index.ts`
- `frontend/src/components/dashboard/metric-card.tsx`
- `frontend/src/components/dashboard/chart-card.tsx`
- `frontend/src/components/dashboard/chart-tooltip.tsx`

### R2

- `R2/api/sessions.py`
- `R2/api/schemas.py`
- `R2/continuous_ops/session_snapshot.py`
- `R2/parallel_worker.py`
- `R2/util/session_compact.py`

### R3

- `R3/agent/audit.py`
- `R3/agent/trace.py`
- `R3/legacy/report_generator.py`

### R4

- `agents/report-writer.md`
- `commands/report.md`
- `rules/reporting.md`
- `agents/chain-builder.md`

### R5

- `R5/server.py` health, structured result, telemetry, and error-statistic
  paths
- `R5/mcp.py` health, structured result, and recovery-result paths

### R6

- `R6/report/writer.py`
- `R6/report/sarif.py`
- `R6/report/state.py`
- `R6/report/usage.py`
- `R6/report/dedupe.py`
- `R6/viewer/report_pdf.py`
- `R6/viewer/server.py`
- `R6/viewer/transcript.py`
- `R6/viewer/frontend/src/App.tsx`
- `R6/viewer/frontend/src/data/serverSource.ts`
- `R6/viewer/frontend/src/types/events.ts`
- `R6/viewer/frontend/src/types/issues.ts`
- `R6/viewer/frontend/src/components/Sidebar.tsx`
- `R6/viewer/frontend/src/components/RunDetails.tsx`
- `R6/viewer/frontend/src/components/PastRunsView.tsx`
- `R6/viewer/frontend/src/components/IssueSeveritySummary.tsx`
- `R6/viewer/frontend/src/components/live/AgentGraph.tsx`
- `R6/viewer/frontend/src/components/live/AgentTranscript.tsx`
- `R6/viewer/frontend/src/components/live/tool-renderers/ToolCard.tsx`
- `R6/viewer/frontend/src/components/live/tool-renderers/ReportListRenderer.tsx`
- `R6/viewer/frontend/src/components/live/tool-renderers/VulnReportRenderer.tsx`
- `tests/test_sarif.py`
- `tests/test_reporting_fields.py`
- `tests/test_report_writer.py`
- `tests/test_report_pdf.py`
- `tests/test_list_reports.py`

## Techniques learned and design decisions

- **R1:** sort report sections deterministically, provide a severity summary and
  time-series usage views, keep PDF generation lazy, and make loading/error/
  empty states explicit. ReachAgent keeps its dependency-free renderer and
  applies the same deterministic ordering to graph findings.
- **R2:** expose lightweight session summaries, preserve bounded history, and
  separate stateful detail from list views. The snapshot comparison API follows
  that split and never returns raw session content.
- **R3:** retain immutable episode/trace provenance and usage facts instead of
  trusting a final narrative. ReachAgent's evidence index keeps opaque handles,
  oracle identity, and bounded audit matches as provenance.
- **R4:** write impact-first reports only after validation, preserve assumptions,
  remediation, and independently proven chain steps. ReachAgent exports the
  chain edges already persisted by the graph rather than inferring chains from
  prose.
- **R5:** represent health, timeout, recovery, and structured tool outcomes as
  observations. These become export metadata only; they never become findings.
- **R6:** use SARIF rule/result separation, severity mapping, stable fingerprints,
  atomic artifacts, hydrated run history, bounded report lists, and explicit
  PDF/report failure handling. ReachAgent implements the useful SARIF/evidence/
  history subset with stdlib JSON/HTML/Markdown and keeps raw exploit bodies out
  of machine-readable exports.

## What was built

### Shared renderer (`src/reachagent/report/renderer.py`)

- Secret-safe bounded text/metadata projection and `sanitize_report_markdown`.
- Confirmed-only deterministic JSON/Markdown/HTML tables.
- Evidence index JSON, Markdown, and HTML with severity counts, scope, identity,
  tool, payload reference, oracle, evidence reference, timing, chain precondition,
  opaque request/response handles, chain paths, and matching audit entries when
  those facts exist in graph metadata.
- SARIF 2.1.0 export with stable rule IDs, severity levels, oracle/evidence
  properties, logical endpoint/target locations, and confirmed-result count.
- Self-contained report HTML combining sanitized narrative and evidence index.
- Deterministic report bundle containing narrative, evidence index, and SARIF.
- Read-only comparison of two in-memory graph/audit snapshots and two persisted
  JSON snapshots, including count, endpoint, finding, and audit deltas.

### GUI/API (`src/reachagent/gui/app.py`, static page)

- `/api/scan/{id}/evidence` returns the bounded evidence index.
- `/api/scan/{id}/export` now supports `json`, `sarif`, `evidence`,
  `evidence-md`, `bundle`, `html`, and sanitized Markdown while preserving the
  legacy findings JSON shape.
- `/api/scans/compare` compares process-local scans without replay.
- `/api/history/compare` compares snapshots only beneath the configured
  `REACHAGENT_HISTORY_DIR`; traversal and unconfigured history fail closed.
- Export responses set `X-Content-Type-Options: nosniff` and safe attachment
  names. The report workspace exposes Markdown, JSON, SARIF, Evidence, Bundle,
  and HTML links with responsive wrapping.
- Stored report prose is sanitized before serving, storing, or downloading.

## Display/export authority proof

`build_evidence_index` starts from `ReachabilityGraph.findings()` and filters to
confirmed violations. `build_sarif_report`, all evidence renderers, and history
diffs consume that projection. No renderer imports a firer, validator, or oracle.
Graph chain paths are read from persisted `enables`/`derived_credential` edges;
no chain is inferred from an LLM narrative. Raw payload/body fields are blocked
by the renderer and provider credentials never enter the scan record.

The explicit redaction test covers Authorization bearer values, password values,
cookie values, userinfo credentials, API-style keys, and JWT-shaped values across
Markdown, JSON bundle, HTML, served reports, and SARIF. The test asserts the
secret values are absent, not merely that a label says "redacted".

## Validation

- `uv run pytest -q tests/phase12/test_reporting.py tests/report/test_llm_report.py tests/gui/test_gui.py tests/gui/test_gui_slices.py tests/phase11 tests/phase3/test_graph_persistence.py` — **48 passed**, one existing Starlette/httpx deprecation warning.
- `uv run ruff check src/reachagent/report src/reachagent/gui/app.py tests/phase12 tests/phase11 tests/report tests/gui` — passed.
- `uv run mypy src --strict-optional` across 152 files — passed.
- Inline GUI JavaScript `node --check` — passed.
- Playwright real server — desktop/mobile launch, responsive overflow, provider
  settings, report link rendering, and browser console — passed with zero
  errors/warnings. Seeded completed-scan UI showed the six export links and one
  confirmed finding sourced from the graph.
- Persisted snapshot comparison and traversal rejection — passed.
- Changed-artifact reference-name leakage scan — no matches.

## Ponytail review

Kept the existing no-build FastAPI/vanilla page and stdlib JSON/Markdown/HTML
formats. Reused `ReachabilityGraph`, `AuditLog`, `graph.persistence`, and the
existing report route; added no dependency, database, or alternate execution
path. No further safe deletion was identified.

## Deletion review

No files were deleted. The pre-existing untracked `docs/payload.json` was not
staged or modified.

## Follow-up boundary

Durable GUI history remains process-local unless callers opt into persisted state
files and configure `REACHAGENT_HISTORY_DIR`. Cross-process indexing and rich PDF
reporting remain outside Phase 12 and belong to later scoped work.
