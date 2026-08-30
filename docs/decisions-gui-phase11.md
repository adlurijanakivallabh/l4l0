# Phase 11 decision record — production GUI workspace

Date: 2026-08-30
Status: complete
Implementation commits: `b77488c`, `9dfd8ad`

## Invariants and scope

- This is a browser-only control surface for the existing LLM-driven scan. The
  UI cannot fire requests, invoke an oracle, or write a finding.
- The six deterministic oracle families and the existing scope, read-only-first,
  and audit gates are unchanged.
- Graph, audit, event, provider, and report projections are bounded and
  server-side redacted. Credentials, raw bodies, cookies, and execution handles
  never enter the browser projection.
- Counts, findings, chains, and report text are rendered only from the live
  `ReachabilityGraph`, `AuditLog`, orchestrator events, and stored Phase 4 report.
  An unavailable graph is represented as unavailable/`—`, not as a fabricated
  zero.
- The five optional Phase 10 capabilities remain explicitly deferred: request
  smuggling, cache poisoning, insecure deserialization, WebSocket mapping, and
  continuous monitoring.

## Licenses recorded before deep reading

Reference checkouts were recorded as neutral aliases: **R1 MIT; R2 dual (MIT
for the agent-origin subtree and research-use-only for authored core); R3 MIT;
R4 MIT; R5 MIT; R6 Apache-2.0**. No checkout names are used in ReachAgent
artifacts.

## Files read in full

### ReachAgent

- `src/reachagent/gui/app.py`
- `src/reachagent/gui/static/index.html`
- `tests/gui/test_gui.py`
- `tests/gui/test_gui_slices.py`
- `tests/phase11/test_gui_workspace.py`
- `tests/phase11/test_gui_static.py`
- `src/reachagent/scan/orchestrator.py`
- `src/reachagent/scan/agentic_loop.py`
- `src/reachagent/report/renderer.py`
- `src/reachagent/report/llm_report.py`
- `docs/gui-plan.md`
- `docs/gui-reference-audit.md`

### R1

- `frontend/src/app.tsx`, `main.tsx`, `styles/index.css`
- `frontend/src/components/layouts/app/app-layout.tsx`
- `frontend/src/components/layouts/app/app-header.tsx`
- `frontend/src/components/layouts/main/main-layout.tsx`
- `frontend/src/components/layouts/main/main-sidebar.tsx`
- `frontend/src/providers/theme-provider.tsx`
- `frontend/src/providers/flow-provider.tsx`
- `frontend/src/providers/flows-provider.tsx`
- `frontend/src/features/flows/dashboard/flow-dashboard.tsx`
- `frontend/src/features/flows/dashboard/flow-dashboard-overview.tsx`
- `frontend/src/features/flows/flow-central-tabs.tsx`
- `frontend/src/features/flows/flow-tabs.tsx`
- `frontend/src/features/flows/agents/flow-agents.tsx`
- `frontend/src/features/flows/agents/flow-agent.tsx`
- `frontend/src/features/flows/tasks/flow-tasks.tsx`
- `frontend/src/features/flows/tasks/flow-task.tsx`
- `frontend/src/features/flows/tools/flow-tools.tsx`
- `frontend/src/features/flows/tools/flow-tool.tsx`
- `frontend/src/features/flows/messages/flow-automation-messages.tsx`
- `frontend/src/features/flows/messages/flow-assistant-messages.tsx`
- `frontend/src/features/flows/terminal/flow-terminal.tsx`
- `frontend/src/lib/report/report.ts`
- `frontend/src/lib/report/index.ts`
- `frontend/src/lib/report/report-pdf.tsx`
- `frontend/src/features/flows/files/use-flow-files-realtime.ts`
- `frontend/e2e/specs/flows/lifecycle.spec.ts`
- `frontend/e2e/specs/flows/live-panels.spec.ts`
- `frontend/e2e/specs/flows/reconnect.spec.ts`
- `frontend/e2e/specs/flows/report.spec.ts`
- `frontend/e2e/specs/cross/a11y.spec.ts`
- `frontend/e2e/specs/cross/responsive.spec.ts`
- `frontend/e2e/helpers/reconnect.ts`
- `frontend/e2e/helpers/subscriptions.ts`
- `frontend/e2e/helpers/a11y.ts`
- `frontend/e2e/helpers/errors.ts`

The complete R1 frontend inventory and prior full-source audit remain in
`docs/gui-reference-audit.md`; unrelated editor/file-manager primitives were
not copied into ReachAgent because this phase has no such surface.

### R2

- `api/app.py`
- `api/server.py`
- `api/sessions.py`
- `api/streaming.py`
- `api/schemas.py`
- `api/commands.py`

### R3

- `unified_agent/task.py`
- `unified_agent/events.py`
- `unified_agent/tools.py`
- `unified_agent/agent.py`

### R4

- `tools/auth_session.py`
- `agents/chain-builder.md`
- `commands/chain.md`
- `docs/auth-sessions.md`

### R5

- MCP client/server concern sections covering process progress, bounded output,
  dashboard state, browser/proxy renderers, and recovery.

### R6

- `interface/viewer/server.py`
- `interface/viewer/transcript.py`
- `interface/viewer/frontend/src/App.tsx`
- `interface/viewer/frontend/src/main.tsx`
- `interface/viewer/frontend/src/index.css`
- `interface/viewer/frontend/src/data/serverSource.ts`
- `interface/viewer/frontend/src/types/events.ts`
- `interface/viewer/frontend/src/types/issues.ts`
- `interface/viewer/frontend/src/components/Sidebar.tsx`
- `interface/viewer/frontend/src/components/RunDetails.tsx`
- `interface/viewer/frontend/src/components/PastRunsView.tsx`
- `interface/viewer/frontend/src/components/IssueSeveritySummary.tsx`
- `interface/viewer/frontend/src/components/live/AgentGraph.tsx`
- `interface/viewer/frontend/src/components/live/AgentTranscript.tsx`
- `interface/viewer/frontend/src/components/live/AgentDetailModal.tsx`
- `interface/viewer/frontend/src/components/live/ScanPromptComposer.tsx`
- `interface/viewer/frontend/src/components/live/GraphSkeleton.tsx`
- `interface/viewer/frontend/src/components/live/AgentNode.tsx`
- `interface/viewer/frontend/src/components/live/tool-renderers/ToolCard.tsx`

The remaining small R6 viewer components were inventoried and read as part of
the same frontend audit; only the live graph, transcript, report, history, and
severity paths are relevant to this phase.

## Concrete techniques learned

- **R1:** route-level composition, a collapsible sidebar, persistent theme
  tokens, split workspaces, explicit loading/error/empty states, live deltas,
  reconnect reconciliation, bounded log panes, keyboard/a11y checks, and report
  export actions.
- **R2:** high-level stream events rather than raw token floods, explicit final
  and error events, cancellation through a running task, session locks, and
  bounded state projections.
- **R3:** normalized lifecycle events and one shared tool surface make a live
  viewer simpler than coupling the UI to individual workers.
- **R4:** transcript/session views must distinguish human input, tool output,
  and derived chain state while keeping authentication material opaque.
- **R5:** progress, partial output, timeout, health, and retry states should be
  visible but remain observations—not security verdicts.
- **R6:** disk-backed polling can survive short network blips, stop after a
  terminal fetch, offer run history, render a graph/transcript separately, and
  use bounded/truncatable tool cards.

## Gap and design decisions

The prior page rendered the core four views but had only `running`/`done`/`error`
state, no cancellation control or process-local history, unbounded event growth,
no heartbeat/stale indicator, a fixed one-second timer that stopped on a single
exception, and browser-default white action buttons in the dark theme.

The smallest safe implementation was:

1. Add a lock-protected scan registry, queued/running/completed/failed/blocked/
   cancelled lifecycle projection, bounded event buffer, timestamps, cooperative
   cancellation endpoint, bounded `/api/scans` history, and incremental
   `/api/scan/{id}/events` reads.
2. Redact event, audit, graph, surface, and finding projections server-side;
   mark graph availability explicitly and never expose provider keys.
3. Add an always-real status strip, cancellation affordance, stale-data state,
   exponential polling backoff, history rows, keyboard labels, responsive
   navigation, and provider-form autocomplete/accessibility fixes.
4. Keep the no-build vanilla page and existing provider/API style controls; no
   new dependency or frontend build pipeline was justified.

## Display-authority proof

- `get_scan` uses `_graph_snapshot`, `_audit_rows`, `_finding_rows`, and the
  orchestrator event buffer. `_surface_snapshot` walks `resolves_to`,
  `runs_service`, and `accepts` graph edges. `_chains_for` calls
  `ReachabilityGraph.chain_paths` and labels only persisted chain edges.
- Findings are sourced from `graph.findings()`, whose store requires
  `confirmed_violation`; no client payload can create a finding.
- Reports are the stored Phase 4 output or deterministic export; the browser
  escapes markdown before rendering and never treats narrative text as a
  finding.
- Missing graph data is marked `available: false`; metric placeholders are `—`.
  Counts are populated only after the corresponding server projection exists.
- `_public_text`/`_public_value` remove bearer/password/token/cookie material and
  ephemeral fire/browser/verdict handles before JSON leaves the server.

## Validation

- Focused API/static gate:
  `uv run pytest -q tests/gui/test_gui.py tests/gui/test_gui_slices.py tests/phase11`
  — **22 passed** (one existing Starlette deprecation warning).
- `node --check` on the extracted inline script — **passed**.
- `uv run ruff check src/reachagent/gui/app.py tests/phase11` — **passed**.
- `uv run mypy src --strict-optional` across 152 source files — **passed**.
- Playwright smoke: desktop and 390px mobile snapshots; navigation to History,
  Refresh, responsive resize, and browser console — **0 errors, 0 warnings**.
- No reference-name matches in changed GUI code/tests/docs.
- Whole-tree pytest was not run; it remains reserved for Phase 14 by design.

## Files changed and deletion review

Changed: `src/reachagent/gui/app.py`,
`src/reachagent/gui/static/index.html`,
`tests/phase11/test_gui_workspace.py`, and `tests/phase11/test_gui_static.py`.

No files were deleted. The pre-existing untracked `docs/payload.json` and
Playwright screenshots under the ignored output directory were untouched.

## Remaining weakness

Scan history is process-local and pause/resume is not exposed because the worker
currently has cooperative cancellation but no pause primitive. Persistent scan
history/report comparison belongs to the separately scoped Phase 12 work.
