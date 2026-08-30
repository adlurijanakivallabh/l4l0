# Phase 11A.1 decision record — visual command-center rebuild

Date: 2026-08-30
Status: complete
Implementation commits: `d75a681`, `e988b29`

## Invariants and scope

- This phase changes only the browser presentation and its static contract
  checks. It does not add a request, execution, or confirmation path.
- LLM output remains advisory; only deterministic oracle-confirmed findings are
  rendered as findings.
- Counts, findings, chains, reports, tool statuses, events, and lifecycle values
  come from server-owned graph, audit, event, report, and scan-summary
  projections. Missing graph state is shown as `—`, never as an invented zero.
- Provider keys, credentials, cookies, raw bodies, and fire/browser/verdict
  handles remain server-side and are not rendered.
- Existing scope, read-only-first, audit, cancellation, and redaction paths are
  unchanged. No file was deleted.

## Licenses recorded before reference reads

Neutral aliases: **R1 MIT; R2 dual (agent-origin MIT plus research-use-only
core); R3 MIT; R4 MIT; R5 MIT; R6 Apache-2.0**.

## Full reads

### ReachAgent

- `src/reachagent/gui/app.py`
- `src/reachagent/gui/static/index.html`
- `src/reachagent/scan/orchestrator.py`
- `src/reachagent/scan/agentic_loop.py`
- `src/reachagent/report/renderer.py`
- `src/reachagent/report/llm_report.py`
- `tests/gui/test_gui.py`
- `tests/gui/test_gui_slices.py`
- `tests/phase11/test_gui_workspace.py`
- `tests/phase11/test_gui_static.py`
- `docs/gui-plan.md`
- `docs/gui-reference-audit.md`

### R1

- `frontend/src/app.tsx`
- `frontend/src/main.tsx`
- `frontend/src/styles/index.css`
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

- MCP client/server paths covering progress, bounded output, health, dashboard,
  browser/proxy renderers, timeout, and recovery.

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

## Techniques and design decisions

- **R1** supplied the dashboard language: persistent theme tokens, a clear
  navigation rail, split detail panels, explicit loading/error/empty states,
  bounded live panes, and responsive/a11y checks. The implementation stays
  dependency-free and uses native CSS/DOM because this page already has a
  stable no-build delivery path.
- **R2** supplied the rule that lifecycle and terminal/error states should be
  first-class observations; the top status strip and stale indicator expose
  these without treating them as findings.
- **R3** supplied normalized event vocabulary; the reasoning stream, timeline,
  tool activity, and console all consume the same redacted event projection.
- **R4** supplied the separation of operator intent, tool observations, and
  chain context; the launch card, decision context, and findings cards keep
  those concerns visually separate.
- **R5** supplied visible progress/health/retry observations; the guardrail rail,
  active-assessment cards, lifecycle pill, cancellation affordance, and stale
  state make those states inspectable without elevating them to verdicts.
- **R6** supplied the run switcher and bounded transcript/report pattern; the
  active rail and report/audit sections reuse ReachAgent's server summaries and
  selected-scan polling rather than introducing client-owned state.

## What changed

`src/reachagent/gui/static/index.html` was rebuilt as a mission-control workspace:

- dark-first design tokens with a light-theme fallback persisted by the existing
  theme toggle;
- sticky topbar and compact sidebar navigation for launch, overview, surface,
  findings, report, audit, history, and settings;
- mission hero and launch card with target, scope, identity, budget, and provider
  controls;
- live status strip with lifecycle, cancellation, heartbeat staleness, and
  server-backed event count;
- metrics, reasoning, tool activity, phase timeline, decision context, and live
  console panels;
- graph-backed Host → Service → Endpoint → insertion-point surface view,
  oracle-confirmed finding cards, chain labels, report exports, bounded audit
  trail, process-local history, provider configuration, and concurrent scan rail;
- responsive breakpoints for 1180px and 760px, reduced-motion behavior, focus
  states, semantic navigation, and no horizontal overflow at 390px.

`tests/phase11/test_gui_static.py` now pins the new title, shell, mission,
active-run rail, and guardrail markers in addition to the existing redaction and
server-state markers.

## Display-authority proof

- The browser never receives a graph object, request body, provider key, cookie,
  or ephemeral execution handle. It receives only `_public_*` projections from
  the FastAPI layer.
- `renderCounts`, `renderSurface`, `renderFindings`, `renderAudit`, and
  `renderReport` consume the selected scan response; `renderActiveScans` consumes
  `/api/scans` summaries. The backend computes those summaries from the actual
  graph/audit/event/report stores.
- A missing graph sets `available: false`; metric cells remain `—`. Findings
  render only rows returned by the server's confirmed-finding projection.
- The active rail and history cards display only server lifecycle, phase, event,
  and confirmed-finding counts. The preview used for visual QA seeded actual
  `ReachabilityGraph` nodes and confirmed `Finding` records, not DOM placeholders.
- Markdown is escaped before the small native renderer inserts report HTML; the
  narrative cannot create a finding or alter oracle state.

## Validation

- `uv run pytest -q tests/gui/test_gui.py tests/gui/test_gui_slices.py tests/phase11`
  — **22 passed**, one existing Starlette/httpx deprecation warning.
- `uv run pytest -q tests/phase11/test_gui_static.py tests/gui/test_gui.py tests/gui/test_gui_slices.py`
  — **17 passed**, one existing deprecation warning.
- Inline script extraction plus `node --check` — **passed**.
- `uv run ruff check src/reachagent/gui/app.py tests/phase11` — **passed**.
- `uv run mypy src --strict-optional` across 152 source files — **passed**.
- Playwright real-server smoke — desktop 1600×900, 1280×800, and 390×844;
  screenshots, navigation, theme toggle, responsive overflow, selected scan,
  and browser console — **0 errors, 0 warnings**.
- Seeded two-record preview — two active assessments remained visible in the
  rail, each with independent phase/finding counts; selecting one populated the
  graph-backed surface, event timeline, console, metrics, and finding card while
  preserving the other card.
- Changed-artifact leakage scan — no reference-name or secret-marker matches.

## Deletion review

No files were deleted. The pre-existing untracked `docs/payload.json` and
ignored Playwright output were not staged or modified. No frontend dependency was
added; native HTML/CSS/DOM remains the smallest working implementation.

## Installed skills

The curated `figma-implement-design`, `playwright-interactive`, and `screenshot`
skills are installed under `$CODEX_HOME/skills`. No runtime dependency was
added to ReachAgent.

## Remaining weakness

The active rail and history are process-local because the current GUI registry is
process-local. Durable cross-process history and report comparison remain scoped
to Phase 12.
