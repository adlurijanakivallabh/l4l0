# Phase 11A decision record — parallel assessment workspace

Date: 2026-08-30
Status: complete
Implementation commit: `32136b0`

## Invariants and scope

- This is a GUI-only extension. It does not add a second execution or
  confirmation path.
- LLM proposals remain advisory; only deterministic oracle-confirmed findings
  are displayed.
- Every count, finding, chain, report, event, and tool status is projected from
  server-owned graph/audit/event state. Missing state is shown as unavailable,
  not invented.
- Credentials, raw bodies, cookies, and fire/browser/verdict handles remain
  server-side.
- Scope, read-only-first, and audit gates are unchanged.
- The five optional Phase 10 capabilities remain deferred.

## Licenses recorded before the reference read

Neutral aliases: **R1 MIT; R2 dual (MIT agent-origin portions plus
research-use-only core); R3 MIT; R4 MIT; R5 MIT; R6 Apache-2.0**.

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

Application shell, theme, sidebar, flow providers, flow dashboard/tabs,
agent/task/tool/message/terminal panels, report helpers, realtime file provider,
and lifecycle/live-panel/reconnect/report/accessibility/responsive browser tests
under the frontend and end-to-end trees.

### R2

`api/app.py`, `api/server.py`, `api/sessions.py`, `api/streaming.py`,
`api/schemas.py`, and `api/commands.py`.

### R3

`unified_agent/task.py`, `unified_agent/events.py`, `unified_agent/tools.py`,
and `unified_agent/agent.py`.

### R4

`tools/auth_session.py`, `agents/chain-builder.md`, `commands/chain.md`, and
`docs/auth-sessions.md`.

### R5

The MCP client/server sections covering process progress, bounded output,
health, dashboards, browser/proxy renderers, timeout, and recovery.

### R6

Viewer server/transcript plus the frontend app, data source, event/issue types,
sidebar, run details/history, severity summary, live graph/transcript/modal,
prompt composer, skeleton/node, tool card, and stylesheet files.

## Concrete techniques learned

- **R1:** keep independent run/flow state in a sidebar, compose detail panes,
  reconcile live deltas after reconnect, preserve scroll position, expose task
  and tool filters, and test lifecycle/accessibility/responsive boundaries.
- **R2:** prefer bounded high-level events, explicit terminal/error events,
  cancellation through the active task, and locked session state.
- **R3:** normalize lifecycle events so a viewer does not depend on one worker's
  internal representation.
- **R4:** distinguish human instructions, tool output, and chain state while
  keeping authentication material opaque.
- **R5:** show progress, partial output, health, timeout, and retry state as
  observations rather than findings.
- **R6:** use a local run switcher, independent run polling, terminal-state
  fetches, bounded cards, and separate graph/transcript/report views.

## Gap and design

The prior GUI could execute more than one backend scan, but one browser variable
tracked only the latest `scan_id`; earlier scans had no live sidebar presence.
The page also lacked a visible active-run count and independent run selection.

The smallest safe extension keeps the existing FastAPI and no-build HTML/JS
architecture:

1. Add a bounded active-assessment rail populated from `/api/scans`, with one
   selectable card per queued/running scan and real phase/finding counts.
2. Keep the selected scan's full detail polling independent from the rail's
   two-second summary refresh; selecting a card changes only the observed scan.
3. Reuse the existing history rows and cancellation/status projections instead
   of adding a second state store. Add no frontend dependency.

## Display-authority proof

`renderActiveScans` consumes only `/api/scans` summaries. The backend summary
uses `_graph_snapshot`, whose counts are computed from `ReachabilityGraph`; the
selected detail view still uses `_audit_rows`, `_finding_rows`, `_chains_for`,
and the stored report/event buffers. `available` and `graph_available` prevent
queued scans from being presented as zero findings. The server redaction seam
remains in force before any value reaches HTML.

## Validation

- Focused GUI/API/static gate:
  `uv run pytest -q tests/gui/test_gui.py tests/gui/test_gui_slices.py tests/phase11`
  — **22 passed** (one existing dependency deprecation warning).
- Inline JavaScript `node --check` — **passed**.
- Full-tree `uv run mypy src --strict-optional` — **passed**.
- Changed-source Ruff — **passed**.
- Playwright smoke with the real server: desktop and 390px mobile navigation,
  History refresh, responsive screenshots, and browser console — **0 errors,
  0 warnings**.
- Seeded visual preview with two concurrent server-side scan records rendered
  both active cards and independent phase/finding counts; selecting a card
  switched the detail view without losing the other card.
- Reference-name leakage scan on changed code/docs — **no matches**.

## Files changed and deletion review

Changed: `src/reachagent/gui/static/index.html` and
`tests/phase11/test_gui_static.py` in this extension. Prior Phase 11 backend
and tests remain in `b77488c`/`9dfd8ad`.

No files were deleted. `docs/payload.json` and ignored Playwright screenshots
were untouched.

## Installed Codex skills

The curated `figma-implement-design`, `playwright-interactive`, and `screenshot`
skills were installed under `$CODEX_HOME/skills`; they are available on the
next Codex turn. No new runtime dependency was added to ReachAgent.

## Remaining weakness

The active-run rail is process-local because the current GUI registry is
process-local. Durable cross-process history and comparison remain scoped to
Phase 12.
