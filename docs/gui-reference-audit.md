# Reference-project GUI audit — pentagi, cai, hexstrike-ai, PentestGPT, claude-bug-bounty

**Date:** 2026-08-24 · **Method:** each project's UI source read in full by a
subagent (frontend tree enumerated, key files read to EOF); licenses stated before
reading. This is the "what do the references actually look like" pass behind
`docs/gui-plan.md`.

**Licenses (stated first, as required):**
- **pentagi** — MIT (`Copyright (c) 2025 PentAGI Development Team`).
- **cai** — dual: `src/cai/agents` MIT (from openai-agents-python), `src/cai` core
  Alias Robotics S.L. research-use-only. The TUI/REPL is read for visual ideas only.
- **hexstrike-ai** — MIT (`Copyright (c) 2026 Muhammad Osama (0x4m4)`).
- **PentestGPT** — MIT (`Copyright (c) 2023 Grey_D`).
- **claude-bug-bounty** — MIT (`Copyright (c) 2026 Claude Bug Bounty Hunter Contributors`).

**Bottom line up front:** only **pentagi** has a real web GUI. cai has a terminal
TUI + REPL (not a web GUI). hexstrike-ai, PentestGPT, and claude-bug-bounty are
CLI/agent-only — none ships a GUI (their "web" files are a JSON API, a static
design doc, and a marketing page / vulnerable demo *target*, respectively).

---

## 1. pentagi — the one real web GUI (MIT)

### 1.1 Framework + UI library
React **19.2** + TypeScript + **Vite** (SWC, pnpm), `react-router-dom` 7 (data
router), **Tailwind CSS 4** + **shadcn/ui** primitives on **Radix UI** (20+
primitives), **Apollo Client 4** (GraphQL) + axios (REST), **TanStack Table 8** +
**TanStack Virtual 3** (virtualized tables), **@xterm/xterm 6** (embedded live
terminal, WebGL), **Recharts 3** (charts), **TipTap 3** (rich-text markdown
editors), **@react-pdf/renderer** (PDF reports), `react-markdown` for report view,
`react-resizable-panels` (split panes), `cmdk` command palette, `sonner` toasts,
`lucide-react` icons, `react-hook-form` + `zod`.

### 1.2 Literal screens/views
- login (2-col split: centered form left, animated logo on a primary-tinted gradient right; force-password-change sub-view)
- oauth result (popup window → posts message to opener → auto-closes)
- **dashboard** — Tabs `Analytics | Overview`; Analytics = period picker + 4 Recharts views (Flows Activity, Tool Calls, Token Usage, Cost) + Flow Execution Details list; Overview = 4 MetricCards + Usage by Provider/Model/AgentType + Tool Calls by Function tables
- **flows list** — virtualized DataTable (ID/title/status-badge/provider-icon/terminals/created/updated; global filter, column-hiding, pagination, sort; hover actions, right-click context menu, inline rename, New Flow)
- new flow (centered card; Automation | Assistant tabs; FlowForm = autosize textarea + provider dropdown + Use-Agents switch + templates/resources attach)
- **flow detail** — full-height split (ResizablePanelGroup 50/50): LEFT panel Tabs `Automation | Assistant | Dashboard`, RIGHT panel Tabs `Terminal | Tasks | Agents | Searches | Vector Store | Files | Screenshots`; header = status icon + provider + double-click-rename title + Report dropdown (open/copy-MD/download-MD/download-PDF) + favorite + prev/next
  - automation chat (message cards: thinking toggle, markdown, collapsible result as markdown **or inline mini xterm**; composer with status-aware placeholder + Stop)
  - assistant chat (assistant selector grouped Active/Finished/Failed; per-assistant log)
  - dashboard (per-flow usage/cost/toolcalls by agent-type/model/function; metric cards)
  - **terminal** (read-only xterm.js, WebGL, 10k scrollback, search + task/subtask filter)
  - tasks (task/subtask cards with status icons, search, autoscroll)
  - agents / searches / vector store (log cards, search + task filter)
  - files (3 sources: uploads / resources / container snapshots; upload, attach, pull, promote, download, copy path, delete)
  - screenshots (gallery)
- flow report (standalone markdown view; `?download=true` triggers client-side PDF)
- templates list + template detail (TipTap markdown editor, 11 pentest presets, rich/raw toggle)
- knowledges list + knowledge detail (semantic search with 400ms debounce, TipTap editor, docType answer/code/guide)
- resources (full file manager: recursive tree, folders-first, bulk actions, drag-drop move, view-options persisted)
- settings account / providers list / provider detail / prompts list / prompt detail (TipTap, Diff vs default) / api-tokens

### 1.3 How live data reaches the screen
**GraphQL WebSocket subscriptions** (Apollo `GraphQLWsLink` + `graphql-ws`), **zero
polling**. The schema exposes ~25 delta-only subscriptions (flowCreated/Updated/
Deleted, taskCreated/Updated, terminalLogAdded, messageLogAdded/Updated,
agentLogAdded, screenshotAdded, …); a single flow-detail page mounts ~16 at once.
Two custom Apollo links auto-merge each subscription payload into the matching
cache row (no manual wiring). Socket is lazy, infinite retry with exp-jitter
backoff (cap 30s); on reconnect it refetches active queries.

### 1.4 Visual style
Dark **and** light themes (toggle stored in localStorage). "Agent-console /
dashboard" aesthetic: sidebar nav, chat split-view with resizable panels, embedded
live terminal (xterm, WebGL), Recharts panels. Accent is an **indigo/blue, hue 245**.
Theme tokens (from `frontend/src/styles/index.css`, `oklch`):
- light: `--background oklch(1 0 0)`, `--primary oklch(0.25 0.14 245)` (fill, white fg), `--accent oklch(0.9 0.03 245)`
- dark: `--background oklch(0.15 0.02 245)`, `--primary oklch(0.5 0.16 245)`, `--accent oklch(0.24 0.09 245)`
Typeface is system; visual baselines are pinned to the `mcr.microsoft.com/playwright` container for font stability.

### 1.5 Screenshots
The repo ships **20 pre-existing Playwright visual baselines** (light+dark:
dashboard, flows list, templates, knowledges, resources, settings-providers/
prompts/api-tokens) — real renders of the mock tier. Downscaled views copied into
this repo:
- `docs/gui-reference/pentagi-dashboard-light.jpg` · `pentagi-dashboard-dark.jpg`
- `docs/gui-reference/pentagi-flows-light.jpg` · `pentagi-flows-dark.jpg`
(originals: `~/Downloads/references/pentagi/frontend/e2e/specs/visual/*-snapshots/*.png`)

**Fresh-run attempt:** blocked in this sandbox — the frontend install failed with
Node v24 `ERR_VM_DYNAMIC_IMPORT_CALLBACK_MISSING` (corepack/pnpm 11 incompatibility
on Node 24); the mock tier (`pnpm build` + `vite preview` :8100 + Playwright route
interception from cassettes) is otherwise the standalone path (no Postgres/Go/LLM),
but the production tsc+terser build is also an OOM risk at this sandbox's ~1.6 GiB
free RAM. The shipped baselines are the project's own official renders of that
exact tier, so they stand as the screenshot evidence.

---

## 2. cai — terminal TUI + REPL, no web GUI (MIT agents / research core)

### 2.1 Framework
Two mutually-exclusive terminal frontends (`CAI_TUI_MODE`):
1. **Textual TUI** (`textual>=0.86`): a real `App` class (`CAITerminal`) with its
   own ~1523-line CSS, custom themes, widgets (`TabbedContent`, `ListView`,
   `Select`, `RichLog`, `Static`, `Footer`), MVC split.
2. **Headless REPL**: `prompt_toolkit>=3.0.39` input line + **Rich** for all
   rendering (`Live`, `Panel`, `Table`, `Markdown`, `Status`) + `questionary`.

### 2.2 Literal screens
- TUI `Terminal` tab (grid of N terminal widgets, each: status-dot header + agent/model/container selects, RichLog output, InfoStatusBar, streaming ActualActionBar)
- TUI `Graph` tab (CTRCanvas: draggable/zoomable node graph)
- TUI `Help` tab (two-column quick-start)
- TUI Sidebar (Ctrl+S: Agents / Teams / Queue / Stats / Keys)
- TUI overlay panels (AgentSelectorPanel + AgentCreatorPanel) + command palette
- REPL banner screen (ASCII "CAI" logo in green + session panel + /command table)
- REPL input line (green `CAI> ` prompt, completion menu, bottom status toolbar)
- REPL compact multi-row **Live task checklist** (agent pill, tool label, timer, animated RUNNING/THINKING dot chase, COMPLETED/ERROR pills, handoff sublines)
- REPL `/help` panels, `/sessions` selector, Ctrl+O output popup, exception-recovery screen

### 2.3 Live mechanism
TUI: Textual reactive properties with watchers + `set_interval(0.5s)` status-poll
+ `set_interval(1.0s)` layout indicator; agent/tool output injected into RichLog
widgets via a Rich `Console` subclass that redirects `print()`. REPL: `Rich Live`
blocks — the checklist runs at **8Hz during a turn / 2Hz idle** (`transient=True`,
`auto_refresh=True`), subscribed to an OUTPUT event bus (TurnStart/TaskStart/
TaskUpdate/TaskComplete/AgentHandoff); the block is erased at turn end so only the
final markdown panel stays in scrollback. Bottom toolbar refreshes via a background
daemon thread every 5s.

### 2.4 Visual style
Dark, green-on-black terminal. ASCII art, Rich panels, status dots, animated dot
chase for running tasks. No color theming beyond terminal defaults; green accent.

### 2.5 Screenshots
None captured (terminal-only; not in scope of a GUI screenshot pass).

---

## 3. hexstrike-ai (MIT) — no GUI
Whole repo is 2 Python files (`hexstrike_mcp.py` MCP server, `hexstrike_server.py`)
+ a Flask **JSON REST API** (every route returns `jsonify()` — no templates, no
static). `assets/` is PNG images only (logos, usage screenshots). `REACT`/`VUE`
appear only as a `TechnologyStack` enum used to **fingerprint target web apps**
(`__REACT_DEVTOOLS`/`__VUE__` markers), not its own UI. **CLI/MCP + JSON API only.**

## 4. PentestGPT (MIT) — no GUI
No streamlit/gradio/flask/fastapi in any tool source. The only web-ish Python is
`tests/support/local_target.py` — a vulnerable HTTP **target** for tests.
`docs/redesign/pentestgpt-redesign-decisions.html` is a **static design doc**
(self-contained `<style>`, no JS), superseded. Entrypoint is `argparse` CLI +
interactive loop. **CLI only.**

## 5. claude-bug-bounty (MIT) — no GUI in the tool
- `demo/app.py` = an **intentionally-vulnerable target** web app (shuvonsec.me
  lookalike, 6 planted bugs: XSS/open-redirect/SSRF/.env/admin/debug) for the A→Z
  tutorial — *not* the tool's UI.
- `site/index.html` = the **bughunter.fun marketing landing page**.
- The tool itself (`agent.py`/`brain.py`/`engine.py`/`commands/`) is a CLI / Claude
  Code plugin (`bughunter` command via argparse). **CLI/agent only.**

---

## 6. What transfers to ReachAgent (patterns, not code)

| Pattern | Source | Transferable? |
|---|---|---|
| Split-pane flow detail: left chat/timeline, right terminal/tasks | pentagi | Yes — ReachAgent timeline + audit pane |
| Findings as severity-flagged dashboard cards + drill-down | pentagi dashboard | Yes — ReachAgent `Finding` nodes |
| Embedded live terminal pane (xterm) | pentagi | Optional — ReachAgent's audit log is the analog |
| GraphQL **WebSocket subscriptions**, zero polling | pentagi | **No** — overkill for one append-only event stream; poll/SSE is honest |
| Live task checklist with animated status dots (8Hz) | cai REPL | Yes — the phase-timeline "stream" feel |
| Dark-first dashboard + indigo accent (hue 245, oklch tokens) | pentagi | Yes — visual direction |
| React 19 + Vite + shadcn/TanStack/Apollo stack | pentagi | **No** — a node build + ~30 deps for data ReachAgent already renders in vanilla |
| Terminal-only, green-on-black | cai | No — ReachAgent wants a dashboard, not a TUI |
