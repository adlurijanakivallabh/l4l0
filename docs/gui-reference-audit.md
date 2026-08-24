# GUI Reference Audit — pentagi / cai / hexstrike-ai / PentestGPT / claude-bug-bounty

**Date:** 2026-08-24 · **Scope:** read the actual frontend source of every reference
project that has a real GUI; for the rest, prove they are CLI-only. Feeds
`docs/gui-plan.md`. No implementation in this stage.

## Licenses (stated before reading)

| Project | License |
|---|---|
| pentagi | MIT (`Copyright (c) 2025 PentAGI Development Team`) |
| cai | **Dual** — `src/cai/agents` MIT (from openai-agents-python); `src/cai` core is Alias Robotics **research-use-only** (commercial prohibited). Read for visual-reference ideas only. |
| hexstrike-ai | MIT (`Copyright (c) 2026 Muhammad Osama (0x4m4)`) |
| PentestGPT | MIT (`Copyright (c) 2023 Grey_D`) |
| claude-bug-bounty | MIT (`Copyright (c) 2026 Claude Bug Bounty Hunter Contributors`) |

## Summary — who has a GUI at all

| Project | GUI? | Kind |
|---|---|---|
| **pentagi** | ✅ | **Real web GUI** (React SPA) — the only one |
| cai | ⚠️ | Terminal UI only (Textual TUI + Rich/prompt_toolkit REPL) — no web GUI |
| hexstrike-ai | ❌ | CLI / MCP-server + JSON REST API only (flask `jsonify()` routes, no HTML/JS/CSS) |
| PentestGPT | ❌ | CLI-only (`pentestgpt_legacy/main.py` argparse + interactive loop; `docs/redesign/*.html` is a static design doc, not an app) |
| claude-bug-bounty | ❌ | CLI / agent toolkit only. `demo/app.py` is an **intentionally-vulnerable target** (shuvonsec.me lookalike, 6 planted bugs) for the tutorial, and `site/` is a marketing landing page — neither is the tool's UI |

---

## 1. pentagi — the real web GUI (the primary reference)

### Framework + UI library
**React 19.2 + TypeScript 6 + Vite 8** (SWC, rollup code-splitting) + **pnpm** +
`react-router-dom` 7 (data router, lazy pages + Suspense). **Tailwind CSS 4** +
**shadcn/ui-style primitives on Radix UI** (20+ Radix primitives), `class-variance-authority`
+ `clsx` + `tailwind-merge`, `lucide-react` icons. Data: **Apollo Client 4.2** (GraphQL
over `HttpLink` + `GraphQLWsLink` WebSocket) + axios 1.18 (REST auth/resources). Tables:
**TanStack Table 8 + TanStack Virtual 3**. Terminal: **@xterm/xterm 6** (WebGL, read-only).
Rich text: **TipTap 3**. Charts: **Recharts 3**. PDF: **@react-pdf/renderer 4**.
Markdown: react-markdown + rehype/remark. Forms: react-hook-form + zod.

### Literal screens/views (from the actual page tree)
- `login` — 2-col split: email/password + OAuth form left, animated logo on gradient right
- `oauth result` — popup window that posts back to opener
- `dashboard` — Tabs **Analytics | Overview**; Analytics = Week/Month/Quarter picker +
  4 Recharts views (**Flows Activity**, **Tool Calls**, **Token Usage**, **Cost**) +
  Flow Execution Details drill-down; Overview = 4 **MetricCards** + Usage-by-Provider/
  Model/AgentType tables + Tool-Calls-by-Function table
- `flows list` — virtualized DataTable (ID/title/**status-badge**/provider/terminals/created/
  updated; global filter, sort, pagination, column-hiding, hover actions, context menu)
- `new flow` — centered card: Automation/Assistant tabs, textarea + provider dropdown
- `flow detail` — **resizable 50/50 split**: LEFT panel Tabs **Automation | Assistant |
  Dashboard**, RIGHT panel Tabs **Terminal | Tasks | Agents | Searches | Vector Store |
  Files | Screenshots**; header with status icon, breadcrumb, **Report** dropdown
- `flow detail — automation chat` — message cards (thinking toggle, markdown, result as
  markdown OR inline mini-xterm), task/subtask filter, composer + Stop
- `flow detail — assistant chat` — assistant selector, per-assistant message log
- `flow detail — dashboard` — per-flow usage/cost/tool-calls stats
- `flow detail — terminal` — read-only xterm.js, WebGL, 10k scrollback, search
- `flow detail — tasks` — task/subtask cards with status icons, autoscroll
- `flow detail — agents` / `searches` / `vector store` — log cards with filters
- `flow detail — files` — 3 sources (uploads/resources/container snapshots), upload/
  download/copy/delete
- `flow detail — screenshots` — screenshot gallery
- `flow report` — standalone markdown report web view + client-side PDF generation
- `templates list` + `template detail` (TipTap markdown editor, 11 pentest presets)
- `knowledges list` + `knowledge detail` (semantic search, TipTap editor)
- `resources` — full file manager (recursive tree, bulk actions, drag-drop, view-options)
- `settings account / providers / provider detail / prompts / prompt detail / api-tokens`

### How live data reaches the screen during a running flow
**GraphQL WebSocket SUBSCRIPTIONS (graphql-ws), not polling — zero polling intervals in
the app.** `lib/apollo.ts` splits `isSubscriptionOperation → wsLink, else httpLink`; the
socket is lazy, infinite-retry with exponential+jitter backoff (cap 30s), re-fetches
active queries on reconnect. ~25 **delta-only** subscription ops (flowCreated/Updated,
taskCreated/Updated, `terminalLogAdded`, `messageLogAdded/Updated`, agentLogAdded,
searchLogAdded, vectorStoreLogAdded, screenshotAdded, …). A single flow-detail page mounts
**~16 subscriptions simultaneously** via `flow-provider`, and a custom
`createSubscriptionCacheLink` auto-merges each subscription payload into the matching
Apollo cache entry — the UI updates with no manual wiring.

### Visual style
**Dark + light themes** (toggle stored in localStorage). Dashboard/agent-console aesthetic:
sidebar nav, resizable split-panel chat, embedded live terminal (xterm WebGL), Recharts.
**Accent is indigo/blue, hue 245** (not a red/terminal theme). Exact tokens from
`src/styles/index.css`:
- light: `--background oklch(1 0 0)`, `--primary oklch(0.25 0.14 245)` (white fg), `--accent oklch(0.9 0.03 245)`
- dark: `--background oklch(0.15 0.02 245)`, `--primary oklch(0.5 0.16 245)`, `--accent oklch(0.24 0.09 245)`

### Real screenshots (captured)
pentagi ships its own Playwright **visual baseline PNGs** (light + dark, 1280px). 11 of
them are copied into this repo for reference:
`docs/gui-reference-screens/` → `dashboard-light/dark`, `flows-light/dark`, `flows-5-light`,
`resources-light/dark`, `settings-prompts-light`, `settings-providers-light`,
`knowledges-light`, `templates-light`. (A fresh local capture was not run: the Vite+terser
build OOMs in this sandbox's 1.2Gi free RAM; the baselines are the same pixels the project
pins for its own e2e.)

---

## 2. cai — terminal UI only (secondary visual reference)

### Framework + UI
Two mutually-exclusive frontends (`CAI_TUI_MODE`), both terminal-only, **no web GUI**:
1. **Textual TUI** (`src/cai/tui/`, textual ≥0.86) — a real `CAITerminal(App)` with its
   own CSS, custom themes, Textual widgets (TabbedContent, ListView, RichLog, Static),
   MVC split (model/state + controller/input + view/layout). The `tui` extra pulls
   networkx/numpy/scipy for a graph canvas.
2. **Headless REPL** — prompt_toolkit input line + **Rich** rendering (Live, Panel,
   Table, Markdown, Status) + questionary wizards.

### Screens
- TUI: **Terminal** tab (grid of `UniversalTerminal` widgets — status-dot header, agent/
  model selects, RichLog output, status/action bars); **Graph** tab (CTRCanvas draggable/
  zoomable node graph); **Help** tab; docked **Sidebar** (Agents/Teams/Queue/Stats/Keys);
  overlay AgentSelector/AgentCreator panels; command palette (Ctrl+P).
- REPL: session-banner screen (ASCII CAI logo, green), `CAI> ` prompt with ghost + status
  toolbar, **multi-row Rich Live task checklist** (agent pill, tool label, timer, animated
  RUNNING/THINKING dot-chase, COMPLETED/ERROR pills, handoff lines), `/help` panels,
  session selector, Ctrl+O output expander, exception-recovery screen.

### Live mechanism
**Event-driven, no polling for agent/tool output.** Textual reactive props with watchers;
a 0.5s interval polls only the status bar; streaming output is injected into per-terminal
RichLog widgets. REPL: Rich `Live` blocks at **8Hz while running / 2Hz idle**, subscribed
to a `cai.output` event bus (TurnStart/TaskStart/TaskUpdate/…/AgentHandoff), transient
(erased on turn end). Bottom toolbar refreshes via a background daemon thread every 5s.

### Visual style
Dark, terminal-native: green accent (green `CAI>` prompt, ASCII logo), Rich panels,
monospace. **This is the "live scan log" aesthetic** — contrast with pentagi's dashboard.

---

## 3. What these tell us for ReachAgent

- **pentagi is the only modern web-dashboard reference**: sidebar + dark dashboard +
  resizable chat/terminal split + live push. Its stack (React + shadcn + GraphQL-WS) is
  justified by ~27 CRUD screens and per-tool-call terminal streaming.
- **cai proves a live "stream + status checklist" UI works with no web stack at all** —
  the exact live-scan-log + per-task-status pattern ReachAgent needs, in a terminal.
- ReachAgent's real data is **small and live-for-minutes**: hosts/services/endpoints/
  params (dozens), findings + chains (few), an audit log (hundreds of rows), and an
  orchestrator event stream. That is a **dashboard + live log**, not a 27-screen console
  and not per-tool-call terminal push. This drives the plan in `docs/gui-plan.md`.

→ See `docs/gui-plan.md` for the one concrete plan.
