# ReachAgent GUI plan — one concrete direction

**Status:** Stages 1-5 built. Provider settings + per-tool activity added. Built alongside `docs/gui-reference-audit.md` (2026-08-24),
which read the five reference projects' UIs. This plan is the single chosen
direction; it does not rebuild what already works.

**Decision in one line:** keep **FastAPI + one no-build vanilla HTML/JS page**
(the current `gui/app.py` + `gui/static/index.html`), add four screens to it, and
keep the **1-second poll** for live data. Do **not** adopt pentagi's
React+Vite+Apollo+WebSocket stack.

## 1. Framework choice + why

| Candidate | Verdict | Why |
|---|---|---|
| React 19 + Vite + shadcn/Radix + Apollo WS (pentagi) | ❌ | ReachAgent's data is tables + a tree + a timeline + a report — nothing that needs a component framework, a node build, a WS layer, or ~30 deps. It would add a build pipeline and OOM-prone toolchain (seen in the screenshot attempt) for zero data-volume benefit. |
| Textual TUI / Rich REPL (cai) | ❌ | The user wants a web GUI, not a terminal. |
| **FastAPI + vanilla HTML/CSS/JS (current)** | ✅ | Already exists, already works, already streams the phase timeline. Tables (`<table>`), a collapsible tree (`<details>`/JS), an inline-SVG chain view, and a monospace audit pane are all native. Ladder: reuse what's here before adding anything. |

No new runtime dependency. The only possible additions are CSS-only. This is the
ponytail answer: the reference that would tempt a rebuild (pentagi) is the one
whose stack is *least* justified for ReachAgent's data.

## 2. Screens — mapped to ReachAgent's REAL data

Every screen below renders an existing object; none invents data.

| # | Screen | Data source (all real, existing) |
|---|---|---|
| 1 | **Scan launch** (exists) | `POST /api/scan` {target, in_scope, out_of_scope, identities_path, max_attempts, use_llm} |
| 2 | **Phase timeline** (exists) | orchestrator `ScanEvent(phase, kind, message, details)` — recon/endpoints/payloads/report badges |
| 3 | **Surface map** (new) | `graph.hosts()` → `graph.services_of(host)` (`runs_service`) · `graph.endpoints()` attached by `graph.resolves_to_edges()` · `graph.parameters_of(endpoint)` (`accepts`) showing `inferred_sink_type`, `access_restricted`, `technology`. Collapsible tree: Host → Service/Endpoint → Parameter |
| 4 | **Findings dashboard** (extends the current table) | `graph.findings()` → severity-colored cards/table: `vuln_class`, `severity`, `oracle_used`, `evidence_ref`, `status`, `metadata`. Click a finding → chain view |
| 5 | **Chain view** (new) | `graph.chain_paths(start)` + `graph.enables_edges()` + `graph.derived_credential_edges()` — a Finding→Finding (`enables`) and Finding→Session/Identity (`derived_credential`) path rendered as inline SVG linked nodes |
| 6 | **Live audit log** (new tab) | `AuditLog.entries` — `(timestamp, identity, method, target, outcome)` tail, monospace, colored by outcome (`fired:` green / `refused_` red / `error:` amber / `ingested` cyan). Add a `/api/scan/{id}/audit` slice endpoint |
| 7 | **Report viewer** (exists) | `render_findings_markdown(graph)` (deterministic table) + `generate_llm_report(graph)` (narrative) when use_llm |

Layout (borrowing pentagi's split-pane feel, in vanilla): a slim left sidebar
(scan list / nav to Surface · Findings · Audit · Report) and a main column with the
phase timeline on top, then tabbed panes for Surface / Findings / Chain / Audit /
Report.

## 3. Live-data mechanism

**Keep the 1-second poll** of `/api/scan/{id}` (already implemented: the scan runs
in a `ThreadPoolExecutor` thread and appends to an in-memory events list + the
shared graph; the poll returns `events`/`findings`/`status`). Rationale, against
the references:

- pentagi's **WebSocket subscriptions** exist because it mounts ~16 concurrent
  subscriptions on a real backend. ReachAgent has **one** append-only stream from a
  single background thread — a poll is cheaper, has zero transport state, works
  through the same HTTP GET, and is already built.
- The reference's **8Hz animated checklist** (cai) is a *rendering* trick: the JS
  already animates the running-task dots client-side between polls; no faster
  transport needed.
- **Upgrade path (documented, not built):** SSE (`text/event-stream`) on
  `/api/scan/{id}/stream` if live latency ever matters. It's ~15 lines (an
  `asyncio.Queue` + an `EventSource`), and the orchestrator's event list makes it
  trivial to add later. Not needed now — the poll is imperceptibly stale at 1s for
  a scan that runs minutes.

## 4. Visual direction

- **Dark-first dashboard**, light theme via `prefers-color-scheme` + a toggle (like
  pentagi's `ThemeProvider` + localStorage, in ~20 lines of vanilla).
- Accent: adopt pentagi's **indigo, hue 245** family (oklch dark `--primary
  oklch(0.5 0.16 245)`) — or keep the current `#4ea1ff` blue; either reads as the
  "agent console" palette. Pick one token set and use it for buttons, active tabs,
  phase badges.
- Panels: flat `--panel`/`--line` surfaces (current GUI already has them), system-ui
  for chrome, **monospace** for the audit log and finding `evidence_ref`/`oracle_used`
  (the "terminal-flavored" panes from cai/pentagi, as data panes — not the whole app).
- Findings: severity as color (high=red, medium=amber, low=green) cards; the phase
  timeline keeps its badge per kind (info/step/finding/not-applicable/error).

## 5. Build order (each step gated: `ruff` + `mypy` + the orchestrator/smoke tests)

1. **Audit + plan** (this pair of docs) — done.
2. **Backend slices:** add `/api/scan/{id}/surface`, `/api/scan/{id}/audit`,
   `/api/scan/{id}/chains` JSON endpoints (read-only over the stored graph +
   audit). ~40 lines.
3. **Frontend screens:** surface tree, chain view (inline SVG), audit pane; wire
   into the existing tab strip. Pure HTML/CSS/JS edits to `index.html`.
4. **Findings dashboard polish:** severity cards + click-to-chain drill-down.
5. **Visual pass:** dark/light tokens + accent, then **review** the diff.

No new dependencies, no build step, no transport change. The GUI stays one
no-build page that FastAPI serves.

## 6. Explicitly not doing

- React/Vite/Apollo/WebSocket (pentagi) — rejected above.
- TUI/REPL (cai) — user wants a web GUI.
- Adding graph-viz libraries (d3/cytoscape) — the surface tree and chain view are
  small enough for `<details>` + inline SVG; add a lib only if a real force-layout
  is demanded, which ReachAgent's data does not need.
- Polling faster than 1s or SSE before a measured need.
