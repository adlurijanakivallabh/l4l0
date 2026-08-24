# ReachAgent GUI Plan — one concrete direction

**Date:** 2026-08-24 · Source: `docs/gui-reference-audit.md` (pentagi = only real web
GUI; cai = terminal live-log pattern). **No implementation in this stage — plan only.**
Status: the GUI already exists as a working FastAPI + single-page app (plan v2); this
doc is the *target* shape for the next build, grounded in ReachAgent's real data.

---

## 1. Framework choice — keep FastAPI + one static HTML page (no build step). Do NOT adopt React.

**Why not React/shadcn (the pentagi stack):** pentagi's React SPA earns its toolchain
with ~27 CRUD screens, virtualized tables, TipTap editors, a file manager, and per-
tool-call terminal streaming over GraphQL WebSocket. ReachAgent has none of that:
its entire data surface is hosts/services/endpoints/parameters (dozens), confirmed
findings + attack chains (a handful), an audit log (hundreds of rows), and an
orchestrator event stream. A React+Vite+TS+shadcn build for that surface is ~10× the
toolchain for ~1.5× the UI quality — and the reference project's own production build
**OOMs at 1.2Gi free RAM** (measured this session), so a frontend build would be a
regular failure mode on this box.

**Why FastAPI + vanilla JS + CSS is right here:**
- It is already the working GUI (plan v2) — zero new dependencies, zero node/pnpm, no
  build step, no RAM ceiling. The ladder says reuse what's there.
- The screens are **a tree, a table, a timeline, and a report** — all vanilla-DOM.
- The one place a heavier lib could earn its keep — the graph/chain view — does not
  need it: ReachAgent's graph is small enough for a hand-rolled collapsible tree +
  inline SVG chain path. No d3, no vis.js.
- Upgrade path if the surface ever grows: add SSE streaming + a chart lib, still no
  React. A React rewrite buys nothing for this data.

---

## 2. Screens — each mapped to REAL ReachAgent data (no invented data)

Data source column = the actual Python call / object the screen renders.

| Screen | What it shows | Real data source |
|---|---|---|
| **1. Scan console** (exists) | target URL, in-scope/out-of-scope, identities file, max attempts, "Use LLM" toggle, Start | `scan_all_classes(base_url, in_scope, out_of_scope, max_attempts, identities, use_llm)` |
| **2. Phase timeline** (exists) | live RECON → ENDPOINTS → PAYLOADS → REPORT stream with kind badges (info/step/finding/not-applicable/error) | orchestrator `ScanEvent` list (`scan_all_classes` `events=`), each `{phase, kind, message, details}` |
| **3. Surface map** (new) | collapsible tree: `Host` → (`Service` via `runs_service`, `Endpoint` via `resolves_to`) → `Parameter` via `accepts`; show `technology`/`detected_version`/`access_restricted` on hosts/endpoints and `inferred_sink_type` on params; severity of `can_call` status | `graph.hosts()`, `graph.services_of(host)`, `graph.endpoints()`, `graph.parameters_of(ep)`, `graph.can_call_edges()`, `graph.owner_of(obj)` |
| **4. Findings dashboard** (exists → extend) | finding cards/table: `vuln_class`, `severity` (color-coded), `oracle_used`, `evidence_ref`, `status` | `graph.findings()` → `Finding.vuln_class/severity/oracle_used/evidence_ref/status/metadata` |
| **5. Attack chain view** (new) | for each finding, the multi-hop path: `Finding →enables→ Finding →derived_credential→ Session/Identity`, drawn as a linked horizontal chain; shows the `chain_precondition` metadata | `graph.chain_paths(finding_id)`, `graph.enables_edges()`, `graph.derived_credential_edges()`, `Finding.metadata["chain_precondition"]` |
| **6. Live audit log** (exists → extend) | append-only tail: `timestamp identity method target outcome`, colored by outcome (`fired:2xx` green, `refused_*` red, `error:*` orange, `ingested` cyan) | `audit.entries` → `AuditEntry(timestamp, identity, method, target, outcome)` |
| **7. Report viewer** (exists) | LLM narrative over confirmed findings + deterministic findings table | `generate_llm_report(graph)` / `render_findings_markdown(graph)` |

Every screen reads only the graph, the audit log, or the orchestrator events — the same
objects `scan_target`/`scan_all_classes` already populate. Nothing new is invented.

---

## 3. Live-data mechanism — keep the 1s HTTP poll. SSE is the documented upgrade, not the default.

- **Now:** the orchestrator runs in a background thread and appends `ScanEvent`s to an
  in-memory list; the frontend polls `GET /api/scan/{id}` every 1s and re-renders the
  timeline/findings. One GET, stateless, no streaming endpoint, no event parsing, works
  behind any proxy. The scan runs for minutes, so 1s granularity is imperceptible.
- **Why not GraphQL-WS / SSE / WebSocket now:** pentagi uses WebSocket subscriptions
  because it streams *per-tool-call terminal output* and re-syncs 16 subscriptions.
  ReachAgent's equivalent granularity is the event list + audit tail — both append-only
  and small. Push buys sub-second latency nobody needs and adds a streaming endpoint +
  client event handling for no user-visible gain.
- **Upgrade path (write it down, don't build it):** if live latency ever matters, expose
  `GET /api/scan/{id}/stream` as `text/event-stream` over the same in-memory event list
  (an SSE generator is ~15 lines in FastAPI); the frontend swaps `setInterval` for
  `EventSource` with no screen changes. The event payload shape stays identical.

---

## 4. Visual direction — dark-first security dashboard, not a clone of either reference

Take pentagi's **dark dashboard + indigo accent** (hue ~245) for the structure, and
cai's **monospace live-stream + status semantics** for the audit log. Plainly:

- **Theme:** dark by default (near-black background, dark surface panels), light optional.
  Keep the current tokens (`#0f1115` bg, `#171a21` panel, `#1e222b` inset, `#2a2f3a`
  border, `#d7dce5` text, `#8b93a3` muted).
- **Accent:** keep the current `#4ea1ff` blue — it already sits in pentagi's hue-245
  indigo family; no reason to move.
- **Severity colors** (the only truly semantic color): critical `#f85149` red, high
  `#d29922` amber, medium `#d29922`/gold, low `#4ea1ff` blue, info muted. Findings cards
  get a left-border in the severity color.
- **Live audit log:** terminal-style — monospace, dark inset panel, `fired:2xx` green
  `#3fb950`, `refused_*` red, `error:*` orange `#d29922`, `ingested` cyan. This is the
  cai live-log pattern, but as a web panel, not a terminal.
- **Layout:** single-page, three-zone: top = scan console + phase banner; left column =
  surface-map tree + chain view; right = findings dashboard; bottom = live audit log.
  All zones are independent scroll regions so a long scan doesn't push findings off.
- **Deliberately not copied:** pentagi's sidebar-of-27-screens, virtualized tables,
  TipTap editors, file manager, PDF export, login/OAuth — ReachAgent has no multi-user
  auth, no knowledge base, no file management, no report PDFs. Shipping those would be
  speculative UI.

---

## 5. Build order (next implementation stage, gated per step)

1. **Surface map tree** — `/api/surface` serializes hosts/services/endpoints/params;
   frontend renders the collapsible tree. (new screen 3)
2. **Attack chain view** — `/api/scan/{id}/chains` serializes `chain_paths` per finding;
   frontend renders the linked path. (new screen 5)
3. **Audit log tail** — `/api/scan/{id}/audit` returns the `AuditLog` tail; frontend
   renders the colored terminal-style log. (extends screen 6)
4. **Findings dashboard cards** — severity-colored cards replacing the bare table.
   (extends screen 4)
5. **SSE upgrade** (only if step 1–4 make the poll feel laggy) — `text/event-stream`
   endpoint + `EventSource` swap. (documented, not default)
6. Re-run `uv run ruff check --fix . && uv run mypy src && uv run pytest -q` + the
   orchestrator suite after every step.

Gates held: GUI stays a read-only observer of the graph/audit/events — no firing, no
oracle, no finding write from the browser. The six oracle families and the
`run_oracle → is_violation → write_finding` invariant are untouched.

→ Reference screenshots: `docs/gui-reference-screens/`.
