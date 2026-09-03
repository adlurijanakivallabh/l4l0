# ReachAgent GUI Reference Notes

Durable reference for building/refining ReachAgent's FastAPI GUI (`uv run reachagent-gui`).
24 reference screenshots grouped into three sources:

- **PentAGI** (external product, visual inspiration only) — files under
  `docs/gui-reference/` and three light `docs/gui-reference-screens/settings-*`,
  `templates-light.png`. Brand/roles are PentAGI's, not ReachAgent's.
- **ReachAgent clone-of-PentAGI build** — `docs/gui-reference-screens/dashboard-*`,
  `flows-*`, `flows-5-light.png`, `resources-*`, `knowledges-light.png`.
  A near-faithful PentAGI clone still carrying the "PentAGI" name (rebrand debt).
- **ReachAgent v2 polished dark redesign** — `docs/gui-reference-screens/eval-*`.
  The intended production visual language.
- **ReachAgent monospace build** (functional predecessor) —
  `docs/gui-reference-screens/reachagent-gui-*`. Terminal aesthetic, real scan data.

---

## Pentagi inspiration screens (what to borrow)

PentAGI is a dark/light app-shell dashboard. The structural patterns worth carrying:

- **App shell**: fixed ~180px left sidebar (brand + line-icon nav + bottom-anchored
  Settings gear and user account chip) + main content area with a breadcrumb header.
- **Card-based analytics grid** (`pentagi-dashboard-dark.jpg` /
  `-light.jpg`): full-width hero bar chart → 2-up row → full-width area chart →
  accordion detail. Each card = bold title + muted caption + chart with dashed
  gridlines. Global `Week | Month | Quarter` segmented range toggle + `Analytics |
  Overview` segmented tabs.
- **Shared list shell** (`pentagi-flows-dark/light.jpg`, `templates-light.png`):
  header with `+ New X` primary button top-right, a filter/search input + filter-icon
  + column-settings-icon toolbar, a rounded-panel data table, and a standard pager
  footer (`Showing 1–N of N`, `Rows per page [All ▾]`, `Page 1 of 1`,
  first/prev/next/last chevrons). This one shell repeats across Flows / Templates /
  Resources / Knowledges — standardize it as one component.
- **Status chips**: blue `Running` pill with a spinner dot; green success check +
  environment tag. In light mode chips darken their fill (don't keep dark-mode
  brightness) to stay legible.
- **Settings sub-shell** (`settings-prompts-light.png`, `settings-providers-light.png`):
  a separate narrow settings sidebar (Account / Providers / Prompts / API Tokens +
  `← Back to App`), per-section count badges, `Default`/`N/A` pill states for
  configurable items, and a centered empty-state (icon + heading + one-line guidance
  + CTA, with a redundant primary CTA in the toolbar).
- **Light/dark parity**: it's a true token-swapped pair. Note the one non-token
  difference: bar fills switch from a gradient (dark) to solid distinct blues (light)
  so categories stay distinguishable.

---

## ReachAgent's own GUI screens (current state)

Three parallel builds exist in the references:

1. **Clone build** (`dashboard-*`, `flows-*`, `resources-*`, `knowledges-light.png`,
   `flows-5-light.png`): a faithful copy of PentAGI including its charts, tables, and
   the literal "PentAGI" wordmark. Ships both themes with consistent tokens. Known
   issues: **not rebranded** (still "PentAGI"); the single-flow detail
   (`flows-5-light.png`) has a **magenta terminal block** — an unstyled/broken
   xterm.js canvas, a bug to fix, not a design choice.

2. **v2 polished dark redesign** (`eval-*`): the intended production look — gradient
   ReachAgent brand, numbered phase pills, floating config card, KPI dashboard,
   persistent active-target/status footer, and an explicit safety-guarantee panel
   encoding the project's non-negotiables.

3. **Monospace build** (`reachagent-gui-*`): older terminal-aesthetic single page
   with real scan data. Source of the two most ReachAgent-specific ideas: the
   **attack-chain pill sequence** and the **color-coded phase-timeline status
   taxonomy** (FINDING / NOT-APPLICABLE / INFO).

Direction: adopt the v2 dark shell; port the monospace build's chain visualization,
timeline taxonomy, and export row into it; retire the PentAGI clone (or rebrand it).

---

## Per-screen reference

### PentAGI — external inspiration

**`docs/gui-reference/pentagi-dashboard-dark.jpg`** — PentAGI Dashboard (Analytics), dark.
- *Layout*: sidebar + main; `Analytics | Overview` tabs left, `Week | Month | Quarter`
  toggle right; card stack (hero "Flows Activity Over Time" bar → 2-up "Tool Calls" bar
  + "Token Usage" stacked area → full-width "Cost Over Time" area → "Flow Execution
  Details" accordion).
- *Key elements*: sidebar Dashboard/Flows/Templates/Resources/Knowledges + Settings +
  user card; per-card title+caption; 3-bar/day-group gradient bars; $-formatted area
  charts; accordion row (chevron + "E2E Alpha" + "1 task · 1 subtask · 1 assistant" +
  "2m 0s" + "7").
- *Theme*: near-black navy, elevated cards, white text, saturated-blue accents,
  two-tone gradient fills.
- *Cue*: card-grid analytics layout + global range toggle + honest-status caption
  microcopy ("may stay near zero when using local engines"). Map: flows→scans,
  tool calls→oracle runs, tokens/cost→LLM planner spend.

**`docs/gui-reference/pentagi-dashboard-light.jpg`** — same dashboard, light.
- Identical layout; bars become solid distinct blues (navy/mid/bright), areas
  muted-slate over blue. White/light-gray surfaces, near-black titles.
- *Cue*: confirms token-swapped light/dark pair; replicate the gradient→solid bar
  switch in light mode.

**`docs/gui-reference/pentagi-flows-dark.jpg`** — PentAGI Flows list, dark.
- *Layout*: shell + header ("Flows" + `+ New Flow`), search/filter toolbar,
  data table, pager footer; sidebar gains "Recent Flows".
- *Key elements*: columns ID/Title/Status/Provider/Terminals/Created/Updated; rows
  5 E2E Alpha, 6 E2E Beta; blue `Running` chip + spinner; provider icon; green check +
  `debian:stable-slim`; timestamps; column-settings icon.
- *Theme*: dark navy, muted headers, white rows, blue/green accents.
- *Cue*: template for ReachAgent's scan-runs table (rename columns:
  Title→Target/Scan, Provider→LLM provider, Terminals→Environment). Running-chip +
  spinner = live-scan pattern.

**`docs/gui-reference/pentagi-flows-light.jpg`** — same list, light.
- Identical; `Running` chips darken to navy pills; light outlined toolbar buttons.
- *Cue*: light-mode chip darkening for contrast.

**`docs/gui-reference-screens/settings-prompts-light.png`** — PentAGI Settings › Prompts, light.
- *Layout*: two-pane settings shell (settings sidebar + main), two stacked tables
  (Agent Prompts, Tool Prompts), each with its own filter bar + pager.
- *Key elements*: settings nav Account/Providers/Prompts(active)/API Tokens +
  `← Back to App`; per-section count badges (15, 12); `Default`/`N/A` pill per
  configurable prompt; column-settings icon; `⋯` row-action menu on Tool Prompts.
- *Theme*: light, understated admin; pale-blue active nav, neutral pill chips.
- *Cue*: structure only for a settings/prompts admin area — count badges,
  per-table filter+columns toolbar, Default-vs-overridden pill states. Taxonomy is
  PentAGI's, not ReachAgent's Explorer/Coordinator/Validator roles.

**`docs/gui-reference-screens/settings-providers-light.png`** — PentAGI Settings › Providers, empty, light.
- *Layout*: settings shell; centered empty-state block.
- *Key elements*: toolbar `Create Provider ▾` split-button top-right; centered
  empty-state (grey gear glyph + "No providers configured" + one-line guidance +
  secondary `Add Provider` CTA).
- *Cue*: empty-state pattern (icon + heading + guidance + CTA with a redundant
  toolbar primary). Directly relevant to ReachAgent's LLM-provider config.

**`docs/gui-reference-screens/templates-light.png`** — PentAGI Templates list, light.
- *Layout*: standard app shell (full product nav) + table + pager.
- *Key elements*: `New Template` top-right; filter+columns toolbar; columns
  Title/Text with one "E2E Seed Template" / "Scan the target and report findings" row.
- *Theme*: light admin; confirms these light shots are PentAGI (brand +
  admin@pentagi.com).
- *Cue*: the seed template ("Scan the target and report findings") mirrors
  ReachAgent's Operator-objective concept — a saved-objective/template feature could
  map onto it.

### ReachAgent clone build

**`docs/gui-reference-screens/dashboard-dark.png`** — ReachAgent Dashboard (Analytics), dark.
- Its own faithful PentAGI dashboard clone: same tabs/toggle/card stack (hero bars,
  2-up, Cost area, Flow Execution accordion), rendered with more vertical breathing room.
- Sidebar still reads **"PentAGI"** (rebrand debt). Dark navy palette matches PentAGI.
- *Cue*: baseline to refine — rename to ReachAgent, add logo, remap metrics to
  security-scan concepts.

**`docs/gui-reference-screens/dashboard-light.png`** — same, light.
- Solid distinct blue bars on white; slate/steel area charts; white cards. Same
  "PentAGI" branding. Proves the theme-swap works for charts.

**`docs/gui-reference-screens/flows-dark.png`** — ReachAgent Flows list, dark.
- Same schema as PentAGI Flows (ID/Title/Status/Provider/Terminals/Created/Updated,
  blue Running chip, green check, pager, Recent Flows sidebar).
- *Cue*: maps to a scan-runs table; rename columns as above.

**`docs/gui-reference-screens/flows-light.png`** — same, light.
- Identical; chips darken, light outlined toolbar.

**`docs/gui-reference-screens/flows-5-light.png`** — ReachAgent single Flow detail (E2E Alpha), light. **Most important build screen.**
- *Layout*: three regions — sidebar nav; a **two-pane resizable workspace** with a
  center drag handle. LEFT pane = flow workspace with `Automation | Assistant |
  Dashboard` sub-tabs (Assistant active), a `New ▾` dropdown + `Search messages…`,
  an empty-state, and a bottom chat composer (`Select Provider ▾`, `Use Agents`
  toggle, send). RIGHT pane = tabbed inspector `Terminal | Tasks | Agents | Searches
  | Vector Store | Files` (Terminal active) with log search + terminal viewport.
- *Header*: running spinner + "E2E Alpha", `Report ▾`, `1/2` pager, favorite star,
  `⋯` overflow.
- *Theme*: light — **the full-magenta terminal viewport is a rendering bug**
  (unstyled xterm.js canvas), NOT intended UI.
- *Cue*: the per-scan detail workspace. Map inspector tabs to ReachAgent:
  Terminal=firer/request log, Tasks=scan phases, Agents=Explorer/Coordinator/
  Validator activity, Searches=recon runners, Vector Store=payload/corpora,
  Files=evidence exports. **Fix the magenta terminal (xterm.js theme/mount).**
  `Report ▾` + `1/2` pager + favorite star are reusable per-scan controls.

**`docs/gui-reference-screens/resources-dark.png`** — ReachAgent Resources (file manager), dark.
- *Layout*: header ("Resources" + `New folder` + `Upload files`), search toolbar,
  file table.
- *Key elements*: select-all + per-row checkboxes, expand chevron, Name / right-
  aligned Size + Modified; rows `reports` folder + `notes.txt` (1.2 KB, 3h ago).
- *Cue*: standard file-manager (multi-select + upload). For ReachAgent = artifact/
  evidence store (grounded evidence exports, payload files, reports).

**`docs/gui-reference-screens/resources-light.png`** — same, light.
- Identical; light outlined action buttons.

**`docs/gui-reference-screens/knowledges-light.png`** — ReachAgent Knowledges (KB), light.
- *Layout*: header ("Knowledges" + `+ New Knowledge`), filter toolbar, table, pager.
- *Key elements*: columns Type / Question / Flags; row = green-outlined `answer`
  chip + "other", "E2E Seed Question", gray `manual` flag chip.
- *Cue*: could back a findings-knowledge / oracle-rationale store. Reuses the exact
  shared list+pager+filter shell — **that shell is the core reusable component.**

### ReachAgent v2 polished dark redesign (target visual language)

**`docs/gui-reference-screens/eval-live-scan-tools.png`** — v2 "Run assessment" landing / new-assessment config.
- *Layout*: three-zone shell — fixed ~230px left sidebar (brand + nav), center-left
  hero column, right floating config card (~40%), top bar (breadcrumb + run-status).
- *Key elements*: sidebar = blue-gradient ReachAgent logo + "SECURITY WORKSPACE",
  nav Run assessment(active, left-accent + `R` hint)/Overview/Attack surface/Findings/
  Report/Audit trail; footer "ACTIVE TARGET" card (`http://localhost:5000` + status dot)
  + appearance toggle + `v2.0 · oracle-gated execution`. Top bar: breadcrumb + status
  dot + `01 · RECON` stage pill. Hero: eyebrow + "Map the surface. Prove the impact."
  (2nd line violet) + four numbered phase pills (01 Recon…04 Report). Config card
  "NEW ASSESSMENT / Configure a target" ("Scope is enforced before every request.")
  with fields Target URL, In-scope/Out-of-scope, Operator objective (textarea),
  Identities file / Max payload attempts (20), LLM provider dropdown; CTA
  `Start assessment →` (blue→violet gradient).
- *Theme*: dark (~#0d1017), off-white text, electric-blue + violet gradient accent,
  green reserved for confirmed metrics.
- *Cue*: **the reference visual language.** Reuse the numbered phase-pill run-progress
  motif and the "scope enforced before every request" trust framing.

**`docs/gui-reference-screens/eval-tools-panel-empty.png`** — v2 "Assessment overview" dashboard, idle/empty.
- *Layout*: same shell; stacked dashboard — KPI stat-card row → full-width "Tool
  activity" → two-column (Phase timeline | Agent decision + safety guarantees) →
  "PHASE 02 · MAPPING" peeking below.
- *Key elements*: five KPI cards (Hosts/Services/Endpoints/Parameters=blue,
  Confirmed findings=green, all 0, faint circular watermark); "Tool activity" with
  `real runner results` chip + "No tools dispatched yet."; "Phase timeline" with
  `1s poll` chip; "Agent decision" with `proposal` chip + inset "RECON PROFILE" card;
  **safety-guarantee block**: Scope guard • enforced / Read-only first • enforced /
  Oracle confirmation • required (values green with leading dot).
- *Theme*: dark; blue KPI numerals, green confirmed/guarantee states.
- *Cue*: canonical empty-state (KPI row → tool activity → timeline/decision split).
  Chips (`real runner results`, `1s poll`, `proposal`) = reusable metadata badges.
  The three-row safety-guarantee panel directly encodes the non-negotiables — reuse it.

**`docs/gui-reference-screens/eval-tools-panel-populated.png`** — v2 config with inline error.
- Identical to the landing config; only differences: top-bar status shows
  `• Error: ANTHROPIC_API_KEY is required for LLM scans` beside the `01 · RECON` pill;
  objective textarea empty showing placeholder "e.g. prioritize authenticated API
  abuse and chained impact".
- *Cue*: config/precondition errors surface **inline in the top status bar** (non-
  blocking, form stays usable). Current treatment is subtle — pair with an icon/color
  when building. Reuse the objective placeholder copy.

### ReachAgent monospace build (functional predecessor)

**`docs/gui-reference-screens/reachagent-gui-findings-chains.png`** — monospace live-scan page, idle; attack-chain highlight.
- *Layout*: single-page two-column terminal layout — narrow left (SCAN form + status
  panels) + wide right (Live audit log, Findings dashboard, Report).
- *Key elements*: header "ReachAgent — live scan progress" + `4 REPORT` pill; left
  SCAN form (Target/In-scope/Out-of-scope/Identities file/Max payload attempts/Use LLM
  checkbox/blue Start scan); status panels RECON PROFILE, GRAPH STATE (mini stat tiles
  HOSTS/SERVICES/ENDPOINTS/PARAMS/FINDINGS, active tile outlined), PHASE TIMELINE;
  Findings cards with severity left-accent bar; **CHAIN row of pills**:
  `bola → ENABLES → ssrf → CREDENTIAL → session` (vuln nodes blue, relations in caps).
- *Theme*: dark monospace; severity badges, blue Start/stat accents, colored chain pills.
- *Cue*: **the attack-chain pill sequence** (vuln → RELATION → vuln/asset) makes the
  graph's reachability story visible — carry into v2 findings. Findings use a severity-
  keyed left accent bar.

**`docs/gui-reference-screens/reachagent-gui-findings-dashboard.png`** — monospace completed scan, findings populated.
- *Key elements*: `4 REPORT` pill; RECON PROFILE "default"; GRAPH STATE
  2/0/1/1/9; **PHASE TIMELINE status taxonomy** — green `FINDING`, amber
  `NOT-APPLICABLE` (jwt/graphql/business_logic reasons), grey `INFO`; audit log rows
  (`seed` blue, `fired:200/204` green); findings cards (clickjacking/csrf/cors MEDIUM,
  file_upload HIGH, oracle: structural); REPORT rendered as raw markdown pipe-table.
- *Theme*: dark monospace; blue keywords, green success, amber not-applicable, grey info.
- *Cue*: the **FINDING / NOT-APPLICABLE / INFO** color taxonomy is an honest way to
  show negative results — preserve it. Report-as-raw-markdown is a rough edge (later fixed).

**`docs/gui-reference-screens/reachagent-gui-live-scan.png`** — monospace scan RUNNING, recon phase.
- Sparse right column; `1 RECON` pill + "running — recon" status; audit log streaming
  calibration probes (`calibration GET …/reachagent-cal-<hash>/nonexistent fired:404`,
  blue verb + green status); Findings = "Scanning…".
- *Cue*: running/streaming state. Stage pill increments (`1 RECON → 4 REPORT`) =
  run-progress indicator; append-only log with mono timestamps + color-coded verb/status.

**`docs/gui-reference-screens/reachagent-gui-live-scan-done.png`** — monospace completed; findings as markdown AND rendered HTML table.
- FINDINGS shows raw markdown pipe-table then a real HTML table (headers finding_id/
  vuln_class/severity/oracle/evidence/status, severity cells color-coded amber/orange);
  9 findings, all confirmed_violation.
- *Cue*: target treatment = the rendered, severity-color-coded table. Drop the
  redundant markdown dump; keep rendered table + download.

**`docs/gui-reference-screens/reachagent-gui-report-viewer.png`** — monospace Phase-4 REPORT / export section.
- "REPORT — PHASE 4 (LLM NARRATIVE + DETERMINISTIC FINDINGS TABLE)" section with three
  outlined download buttons `Download .md / .json / .html` above the rendered findings
  table (9 confirmed_violation rows).
- *Cue*: **three-format export row above the deterministic table**, with the section
  label reinforcing the LLM-prose vs oracle-confirmed-data split. Model for the v2
  Report page.

**`docs/gui-reference-screens/reachagent-gui-review-fixed.png`** — monospace, reordered layout + fixed severity badges.
- Section order changed: FINDINGS DASHBOARD first, then REPORT — PHASE 4 (downloads +
  table), and LIVE AUDIT LOG relocated to a **full-width bottom band**. Severity now
  rendered as **colored outline pills** (orange MEDIUM/HIGH) instead of grey brackets.
- *Cue*: two decisions to carry into v2 — (1) confirmed findings + report above the
  fold, verbose execution log demoted to a bottom strip; (2) severity as colored
  outline pills.

---

## Design cues for building/refining the GUI

1. **Adopt the v2 dark shell as the base** (`eval-*`): ~230px sidebar with gradient
   ReachAgent brand, breadcrumb + status top bar, floating rounded config card, deep-
   navy (~#0d1017) ground, electric-blue + violet gradient accent, green reserved for
   confirmed metrics. This replaces the PentAGI clone.

2. **Rebrand debt is real**: the clone build (`dashboard-*`, `flows-*`) still says
   "PentAGI". Rename, add the ReachAgent logo, and remap all metrics to security
   concepts (scans/requests/oracle runs/planner spend).

3. **Standardize one shared list shell** (seen across Flows/Resources/Knowledges/
   Templates): header + `+ New X` primary + filter/search + column-settings toolbar +
   rounded-panel table + standard pager footer. Build it once.

4. **Numbered phase pills** (`01 Recon → 02 Endpoints → 03 Payloads → 04 Report`) as
   the run-progress motif, echoed by the top-bar stage pill (`01 · RECON`) and the
   monospace build's `1 RECON → 4 REPORT` increment.

5. **Safety-guarantee panel** (`eval-tools-panel-empty.png`): Scope guard • enforced /
   Read-only first • enforced / Oracle confirmation • required, values green. Directly
   encodes the project's non-negotiables — a strong trust cue; keep it visible.

6. **Attack-chain pill sequence** (`reachagent-gui-findings-chains.png`):
   `vuln → RELATION → vuln/asset` rendered inline under each finding — this is the
   reachability graph made legible. Port it into the v2 findings view.

7. **Phase-timeline status taxonomy**: green `FINDING` / amber `NOT-APPLICABLE` (with
   an honest reason) / grey `INFO`. Preserve — it shows negative results honestly.

8. **Findings + report first, audit log last** (`reachagent-gui-review-fixed.png`).
   Severity as **colored outline pills** (not grey brackets), findings table
   severity-color-coded, `oracle: … / evidence: … / status: confirmed_violation`
   metadata line per finding.

9. **Export row**: three-format download (`.md / .json / .html`) directly above the
   deterministic findings table, labeled to split LLM narrative from oracle-confirmed
   data.

10. **Per-scan detail workspace** (`flows-5-light.png`): resizable two-pane (assistant/
    chat left, tabbed inspector right). Map inspector tabs to ReachAgent:
    Terminal=firer log, Tasks=phases, Agents=Explorer/Coordinator/Validator,
    Searches=recon runners, Vector Store=payloads/corpora, Files=evidence exports.
    **Bug to fix: the magenta terminal viewport (unstyled xterm.js canvas).**

11. **Status/error patterns**: blue `Running` chip + spinner for live scans; config/
    precondition errors surfaced **inline in the top status bar** (non-blocking) — but
    add an icon/color, the current treatment is too subtle.

12. **Theme parity**: true token-swapped light/dark. One non-token rule — bar-chart
    fills go gradient (dark) → solid distinct blues (light); chips darken their fill in
    light mode for contrast.

13. **Reusable metadata badges/chips**: `real runner results`, `1s poll`, `proposal`,
    `Default`/`N/A` — small muted-border chips for provenance/state labeling.

14. **Empty states** (`settings-providers-light.png`, `eval-tools-panel-empty.png`):
    icon + heading + one-line guidance + CTA, with a redundant primary in the toolbar.

15. **Honest-status microcopy**: PentAGI's "may stay near zero when using local
    engines" caption and the not-applicable reasons are good models — say plainly when
    a metric or check is inapplicable rather than showing a false zero.
