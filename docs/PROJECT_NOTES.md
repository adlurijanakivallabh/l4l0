# ReachAgent Project Notes (decisions, history, status)

ReachAgent is an authorized Web/API authorization-and-vulnerability testing
agent. This file is a durable digest of the design/decision/audit record.
Source of truth for architecture: `docs/reachagent-final-plan.md` (v2.9,
locked). Operational history: `docs/build-plan.md` and the
`docs/decisions-*.md` per-phase records.

## What is locked (the plan invariants and positioning, unchanged since v1.14)

Positioning (`docs/reachagent-final-plan.md`): confirmed multi-hop, cross-class
attack **chains**, not single-request scanning. Three-role agent split —
Coordinator (Sonnet, graph/scoring), Explorer (Haiku, fires requests),
Validator (Sonnet, oracle + finding).

The five non-negotiables, enforced in code (not just documented):

1. **No Finding without a deterministic `run_oracle` confirmed_violation.**
   LLM judgment only proposes candidates. A tool's own "vulnerable" output is
   never a finding. Three independent guards enforce this
   (`docs/decisions-oracle-phase6.md`,
   `docs/decisions-snapshot-phase1.md`):
   (a) an AST walk over all of `src/` asserts `OracleVerdict(...)` — the sole
   type carrying `.confirmed` — is constructed only inside the six oracle-family
   files; (b) `write_finding` is gated on `verdict.is_violation` (NOT
   `.confirmed` — a `confirmed_allowed` verdict has `confirmed=True` but is
   refused); (c) `ReachabilityGraph.add_finding` independently raises unless
   status is `CONFIRMED_VIOLATION`.
2. **Role-bounded tools, pinned by AST tests (4/3/3 counts).** Explorer
   (fingerprint/get_payloads/fire_request/fire_browser/classify_response) never
   calls `write_finding` or `run_oracle`. Coordinator
   (query_graph/score_and_select/check_budget) never fires or runs the oracle.
   Only the Validator calls `run_oracle` + `write_finding`. Subagent
   `.claude/agents/tool-boundary-auditor.md` re-verifies this.
3. **No external scanners as detection dependencies.** sqlmap/Nuclei/ZAP/
   Burp/Caido are never a detection authority. Phase 8 signal-gated adapters
   (sqlmap/nuclei/nikto/dalfox/commix/jwt_tool) produce inert bounded
   `Candidate` records (cap 100, 1 MiB) that must be independently re-fired and
   confirmed by a mechanism-matching `OracleVerdict`
   (`docs/decisions-signal-gated-phase8.md`).
4. **Read-only-first.** No state-changing request until the read-only case is
   confirmed safe. Confirmation is always an independent read-only re-read,
   never the mutating response.
5. **Scope allowlist enforced at the execution layer.** ScopeGuard is
   deny-by-default, per-segment path match (`/api` != `/apixyz`). Fixed gate
   order per request: scope -> read-only-first -> send, failing before any
   network I/O (`docs/decisions-snapshot-phase1.md`).

Other locked facts: exactly **six oracle families** (differential,
execution_confirmation, oob_callback, timing_statistical, structural,
business_rule_invariant), a hard cap — new classes (clickjacking, CORS, CSRF,
CVE-match) route through the existing STRUCTURAL family, no seventh added
(`docs/reachagent-final-plan.md` §7, `docs/decisions-oracle-phase6.md`).
In-flight objects pass by server-side handle (fire_ref/verdict_ref), never over
the JSON wire — rebuilding a verdict from JSON would let a caller forge a
"confirmed" verdict. `payload_ref` is a handle, not an inlined exploit string.
NetworkX is the default graph store; Neo4j-via-MCP exists as parity only.

**Entry-surface reversal (gotcha):** final-plan v1.14 still documents a
`reachagent-scan` CLI and `reachagent-tui`, but plan v2 (README,
`docs/llm-first-execution-plan.md`, CLAUDE.md, `.claude/plans/gui-llm-driven-plan.md`)
**removed both** — the GUI is the only entry point. Treat README/build-plan as
authoritative on entry surface. GUI requires a configured LLM + validated
execution plan; `use_llm=false` is rejected; no fallback plan in the GUI path.

## Phase-by-phase history

From `docs/build-plan.md` (14-phase plan) and the `docs/decisions-*.md` records.
Phases 1-12 + 11A + 11A.1 are COMPLETE with commit hashes; Phases 13-14 are not.

- **Phase 1 — scaffolding / execution layer** (`docs/decisions-snapshot-phase1.md`):
  execution gate order (scope->read-only-first->send), identity/session
  isolation, recon SurfaceMapper (empirical-or-absent `can_call`), tagged
  payload library (payload_ref handles, null-sink authz classes), Explorer
  4-tool pipeline, differential oracle with a pure `decide()` table, Validator
  `write_finding`/`mark_inconclusive` gates, `reachagent-mcp` server (7 tools,
  handle indirection), docker-compose two-toggle eval env. Decision: the finding
  gate is `is_violation`, and empirical-or-absent (missing baseline ->
  inconclusive, never "safe") is what keeps toggle-OFF runs at zero findings.

- **Phase 2 — graph ownership + business logic + chains + crAPI**
  (`docs/decisions-snapshot-phase2.md`, `docs/decisions-endpoint-mapping-phase2.md`):
  store ownership + finding-relationship edges, ownership as a discovery
  *recipe* (read off the app's own response, not a static field), per-instance
  object node identity (`object:{type}:{instance_key}`), business-logic
  4-template oracle (2nd verdict-minting family), Neo4j backend via
  neo4j-cypher MCP (parity not cutover, no `import neo4j`), Chain Solver
  (spawn-and-requery, one `advance` entry). Endpoint/form mapping: stdlib
  HTMLParser, no JS execution, 9 normalized parameter locations. Key bug caught:
  Chain Solver over-linked on iteration-adjacency; fixed to link only on a
  produced/consumed identifier shape match.

- **Phase 3 — identity / authentication / session-binding**
  (`docs/decisions-identity-phase3.md`): login is an explicit scope-gated,
  audited session-bootstrap POST; secrets stay process-local (graph sees only
  `token:<identity>`, cookie names, auth kind, expiry). IdentityStore sole
  owner, OIDC/.well-known read-only probe, per-identity firer header
  resolution, fail-closed auth.

- **Phase 4 — LLM planning / adaptive control**
  (`docs/decisions-llm-control-phase4.md`, commits 97a54f7, a95de3d): stdlib-only
  adaptive control in `scan.agentic_loop` — SHA-256 state revisions, four
  allowlisted actions (continue/skip/revise/revisit), loop/revisit/idle/cancel
  guards, atomic JSON checkpoints. Model proposes scheduling/priority only;
  malicious status/finding fields rejected before the finding seam.

- **Phase 5 — payload library / context-selection / mutation**
  (`docs/decisions-payload-phase5.md`): model ranks in-tree sink-matched refs and
  requests bounded mutation descriptors; never supplies payload text. Pure
  mutation module (<=4 children/parent), revalidates sink/oracle/edge/provenance/
  decoded shape. Adds R7/R8 vendored payload/wordlist manifests.

- **Phase 6 — deterministic-evidence / oracle hardening**
  (`docs/decisions-oracle-phase6.md`): adds `oracles/evidence.py`
  `EvidenceMetadata` projection (bounded opaque handles, non-secret headers,
  deterministic inconclusive reason strings, negative-result audit); rejects
  secret-bearing finding metadata at `write_finding` and `graph.add_finding`.
  AST proof: exactly six `OracleVerdict(...)` call sites, one per oracle.

- **Phase 7 — stateful API + property-based exploration**
  (`docs/decisions-stateful-phase7.md`, commit 824b69a): immutable
  StatefulPlan/StatefulStep, deterministic boundary/negative values,
  OpenAPI/GraphQL/Postman/observed-traffic ingestion, hash-only RuntimeBindings.
  Adds exactly ONE structural graph edge (`data_dependency`); `enables` stays
  finding->finding. NOT yet wired into top-level scan orchestrator (deferred).

- **Phase 8 — signal-gated external adapters**
  (`docs/decisions-signal-gated-phase8.md`, commit 5a91e24): sqlmap/nuclei/nikto/
  dalfox/commix/jwt_tool as OPTIONAL evidence only. Live off unless
  `REACHAGENT_RECON_LIVE`; enforces signal->scope->binary-presence, `shell=False`
  arg arrays, empty env when off. Candidate reaches the writer only via an
  injected Validator-side reconfirmation callback + a mechanism-matching
  confirmed_violation.

- **Phase 9 — browser + proxy transports**
  (`docs/decisions-transports-phase9.md`, commits 874f04e/5db9ab3/b43332d/97510e1;
  re-verified `docs/decisions-phase9-reverification.md`): LLM chooses only
  http/browser/proxy — choice changes EVIDENCE COLLECTION, not interpretation.
  Browser re-checks scope on every HTTP(S) request incl. redirects/subresources;
  proxy fails closed with no URL and rejects model-supplied credential headers.
  Re-verification (no code change) disproved an alleged non-configurable
  `window.fetch` hook: absent from repo + reachable git history; the shim hooks
  only `Element.prototype.innerHTML` and `Location.prototype.href`.

- **Phase 10 — multi-hop chaining + durable resume**
  (`docs/decisions-chain-resume-phase10.md`, commit 52f2c3a): only a committed
  confirmed_violation advances a chain. Resume is CONTINUE-NOT-REPLAY (existing
  can_call statuses incl. INCONCLUSIVE filtered before selection; errored
  attempts stay retryable). Durable state = atomic JSON (temp-file + os.replace):
  structural facts, solver ledgers, last 2000 audit entries, bounded phase
  projection — NO bodies/cookies/credentials/handles.

- **Phase 11 — production GUI workspace**
  (`docs/decisions-gui-phase11.md`, commits b77488c/9dfd8ad): browser-only control
  surface that CANNOT fire/oracle/write-finding. Lock-protected scan registry,
  lifecycle projection, bounded event buffer, cooperative cancellation,
  incremental events. All projections server-side redacted
  (`_public_text`/`_public_value`); missing graph -> `available:false` + "-",
  never fabricated zeros. No-build vanilla page.
  - **Phase 11A** (`docs/decisions-gui-phase11a.md`, commit 32136b0): parallel
    assessment rail from `/api/scans` (GUI-only, no second state store).
  - **Phase 11A.1** (`docs/decisions-gui-phase11a-visual.md`, commits
    d75a681/e988b29): visual command-center rebuild — dark-first tokens + light
    fallback, mission-control layout, responsive 1180/760/390px. Presentation
    only.

- **Phase 12 — reporting / evidence export / history**
  (`docs/decisions-reporting-phase12.md`, commit 7201978): read-only over
  confirmed graph state. Only `CONFIRMED_VIOLATION` nodes exported. Shared
  `report/renderer.py`: deterministic JSON/Markdown/HTML tables, evidence index,
  SARIF 2.1.0 (stable rule IDs), self-contained HTML, deterministic bundle.
  Chain paths read from persisted `enables`/`derived_credential` edges, never
  inferred from LLM prose. Redaction verified by asserting secret VALUES absent
  across all formats. GUI exports set `X-Content-Type-Options:nosniff`.

## Eval gates and measured results

From `docs/reachagent-final-plan.md` §14, `docs/decisions-snapshot-phase1.md`,
`docs/decisions-snapshot-phase2.md`, and CI (`.github/workflows/ci.yml`).

- **VAmPI (Phase 1 gate) — PASSED.** Toggle ON: precision **100% (3/3)**,
  recall **100% (3/3)** on bola/mass_assignment/idor. Toggle OFF: **0** confirmed
  findings. Thresholds were >=90% precision, >=80% recall, exactly zero off.
  Autonomous live confirmation later extended to SQLi via differential
  DATABASE_ERROR.
- **crAPI BOLA (Phase 2) — PASSED.** Both documented BOLA chains
  (vehicle-location, mechanic-contact) reconstructed end-to-end live;
  per-instance object identity live-confirmed (adam + pogba resolve to distinct
  `object:vehicle:{uuid}` nodes). crAPI eval gate itself is SKIPPED in the
  composite (not provisioned in CI).
- **Juice Shop — PASSED 6/9 (66.7%) at 0% FP**
  (`REACHAGENT_JUICESHOP_EPHEMERAL=1`). The historical **7/9 (75%)** target was
  REVERTED to 6/9 because a "flow != executed" DOM-XSS attribution inflated FP
  from 0 to 14.3%. Code keeps two constants: `COVERAGE_FLOOR=0.75` vs
  `API_ONLY_COVERAGE_FLOOR=6/9`. uploadSize/uploadType lack retrieval/execution
  evidence; localXss needs browser DOM attribution the API-only runner can't
  provide.
- **PortSwigger blind-SQLi — SKIPPED** (not provisioned; OOB/interact.sh infra
  not stood up, timing fallback only). **DVGA GraphQL — SKIPPED.**
- **Composite `python -m reachagent.eval` — PASSED** when only
  locally-provisionable gates run (vamp + juice PASS; crapi/portswigger/dvga
  SKIPPED).
- **Last recorded fresh whole-tree pytest** (baseline @174bfaf): **1,154 passed
  / 3 skipped / 5 failures** — 1 real payload-slot regression fixed, 4 external-
  service startup races passed on rerun ("no deterministic local failure
  remains"). The whole-tree run is intentionally reserved for Phase 14; phases
  run only focused gates (Phase 4: 37, Phase 5: 153, Phase 6: 240/2, Phase 7: 17,
  Phase 8: 8+62, Phase 9: 11+112+2, Phase 10: 57, Phase 11/11A: 22, 11A.1: 22+17,
  Phase 12: 48).

## Audit findings still open

The dedicated D4_audits digest was a placeholder (test stub, no real content),
so there is no separate audit-findings document to draw from. The only
audit-shaped record is the **Phase 9 browser-shim re-verification**
(`docs/decisions-phase9-reverification.md`): CLOSED with no code change — the
alleged non-configurable `window.fetch` replacement is absent from the repo and
reachable git history, so no historical DOM-XSS/execution-marker finding is
attributable to it (50/51/2 tests re-run green). No open audit finding is
recorded across the docs.

## Deferred / open items (ranked)

1. **Phase 13 (race / async)** — sequential-first, HTTP/2 single-packet
   escalation, reuse business-rule oracle. Planned, not implemented
   (`docs/build-plan.md`).
2. **Phase 14 (full hardening + eval)** — re-run all gates simultaneously, one
   authorized whole-tree pytest suite, fresh scope/audit/oracle-boundary review,
   release report. Not done; the whole-tree run is deferred here by design.
3. **crAPI, PortSwigger blind-SQLi, DVGA GraphQL eval gates SKIPPED** — not
   provisioned. OOB/interact.sh infra not stood up, so blind-SQLi OOB path stays
   dormant (timing fallback only).
4. **Phase 7 stateful sequences not wired into the top-level scan orchestrator**
   — integration deferred to avoid a second planning loop.
5. **Phase 8 top-level reconfirmation wiring** — emits
   `reconfirmation_required` when no Validator callback is supplied; a
   class-specific independent evidence builder is deferred.
6. **GUI scan history + active-assessment rail are PROCESS-LOCAL** — durable
   cross-process history, pause/resume (only cooperative cancellation exists),
   and rich PDF reporting are later scoped work (`REACHAGENT_HISTORY_DIR` opt-in).
7. **Multi-provider live-reasoning tuner** — only the Anthropic adapter ships
   (`claude-3-5-sonnet-20240620`); OpenAI adapter deliberately deferred
   (provider-neutral interface, one-class swap). Live tuning is flag-gated
   default OFF (`docs/live-reasoning-design.md`).
8. **Final-plan §17 pre-code open questions** — per-target test-identity
   provisioning; confirmed-chain output format (replay script vs Postman vs
   both); how aggressively the race module should auto-identify limits.
9. **Optional post-plan capabilities (proposal-checkpoint only, not built)** —
   request-smuggling evidence, cache-poisoning evidence, insecure-deserialization
   safe-canary evidence, WebSocket/API event mapping, continuous monitoring.
   These four (smuggling / cache poisoning / deserialization / novel business
   logic) are permanently Weak by design — no safe generic oracle.
10. **Deferred integrations** — external-scanner ingestion mode, notification
    webhook on confirmed_violation, ticketing (GitHub Issues/Jira), CI/CD
    triggering. SSE `/stream` on the GUI documented as the poll's upgrade path,
    not built.
11. **Future migrations gated on measured bottlenecks** — SQLite payload store
    (if `(vuln_class, sink)` lookup measured slow), Neo4j-via-MCP cutover (when
    chain queries become the bottleneck).
12. **JWT `kid` injection not payload-backed** — only none-alg / HS256
    key-confusion / weak-secret are. CSRF stays Partial (precondition-only:
    SameSite=None + no token; absent SameSite = inconclusive).

_Note on doc drift:_ adapter counts differ across docs (build-plan §0: 35
LLM-selectable; llm-first: 26-adapter catalog; final-plan: 17 wrappers) — these
are dated snapshots, not one source of truth.

## v2 Capability-Expansion — Phase 1 (shipped 2026-09-01)

Making ReachAgent behave like Shannon+Strix+CAI+PentAGI combined while keeping the
oracle proof gate none of them have. Phase 1 (of 5):
- **Real conversational agent**: `OpenAICompatibleClient.chat(messages)` (multi-turn,
  `system` role) + `POST /api/scan/{id}/ask`. Replaces the fake canned steer reply with
  a real LLM answer from live scan state; the box answers AND steers; the agent's own
  loop rationale streams into chat via `kind:"assistant-note"` events. Read-only persona
  (never `write_finding`).
- **Suspected / Unconfirmed tier**: new `SuspectedFinding` node (structurally separate,
  like `StaticAdvisory`). Captures ONLY a genuine external assertion that failed
  reconfirmation — signal-gated scanner (nuclei/sqlmap/dalfox/jwt-tool) claims the oracle
  couldn't re-prove. Deliberately NOT populated by routine oracle non-confirms inside our
  own systematic drivers (nosqli/ldap/command_injection/jwt_forgery) — that's the expected
  clean-negative outcome for a secured parameter, not a lead; an early version did record
  those and was caught + reverted in-session before shipping (would have flooded every scan
  with noise). Own report section + GUI area + API `suspected` rows; never counted as
  confirmed.
- **Cancel-feedback fix**: distinct `cancelling` lifecycle, disabled/relabelled Cancel
  button during wind-down, stable header-button width, idempotent repeat-cancel.

Remaining phases: aggressive mode, interleaved hunting, per-role model tiering, detection
depth (JWT forgery / two-identity IDOR / prototype pollution / cache poisoning), extended
browser recon, attack-path chaining (W17), app-domain inference (W18), LLM-authored report.

## v2 Capability-Expansion — Phase 3 (partial, shipped 2026-09-01)

- **Prototype pollution (W9)**: new client-side STRUCTURAL check. Headless browser loads
  each HTML endpoint with an injected `__proto__`-shaped query param (3 encodings), then
  checks a fresh `{}` literal for the marker — unambiguous, no baseline needed. New
  `scan/prototype_pollution.py`, mirrors `scan/xss_dom.py`'s driver-accepting-core /
  untested-launch-plumbing split for testability.
- **W7 (JWT forgery) and W8 (two-identity IDOR)**: verified already fully built this
  session — no code needed, just confirmed and documented.
- **W17 (attack-path chaining) research**: mapped the real mechanics before building.
  Key findings: `bypass_identity_hint` (nosqli/ldap) is computed but never read by any
  caller — pure dead intent. `ChainSolver.advance()`'s spawn branches are fully implemented
  but have zero live callers (only the self-escalation `spawn=None` path is ever used, in
  `scan/entrypoint.py`). The real blocker: `RequestFirer._identity_stores` is a one-time
  snapshot taken at construction with no post-construction registration hook — a
  mid-scan-spawned identity cannot authenticate through the existing firer without either
  rebuilding it or adding a new registration method. `merge_new_findings` is findings-only
  and would silently drop a spawned Session/Identity node if reused unchanged for chaining.

## v2 Capability-Expansion — Phase 3.5: attack-path chaining (shipped 2026-09-01)

- **W17**: a confirmed nosqli/ldap auth-bypass whose probe response carries REAL session
  material (reusing `identity.login._extract_session_material` — the same parser the real
  login flow uses) spawns a fresh synthetic (`AuthState.SYNTHETIC`/`Provenance.DERIVED`)
  identity and re-hunts the full Phase-3 class order under it, exactly once. New
  `RequestFirer.register_identity()` — the one additive seam needed since the firer's
  identity stores were otherwise frozen at construction. New `scan/chaining.py`. New
  findings link back to the confirming finding via `add_enables` (already rendered by the
  report/GUI's existing chain display). This is the literal "SQLi -> admin creds -> deeper
  bug only reachable as admin" scenario.
- Bounded: exactly one re-hunt pass (no chain-of-chains), sequential dispatch path only
  (concurrent-specialist path deliberately untouched to avoid touching Build Order 2c's
  already-reviewed thread-safety guarantees).
- Disclosed limit: re-hunts the SAME already-discovered endpoint set under the new
  identity's privilege — does not trigger new content discovery (an admin route never
  crawled unauthenticated stays invisible).
- Two real bugs caught and fixed during test-writing itself (not production code): a
  timing-oracle flakiness class (denoised via the codebase's own established
  `_TIMING_TRIALS` remedy, matching `test_blind_injection_drivers.py`'s documented
  pattern) and a test-design flaw (the first mock target granted the derived identity
  access unconditionally, leaving no genuine bypass shape for the auth-bypass oracle to
  confirm — fixed by giving the admin-authenticated path its own two-layer bypass shape).

## v2 Capability-Expansion — W6: per-role model tiering (shipped 2026-09-01)

- `build_openai_compatible_client(tier="core"|"grunt")` — additive, default "core" is
  byte-for-byte the old behavior. "grunt" resolves optional `REACHAGENT_LLM_GRUNT_MODEL`
  (same account, cheaper model) for high-volume/low-stakes calls: `rank_vuln_classes` +
  all 6 recon tuning helpers. Core reasoning (chat, phase-decision advisor, report
  narrative) deliberately untiered by design.
- GUI named-provider config gains optional `grunt_model`, threaded through the existing
  named_overrides env-application mechanism — no new plumbing.
- Disclosed limit: the recon per-step tool-selection loop shares one client with the
  upfront strategic plan call (`llm/planner.py::build_planner_client`) — splitting that
  safely needs more surgery than fit this increment; left untiered, not silently skipped.
- Housekeeping: fixed 2 pre-existing ruff line-length violations (test files) that had
  slipped past an earlier commit's `src/`-only ruff check.

## v2 Capability-Expansion — W11: extended browser recon for SPA targets (shipped 2026-09-01)

- New `run_browser_recon_async` in `browser/shim.py` — independent from the XSS taint
  shim (separate init script, separate collector), same "hook via init script, read
  via evaluate()" pattern. localStorage/sessionStorage KEY NAMES ONLY (never values —
  matches the cookie-value discipline already in place). New `scan/browser_recon.py`
  reuses `recon/surface.py`'s `_form_endpoint` to materialize SPA-rendered forms as
  real Endpoint/Parameter graph facts — a form only a JS framework renders (invisible
  to the static HTML parser's empty `<div id="root">` shell) becomes visible surface.
- Wired into `scan_all_classes` right after firer/identity are constructed (had to move
  it there after first placing it too early, before those existed) and before Phase 3.
  Fail-open on any browser/Playwright error.
- Disclosed limit: newly materialized parameters aren't auto-fingerprinted — sink-type
  inference is a separate on-demand Explorer pass, not something this driver safely
  triggers inline. A real follow-up, not silently skipped.
- Caught and fixed one real correctness bug during development: the driver initially
  emitted new-endpoint events as `kind="finding"` — that's reserved for actual
  run_oracle-confirmed findings in this codebase's event vocabulary. Fixed to
  `kind="info"` before it shipped.

## v2 Capability-Expansion — W12: per-host circuit breaker (shipped 2026-09-01)

- Always-on Gate 1.1 in `RequestFirer.fire()`, right after scope enforcement, applying
  to every fire (read-only included, unlike the Guardian advisor which is
  state-changing-only). Opens per-host after 5 consecutive TRANSPORT-LEVEL failures
  (a raised exception — connection refused/timeout/DNS), 30s cooldown, then half-open.
- Deliberately counts ONLY transport exceptions, never an HTTP status code — a
  401/403/404/500 is frequently the exact signal an oracle needs, not a "host is
  down" indicator. This narrow definition is what makes an always-on default safe
  (verified: no hermetic test raises a transport exception across the several
  consecutive fire() calls needed to trip it).
- Composes with, never replaces, ScopeGuard — an out-of-scope host is still refused
  by scope first, always (verified with a dedicated test).
- New `CircuitOpenError`, exported from `execution/__init__.py`. 6 new tests.

## v2 Capability-Expansion — W13: LLM full authority over the report (shipped 2026-09-02)

- New `report/llm_full_report.py::generate_llm_authored_report` — the LLM writes the
  ENTIRE report (structure, exec summary, per-finding narrative/risk/remediation,
  prioritization, the whole Suspected-tier presentation), not just the exec-summary
  prose `generate_narrative` already produced.
- Hard boundary unchanged: confirmed findings + evidence come from `run_oracle`
  (`build_evidence_index`) BEFORE the LLM sees anything; a defense-in-depth check
  after generation confirms every confirmed finding_id appears verbatim in the
  output. Missing even one -> the whole LLM report is discarded, falls back to the
  existing, unmodified deterministic template. Never partially trusted.
- Wired additively in gui/app.py's report-generation step: try full-authority first,
  fall back on None. The existing, heavily-tested `render_professional_report_markdown`
  path is completely untouched — zero risk to existing report tests.
- 9 new tests (7 unit on generate_llm_authored_report incl. multi-finding coverage
  and graph-immutability; 2 GUI wiring tests for both the success and fallback paths).

## v2 Capability-Expansion — W5: widen candidate generation, nosqli/ldap (shipped 2026-09-02)

- `run_nosqli`/`run_ldap` in `scan/orchestrator.py` move from one hardcoded bypass
  value each to a named multi-variant tuple tried in order — `_NOSQL_BYPASS_VALUES`
  (ne-null/ne-empty/gt-empty/regex-wildcard/exists-true) and `_LDAP_BYPASS_VALUES`
  (wildcard-classic/objectclass-wildcard/admin-password-bypass/cn-wildcard) —
  mirroring `run_jwt_forgery`'s existing 4-variant loop pattern. First oracle
  confirmation wins (`break`); a WAF/filter that strips one operator/wildcard shape
  may not catch another.
- Flakiness-safe by construction: only the LAST variant in each loop may exercise
  the real wall-clock timing fallback (`_paired_timing`). Every earlier variant uses
  a fake `_no_timing_signal()` (identical fabricated latencies, zero live network
  calls, can never itself confirm) — widening candidates does not multiply real
  timing probes fired per parameter, so it can't reintroduce the documented
  TIMING_STATISTICAL flakiness class.
- The confirming `variant_name` now rides on `evidence_ref`/`finding_id` (e.g.
  `orchestrator/nosqli /admin/secret user:gt-empty`) and the emitted event message,
  so the report/GUI can show which bypass shape actually worked.
- Updated `tests/scan/test_attack_path_chaining.py`'s hardcoded expected finding_id
  to include the new `:ne-null` variant suffix (the mock target's first-tried
  variant already confirms deterministically). 3 new tests in
  `tests/scan/test_blind_injection_drivers.py`: a WAF-like handler proving the loop
  tries later variants when earlier ones are blocked (nosqli + ldap), and a
  request-count assertion proving the real timing round fires exactly once (on the
  final variant only), not once per variant.
- Disclosed scope limit: this is the curated-list version of "widen candidate
  generation," not the plan's original freeform-LLM-proposes-payloads vision — an
  open-ended checklist feeding `llm/planner.py`/`tools/candidate.py` remains a
  future increment, deliberately deferred rather than rushed.

## W16: adversarial review + live verification, closing Phase 5 (shipped 2026-09-02)

- Two read-only review agents (Suspected-tier isolation; chat-persona role
  boundary) found zero exploitable issues — both only flagged a test-coverage
  gap, closed with 3 new regression tests locking in the invariants explicitly
  (severity-stat exclusion, `add_enables`/`add_derived_credential` reject a
  suspected id, a chat reply that impersonates a tool instruction is inert).
- Live verification against `http://demo.testfire.net` found a REAL bug on the
  first live attempt: the LLM planner's 3-round validation-fixer loop only
  repeated the raw error text, never reminding the model which phase a
  misplaced tool belongs to — two different real models both failed to
  self-correct. Fixed by adding a compact `{tool: required_phase}` map to the
  fixer prompt. Re-verified: the same scan then completed with 11 real
  confirmed findings (command_injection, path_traversal, clickjacking ×6,
  default_credentials, ...).

## Operator-requested: LLM-driven vulnerability review (shipped 2026-09-02)

- New `scan/llm_vuln_review.py::run_llm_vulnerability_review` — the LLM gets
  genuine Shannon/Strix-style judgment over the discovered surface (paths,
  methods, params, sink types, app-domain — structure only, not response
  content, since the audit trail never persists bodies). Every lead lands ONLY
  as a `SuspectedFinding` (`source="llm_judgment"`) — never `write_finding`/
  `run_oracle`. Bounded to one call per scan, capped at 12 leads, fail-open.
- This was an explicit operator ask mid-session for the LLM to "detect
  vulnerabilities like the reference projects" — delivered as an ADDITIVE
  capability that never weakens the oracle proof gate, not a replacement for
  it. 13 new tests.

## Phase 6, Stage A: GUI live-data richness (shipped 2026-09-02)

- Root cause of the operator's complaint ("clickjacking medium / Oracle:
  structural / Evidence: .../security.htm / Status: confirmed_violation" and
  nothing else): the GUI's finding rows never included the rich, ALREADY-BUILT
  deterministic narrative context the markdown report already used
  (description/remediation/WSTG/CVSS/likelihood/impact). New
  `report/professional.py::vuln_class_context()` factors that out so both
  surfaces read the exact same reviewed text — no duplication, no new LLM cost.
- `.fcard` rebuilt as an expandable `<details>` card (same idiom as the
  existing surface-tree disclosure elements) showing the new fields; `ScanEvent`
  gained a `timestamp` field; Inter+JetBrains Mono fonts; staggered fade-in;
  animated metric counters.
- Two real bugs caught during LIVE Playwright verification, not by code
  reading alone: (1) a broad font-stack find/replace turned `--font-mono`'s own
  definition into a circular self-reference, silently breaking every monospace
  font on the page (computed value came back empty); (2) the existing ~2.5s
  poll cycle rebuilds the whole findings list unconditionally, which would have
  snapped every expanded `<details>` card shut every tick — fixed with a cheap
  count-based signature that skips the rebuild when nothing changed.
- Deferred, disclosed: a phase-progress stepper was scoped but not built — the
  top-level scan `phase` field only has 4 coarse values, not the full 7-stage
  pipeline, so a stepper against it would show misleadingly-stuck progress.
  Needs the per-event phase stream tracked as state instead — left for later
  rather than shipped half-right.

## Phase 6, Stage B: report-writing quality (shipped 2026-09-02)

- The LLM-authored report's prompt gave no writing-quality guidance, so it
  produced generic field-restatement prose ("A path-traversal violation was
  confirmed... The associated probe response is referenced as fire-87...")
  instead of real analyst writing. Researched real pentest report templates/
  guidance (OWASP's reporting standard, TCM Security's sample report,
  FireCompass's good-vs-bad finding-writing guidance) and added a concrete
  WRITING STYLE block to the prompt: root-cause-first, concrete attacker-action
  framing, name the actual affected functionality, specific (not cheatsheet)
  remediation, vary sentence structure, a plain-language exec summary — paired
  with an explicit anti-hallucination guard so pushing for specificity can't
  invent a technical detail not actually in the evidence.

## Phase 6, Stage C: closing reference-project gaps (in progress, 2026-09-02)

- Operator asked for the gap list to be actually BUILT, not just documented.
  Two items closed:
  - DVWA local eval target: `docker-compose.dvwa.yml`, verified live
    end-to-end (setup, login). Bound to `127.0.0.1` only after a
    security-review catch on the default all-interfaces port binding.
  - Attack-chain discovery narrowed: `browser_recon.py` now materializes
    rendered links (not just forms) as new endpoints; `_run_attack_path_chain`
    re-runs it under the newly-derived identity before re-hunting, so an
    admin-only nav link becomes real, graph-visible surface the same pass.
    Honestly scoped: only endpoint-level STRUCTURAL checks test the new
    endpoint immediately, since new parameters still aren't auto-fingerprinted.
- Four items stay open, each needing dedicated future scoping rather than a
  rush job: W4b (recon blocks vuln-testing, needs concurrency rigor), freeform
  LLM payload proposal, live intercepting-proxy integration (needs real
  infra), and response-content-aware LLM review (would touch a design
  property this session's own adversarial review just verified as clean).
