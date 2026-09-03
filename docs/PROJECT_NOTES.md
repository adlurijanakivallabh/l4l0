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

## Phase 6, Stage D live-verification bugs (shipped 2026-09-02)

- Running 4 concurrent GUI scans against local targets found two real bugs:
  - Named-provider concurrency: `_run_scan` threaded LLM connection fields
    through raw `os.environ`, so one scan finishing could wipe the
    connection info a different still-running scan needed (an unrelated
    "LLM base URL is required" crash). Fixed by extending the existing
    `RuntimeConfig`/`override()` contextvar to carry these fields too.
  - `response_body` evidence-size crash: a real multi-megabyte response
    hit the oracle evidence's own validation cap, aborting the whole scan
    with an uncaught `ValueError`. Fixed by capping the body where it's
    resolved server-side, a graceful degrade instead of a crash.

## Phase 6, Stage E: real evidence, intent-parsing fixes, GUI pass (shipped 2026-09-02)

- **E1 real evidence**: `StructuralOracle.run()` now auto-fills a bounded,
  secret-scrubbed `body_projection` from the evidence it already decides
  on (mirroring its existing header auto-fill) — `write_finding` already
  persists it, a new shared `evidence_snippet()` surfaces it in both the
  GUI finding cards (a real code block, baseline-vs-probe pair for
  differential findings) and the markdown/HTML report.
- **E2 intent-parsing hardening**: `/api/parse-intent` now returns a
  specific `reason` (no_provider/provider_error/malformed_reply) instead
  of one generic message for every failure mode, and recovers a shorthand
  credential string ("admin/admin123") instead of dropping the whole list.
  Verified live end to end.
- **E4 multi-panel GUI pass**: Audit/Surface/Report redesigned to match
  Stage A's Findings work; Terminal got a narrower polish only (the full
  PentAGI task-tree restructure stays deferred). Self-caught: a Surface-tab
  flicker regression from this stage's own new entrance animation
  (fetchSurface() rebuilds unconditionally every ~2.5s poll) — fixed with
  the same count-based signature-skip already used for the Stage A
  findings-list fix. Also caught a testing-process gap: a CSS-only edit
  needs a fresh page navigation to actually apply, since `index.html`'s
  `<style>` block only loads once at page load.

## E3: ground-truth validation vs. real local targets — 7 real bugs found live (2026-09-02)

Manually compared confirmed findings from real GUI scans against researched, documented
vulnerabilities for VAmPI/DVWA/Juice Shop/crAPI (the automated harness itself is still open).
Found and fixed, each git-stash-verified:

1. `recon/surface.py::_path_and_query` never checked a resolved URL's netloc against the
   current page — an external absolute link (DVWA's own footer link to its GitHub repo)
   materialized as a phantom same-host endpoint (`/digininja/DVWA`). User-reported live via the
   GUI chat persona noticing the mismatch. Fixed at the one shared choke point.
2. `cloud_bucket/detector.py::derive_seed_names` guessed bucket names from an IP address's
   dotted octets (`"127.0.0.1"` → `"127"`/`"0"`), probing real third-party S3/GCS/Azure buckets
   and confirming a false positive on VAmPI. Fixed: returns no seeds for an IP hostname.
3. `oracles/structural.py`'s response_body size cap crashed a live scan (crAPI's
   cache_poisoning driver) — the earlier MCP-boundary fix didn't cover in-process driver calls.
   Fixed at the real choke point: `StructuralEvidence.__post_init__` truncates at construction.
4. `scan/orchestrator.py::_dispatch_classes` had no exception handling — one driver crashing
   (bug #3) took the ENTIRE remaining scan down. Fixed: catch per-class, re-raise
   `ControlError`/`ScanCancelled` untouched, continue. Strictly improves on the existing
   per-specialist crash isolation from Build Order 2c.
5. `run_file_upload`'s `FILE_UPLOAD_BYPASS` check is pure status-code based; Juice Shop's
   permissive-CORS/catch-all backend answers 2xx for ANY made-up path, "confirming" 4 phantom
   upload bypasses at once. Fixed with a canary probe, same pattern as the existing
   `recon/calibration.py` wildcard guard.
6. The IP-address guard from bug #2 didn't survive a `host:port` hostname (crAPI's Host fact is
   `"127.0.0.1:8888"`) — `ipaddress.ip_address()` raises on a string with a port, silently
   defeating the guard. Fixed: strip a single unambiguous port suffix first.
7. **Diagnosed, deliberately not yet fixed**: DVWA's login succeeds but
   `identity/login.py::_extract_session_material` only recognizes a session cookie newly issued
   in the login response — DVWA sets its cookie on the pre-login page load and never rotates it,
   so the scan correctly detects login success but can't recognize the session as usable, and
   halts (`status: blocked`) rather than silently scanning unauthenticated. A real fix needs new
   `RequestFirer`/identity-layer API surface (security-sensitive session code) — not a rushed
   bolt-on. Next up.

Also found, self-inflicted and unrelated to product code: the first DVWA scan launch this
session called `/api/scan` directly with credentials only as free text in the `prompt` field,
never populating the structured `identities` field the scan actually consumes — so it scanned
fully unauthenticated. Fixed by relaunching with `identities` populated correctly.

## Round 3: Methodology section + live-surfacing LLM leads; two architecture asks declined

- Neither report path had a Methodology section. New `report/professional.py::methodology_markdown()`
  builds one deterministically from real scan facts (never LLM prose), appended verbatim to the
  LLM-authored report too. Self-caught: the new prose originally used the literal phrase
  "Suspected / Unconfirmed", colliding with 3 existing tests that partition the report on that
  exact string — fixed by rewording.
- `run_llm_vulnerability_review` now emits one event per lead (not a silent batch write) and
  runs twice per scan — early (after recon, before Phase 3) and final (after Phase 3, as
  before) — so Suspected leads appear live across the scan instead of all at once near the end.
- Two architecture-decision requests were declined with concrete reasoning, not built: dispatching
  LLM-proposed leads to the matching oracle-backed class driver for real confirmation (the
  operator explicitly said no to this one before it was built), and removing the oracle gate /
  rewriting the architecture around LLM-only detection. Every real bug found this session (7 of
  them) was only findable because a falsifiable oracle claim existed to violate.

## v3: the oracle gate is removed — operator's final, explicit decision (2026-09-02)

After extensive further discussion (concrete worked examples across all four proof mechanisms —
response diff, response marker, OOB callback, cross-identity access; a direct code walkthrough of
the real oracle logic; independent engagement with three alternative designs — LLM-as-oracle, a
second independent verifying agent, a multi-stage LLM pipeline), the operator made a final,
explicit decision: remove the deterministic `run_oracle` gate. CLAUDE.md rewritten to describe the
new model plainly (see its own "v3 architecture change" section). Implementation:

- New `oracles/llm_judgment.py::judge()` — takes the same evidence objects every driver already
  built, asks an LLM to decide one of the four real `FindingStatus` values, fail-closed to
  `INCONCLUSIVE` on any provider/parse failure. Wired into both live dispatch points:
  `tools/validator.py::run_oracle` (gained an optional `client=` for injection) and
  `detection/oracle_gateway.py::registry_runner` (the path most individual detectors actually use).
  Zero changes needed to any of the ~30 orchestrator drivers or detector modules — the swap
  happened entirely inside the one shared choke point each already called through.
- The six legacy family files' `decide()` functions (and helpers that existed only to serve them)
  are deleted; their evidence dataclasses are untouched (still load-bearing data carriers). Each
  `Oracle` subclass's `run()` now raises `NotImplementedError` rather than pretending to decide
  anything, since nothing on the live path calls it. Metadata auto-fill logic that used to live
  inside those `run()` methods (structural's header/body-projection snippet, timing's
  sample-array fill, OOB's channel fill) — genuinely separate from the decide() logic itself —
  was relocated into `llm_judgment.py::_enrich_metadata`, verified working end to end.
- ~150 hermetic tests across the whole repo (not just the six oracle files) called `run_oracle`/
  `registry_runner` with no injected client and broke when judgment correctly failed closed with
  no provider configured. Fixed via a new shared `tests/_oracle_test_support.py`
  (`fixed_oracle_runner`, `FixedJudgmentClient`) injected per-test — rewriting each test to verify
  detector/driver WIRING (given a fixed verdict, does the surrounding code react correctly)
  instead of the now-impossible-to-test fixed decision logic itself. One file needed a smarter
  fake (`test_attack_path_chaining.py`'s `_DifferentialJudge`, reproducing the exact old
  differential semantics) since it needed different verdicts for different oracle calls within one
  test run. Full suite: 1737 passed, 11 skipped (pre-existing infra-gated), 2 failed — both live
  integration gates (VAmPI/crAPI) that now correctly require a real configured LLM provider
  against live Docker infra to produce any confirmed findings; a disclosed, expected consequence
  of the decision, not a bug.
- Real, disclosed production cost: every confirmation is now a live LLM call — latency, money,
  and non-determinism where a fixed check used to be free and instant. The operator was told this
  plainly before building it.
- Not yet built (still in the v3 plan, V8): a genuinely sandboxed (container, never the
  operator's host) command-execution environment for the LLM — the one hard line already agreed
  on the separate "give it a free shell" request: real flexibility, contained blast radius.

## v3: first workstream implementations — V1 slices, V4, V7 shipped; V5/V8 deliberately
## deferred (2026-09-02)

Began implementing the v3 plan's V1-V8 workstreams individually, each committed and tested on
its own (per the plan's own "commit after each phase" convention added this session).

- **V1 (rich intent capture), partial**: `ScopeGuard.from_raw` parses each in/out-of-scope
  entry into a full `ScopeRule` (path_prefix/port/allowed_schemes, not just a bare host) — an
  operator can now write `target.test/admin` or `target.test:8080` directly in the
  confirmation card. Credential role is now a genuine free-form label end to end: the backend
  no longer forces a non-user/admin role down to "user", and the confirmation card's role field
  is a text input (with a user/admin datalist) instead of a `<select>` that structurally could
  only ever hold those two values — `identity/store.py`'s `Credential.role: str` always
  supported this; the bug was purely at the GUI/API boundary, fixed at both ends.
  **`skip_phases` investigated and found not honestly buildable as scoped**: recon and
  endpoint-mapping execute unconditionally before `AdaptiveControlState.skipped` is ever
  consulted (verified against the real control flow), so seeding it pre-scan would silently
  fail to skip exactly the phase most likely to be requested. Deferred alongside W4b rather
  than ship a feature that looks like it works but doesn't.
- **V4 (cross-host credential reuse) shipped in full**: `scan/cross_host_reuse.py` extracts
  high-confidence JSON-shaped credential pairs from any confirmed finding's own captured
  evidence and tries each once against every other in-scope host's login form (reusing
  `identity.login.detect_login_forms`/`submit_login`, the same mechanism
  `run_default_credentials` already uses on the primary host), writing a `credential_reuse`
  Finding on success. Confirmed via this session's own reference-project research that none of
  the seven projects studied does this either — a genuine differentiator.
- **V7 (multi-format report) closed**: PDF (WeasyPrint) and DOCX (html2docx — chosen over
  pypandoc specifically to avoid a system-binary dependency, even though pandoc happened to be
  available in this environment) both render FROM the existing self-contained HTML report
  rather than a separate template, matching the plan's "single source of truth" decision.
- **V5 (Burp Suite Pro MCP) and V8 (sandbox) deliberately NOT started**: Burp's MCP server,
  confirmed live earlier this session at `127.0.0.1:9876`, was no longer reachable when
  checked for this work (connection refused) — building against a dependency that can't be
  verified live would repeat the exact mistake this plan already flagged for the Caido/Strix
  proxy item. V8's network containment — scoping a sandboxed container's egress to only
  in-scope hosts, in a way a compromised/injected process can't simply bypass by ignoring a
  soft proxy env var — needs the same dedicated iptables/network-namespace verification rigor
  this session already reserved for other structurally risky changes (2c's prerequisite
  thread-safety research, W4b's deferral), not a bolt-on alongside command-execution plumbing.

## v3: nmap depth escalation — manual floor + autonomous LLM layer (2026-09-02)

Two independently-settable, validated nmap depth dimensions (`REACHAGENT_NMAP_WIDEN_PORTS`,
`REACHAGENT_NMAP_SCRIPT_CATEGORY`) replace what was initially built as a flat quick/full/
scripted enum. Two ways either gets set:

- **Manual floor**: the GUI's "Nmap recon depth" select, using the same os.environ
  tuning-flag mechanism every sibling opt-in layer (aggressive/surface_tuning/...) already
  uses — a pre-existing, disclosed concurrency limitation this doesn't newly introduce.
- **Autonomous layer** (new `recon/depth_escalation.py`, flag-gated
  `REACHAGENT_RECON_DEPTH_TUNING`, a new GUI checkbox): after nmap's first pass, an LLM
  reads the discovered Host facts and decides whether widening ports and/or an NSE script
  category is warranted, mirroring `signal_tuning.py`'s exact propose/validate shape.
  `apply_floor()` composes this with the manual floor: `widen_ports` is a monotonic OR;
  `script_category` is NOT linearly ordered, so an operator-required category is
  authoritative and the LLM may only add one the operator left unset, never substitute a
  different one for one the operator specifically asked for.
- Wired into `scan/entrypoint.py::scan_target`'s existing per-tool dispatch loop via a new
  `_maybe_escalate_nmap_depth` helper, only after nmap's live (non-fixture, non-dry-run)
  first pass — a second `runner.run()` call with the escalated env vars temporarily set and
  always restored (even on failure), fail-open throughout.

**Operator feedback mid-implementation, addressed directly and saved to memory**
(`feedback-operator-input-is-a-floor-not-ceiling`): the first cut shipped only the manual
GUI preset with no autonomous decision behind it — correctly called out as building the
passive "1%" (a setting the operator has to remember to flip) instead of the active "99%"
(the LLM deciding at scan time from live signals) the plan's own "LLM-controlled recon
depth" language actually called for. Also addressed: "give the LLM freedom to choose its
own flags" — real freedom, but bounded to a vetted-safe NSE category allowlist (`default`/
`discovery`/`version`/`vuln`/`safe`), independently re-validated in `nmap.py` itself
(defense in depth, not just the proposer) so a disruptive category (`intrusive`/`exploit`/
`dos`/`malware`/`brute`/`auth` — nmap's own docs describe these as capable of crashing,
locking out accounts, or actively exploiting a target) can never reach subprocess argv even
if proposed. Both readings — floor-not-ceiling, and bounded-not-arbitrary flag freedom — are
recorded as standing principles for every future v3 workstream, not just this one.

24 new tests across 3 files, all git-stash-verified. Verified live in a browser: both new
GUI controls render and wire correctly, zero console errors. Full recon+scan+gui suite: 150
passed.

**Follow-up shipped same day**: `preferred_wordlist` gained the analogous size/tech
dimensions for content-discovery tools (gobuster/ffuf/feroxbuster/dirb) —
`REACHAGENT_WORDLIST_SIZE` (small/medium/large, real vendored SecLists paths) and
`REACHAGENT_WORDLIST_TECH` (wordpress/joomla, keyed off the same fingerprint labels
`Host.technology` uses), wired as a GUI floor exactly like nmap's depth select. Disclosed
scope, matching nmap's own two-stage delivery: this is the resolver/floor half only: an
autonomous escalate-on-zero-results decision for wordlists remains a deferred follow-up.

## v3: V3 first slice — technique-diversity corroboration (2026-09-02)

Researched via a 5-agent workflow before writing any code, given this is the mechanism that
stands in for the removed oracle gate's own precision rigor: a call-site audit of every
`seam.run`/`run_oracle` invocation in `orchestrator.py` (classified into per-variant loops
already tried before judgment vs. genuine single-shot checks), a per-check-type
corroboration-action design across all 6 oracle families, a role-boundary feasibility check
against CLAUDE.md's own text, and a survey of hexstrike-ai/claude-bug-bounty for any
reusable bounded-loop control-flow shape.

**A real discovery revised the research's own first proposal before any code was written**:
a `confirmation/corroboration.py` module already existed (Build Order 5) — but reading it in
full showed it implements REPEAT-and-vote corroboration (re-run the IDENTICAL measurement N
times, majority agreement), scoped specifically for signal-noisy oracle families like
TIMING_STATISTICAL where network jitter/system load can tip one measurement. Its own
docstring explicitly argues a deterministic sentinel-in-body STRUCTURAL/DIFFERENTIAL check
gains nothing from a repeat, since it has no comparable flakiness — which reads, at first
glance, like it CONTRADICTS CLAUDE.md's own worked example ("read a target file... try
additional files to corroborate"). On closer reading, it doesn't: CLAUDE.md's example
describes trying a DIFFERENT file, not repeating the identical one — a different failure
mode entirely (ruling out a coincidental single-signal match, not measurement noise). Built
the missing complementary mechanism, `corroborate_with_variant()`, in the same module,
documented as addressing the OTHER failure mode, explicitly not competing with or replacing
the existing `corroborate()`.

**Also revised**: the research's synthesis proposed threading a new `corroborate` parameter
through the three shared call layers every driver goes through (`judge()` →
`validator.run_oracle` → `_ValidatorSeam.run`), which would have meant every one of the
~20+ existing single-shot call sites at least needing to reason about (even if not use) the
new parameter. Investigating the research's own recommended first slice — STRUCTURAL/
PATH_TRAVERSAL, matching CLAUDE.md's literal example — found it has ZERO production callers:
`pathtraversal/detector.py`'s `PathTraversalProber` is test-only; the actual live
path-traversal detection goes through a more indirect MCP `fire_ref`-resolution path via
`tools/payload_chain.py`/`mcp/server.py` that would need its own dedicated investigation.
Chose a cleaner, smaller-blast-radius design instead: corroboration lives entirely at the
DETECTOR level (the `*Prober` dataclass pattern every check-type already uses for hermetic
testability), never touching `judge()`/`run_oracle`/the shared `OracleRunner` Protocol at
all — generalizes one detector module at a time, with zero risk to the ~20+ untouched
single-shot call sites.

**Shipped, first slice**: `openredirect/detector.py`'s `OpenRedirectProber` gained optional
`fire_second_probe`/`second_param_name` fields (default `None`/`""` — omitting them keeps
today's exact single-probe behavior byte-for-byte unchanged). `detect_open_redirect`
corroborates a confirmed first probe against a SECOND, different redirect-shaped parameter
on the same endpoint (when one exists — most endpoints only have one, an honest disclosed
limit) before trusting it, failing closed (not-confirmed) rather than falling back to the
uncorroborated first result if the second parameter doesn't also reflect the attacker URL.
`scan/orchestrator.py::run_open_redirect` wires the second param through when present.

**Full per-check-type corroboration-action table** (from the research, recorded in the
living plan file to guide subsequent slices): STRUCTURAL has 11 check-types that genuinely
benefit (FILE_UPLOAD_BYPASS, PATH_TRAVERSAL, UNION_EXTRACTION, JWT_FORGERY, CORS_MISCONFIG,
OPEN_REDIRECT ✅ shipped, WEB_CACHE_POISONING, SSRF_RESPONSE, DEFAULT_CREDENTIALS,
RATE_LIMIT_ABSENT, CLOUD_BUCKET_EXPOSURE) and 6 that correctly stay single-stage
(CLICKJACKING, CSRF_MISSING_PROTECTION — read-only-first forbids a corroborating
state-changing fire — SUBDOMAIN_TAKEOVER, INFO_DISCLOSURE, KNOWN_VULNERABLE_VERSION,
PROTOTYPE_POLLUTION, all static-config/externally-established/logically-unambiguous facts a
refire proves nothing new about). All 5 DIFFERENTIAL expectations and all 4 BUSINESS_RULE
templates genuinely benefit. TIMING_STATISTICAL and OOB_CALLBACK were deliberately NOT
forced into this shape — they need a policy gate (corroborate only when marginal/high-severity,
or a channel-count/poll-window policy) rather than a plain second-probe, flagged as an
explicit follow-up. EXECUTION_CONFIRMATION: DOM XSS and Stored XSS benefit (a second
independent read rules out a stale marker or distinguishes "stored" from "merely reflected
in a save-confirmation page"); Reflected XSS stays single-stage (no persistence claim to
verify).

24 new tests across 3 files, all git-stash-verified. Full regression sweep (confirmation/
phase3/scan/report directories): 714 passed, 3 pre-existing infra-gated skips. CLAUDE.md
gained a one-line clarification that a corroboration probe is a driver-owned closure over
the already-scoped firer, never a firer living inside the oracle/judgment layer itself.

**Further slices, same day**: JWT_FORGERY (A1-loop, next-technique-must-also-confirm —
research-confirmed safe since all 4 forgery techniques are symptoms of one shared validator
flaw), CORS_MISCONFIG (second attacker origin), FILE_UPLOAD_BYPASS (second disguise
extension), WEB_CACHE_POISONING (third delayed re-read, with a monkeypatchable delay constant
so the test suite stays fast), and Stored XSS (second independent identity's read — flagged
"near-mandatory" since it's what actually distinguishes genuinely-stored from
reflected-in-a-confirmation-page). All git-stash-verified, all detector-level
`corroborate_with_variant`, no shared-layer changes.

**A real design mistake found and reverted before it ever reached a commit**: attempted the
SAME "next variant must also confirm" pattern on `run_nosqli`'s bypass-operator loop
(AUTH_BYPASS) — the existing regression test for a WAF that correctly blocks `$ne` but is
blind to `$gt` caught it immediately, since requiring a SECOND operator to also succeed turns
a realistic single-technique bypass into an unrealistic two-technique bar, suppressing the
true positive. JWT forgery techniques are different symptoms of ONE shared flaw; nosqli/ldap
operator variants are INDEPENDENT probes of a keyword blocklist — the analogy didn't hold.
Reverted in full via `git checkout` before committing.

**Two items deliberately skipped/deferred with reasoning, not silently dropped**:
PROBE_AUTHORIZED (graphql) — its own test shows the correct verdict for a public field is
`CONFIRMED_ALLOWED`, not a violation, so this branch essentially never writes a Finding;
corroborating it has no real security value. `_reconfirm_sqli` (DATABASE_ERROR) — it only
builds evidence; judgment happens in a shared `reconfirm_candidate()` used by 5 different
vuln classes, a materially bigger/riskier change than every driver-calls-`seam.run`-directly
slice shipped so far — deferred for a dedicated session, not rushed.

**Operator instruction, same day**: eval-target Docker containers (VAmPI/crAPI/Juice Shop/
DVWA) are on-demand only — bring up only what a live task needs, tear down right after. Found
all three running idle mid-session with nothing in the (hermetic) work using them; stopped
them.

**Second slice, same day: DIFFERENTIAL/PROBE_UNAUTHORIZED (BOLA/IDOR)** — the highest-value
next target per the research's own table, given how central authorization findings are to
this project's positioning. `bola/idor_detector.py`'s `IdorProber` gained the same optional
`fire_second_probe` pattern as `open_redirect`: when a THIRD identity is configured (beyond
the owner and first non-owner), a confirmed cross-user write is corroborated against that
third identity's own write against the same object before being trusted — ruling out the
first non-owner session having its own unrelated delegated/shared access rather than a
systemic flaw. Deliberately conservative given this driver's own docstring calls it "the
single most invasive action this project ever takes": the second write fires lazily, only if
the primary already looks like a violation, and no new opt-in flag was added — this is a
strictly-improving refinement within the existing `allow_cross_user_writes` gate, not a new
invasive capability. 13 new tests (8 detector-level, 1 orchestrator wiring test that
deliberately doesn't hardcode which non-owner identity ends up "first" vs. "corroborating",
since `auth_ok` is a set with no guaranteed iteration order), git-stash-verified. Full sweep
(phase2/scan/confirmation): 134 passed.

## v3: V3 8th slice — RATE_LIMIT_ABSENT corroboration, opt-in (2026-09-02)

Operator instruction: "push into RATE_LIMIT_ABSENT next, scoped carefully with the opt-in
gate." Same `corroborate_with_variant` shape as every other slice — `rate_limit/detector.py`'s
`RateLimitProber` gains an optional `fire_second_attempt`; a confirmed first bounded burst (6
wrong-credential attempts) is corroborated against a second, independent burst after a real
30s cooldown (`_COOLDOWN_S`, monkeypatchable for tests) — but this is the ONE slice in the
sweep that does NOT corroborate unconditionally once wired.

**The real difference**: doubling live wrong-credential attempts against a real login endpoint
carries a genuine self-inflicted lockout/DoS risk against the scan's own traffic, unlike every
other slice's read-only or idempotent-write re-probe. `scan/orchestrator.py::run_rate_limit_absence`
gates the second burst behind a new `REACHAGENT_RATE_LIMIT_CORROBORATION=1` flag (GUI checkbox
"Rate-limit corroboration", off by default — every other opt-in tuning flag in this codebase
gets one, so this does too). A second safety check runs even with the flag on: if the fixed
probe username (`"ra-probe-user"`) collides with any real seeded identity's own login username,
corroboration is silently skipped rather than firing wrong-password attempts at what might be a
real account.

12 new tests across 3 files (detector-level sequenced-verdict corroboration incl. "second burst
never fires when the primary doesn't confirm" and "flag off is byte-for-byte unchanged",
orchestrator-level wiring incl. the collision-safety check, GUI env-override wiring), all
git-stash-verified. Full local suite green: 684 passed, 3 skipped (Docker-gated, expected).

Remaining v3 V3 candidates unchanged from the prior pause note: DEFAULT_CREDENTIALS/
CLOUD_BUCKET_EXPOSURE (same opt-in-decision care as this slice), DOM XSS (real browser
lifecycle per probe), `_reconfirm_sqli`/BUSINESS_RULE (shared generic-dispatch-loop
architecture needs restructuring first).

## v3: V3 9th slice — CLOUD_BUCKET_EXPOSURE corroboration, no opt-in needed (2026-09-02)

Read the actual driver/detector code for both remaining opt-in-flagged candidates before
proceeding — the two turned out to need genuinely different treatment. **CLOUD_BUCKET_EXPOSURE
ships default-on**: every candidate bucket URL is an independent third-party resource
(S3/GCS/Azure), so "try a different candidate" proves nothing about the original finding, but a
DELAYED RE-READ of the SAME confirmed URL is a safe corroboration ruling out a transient
exposure window — the exact shape `cachepoisoning/detector.py` already uses for
WEB_CACHE_POISONING. `cloud_bucket/detector.py`'s `BucketProber` gains an optional
`fire_delayed_reread`; a confirmed exposure is corroborated via `corroborate_with_variant`
against a re-read of the same url after a real 2s delay (`_CLOUD_BUCKET_REREAD_DELAY_S`,
monkeypatchable). No opt-in flag: every probe is read-only against a third party, never
doubling load on the scanned target — none of RATE_LIMIT_ABSENT's self-inflicted-DoS risk.
One refinement beyond the cache-poisoning precedent: since this detector loops over MANY
independent candidates (not one fixed URL), a corroboration failure on one candidate doesn't
abort the search — the loop moves on, since a different bucket being genuinely exposed is a
separate question from whether THIS one merely flapped. 6 new tests, git-stash-verified.

**DEFAULT_CREDENTIALS deliberately deferred, not built** — it needs the SAME inverted-polarity
corroboration design already flagged (and deferred) for nosqli/ldap's baseline recheck, not
the "next variant must also confirm" shape: different default-credential pairs are INDEPENDENT
probes (a target may have exactly one working seeded account), so requiring a second pair to
also succeed would repeat the exact AUTH_BYPASS mistake already made and reverted this session.
The only safe shape is trying a deliberately-wrong pair afterward and expecting REFUSAL — left
for a dedicated pass given the plan's own standing caution that this polarity is "genuinely
more bug-prone."

## v3: V3 10th slice — DOM XSS corroboration, "materially heavier" reassessed and built
## (2026-09-02)

The original sweep note deferred DOM XSS as "materially heavier — full Chromium lifecycle per
probe." Reading the actual code found the concern is real but narrow (wall-clock cost, not a
safety/precision risk) and, like every other slice, the second navigation only ever fires on an
already-confirmed candidate — the same bounded-cost discipline every prior slice already
follows. Built it: `scan/xss_dom.py::run_xss_dom` predates `xss/detector.py`'s injectable
`XssProber` pattern (drives Playwright directly, dispatches the oracle inline, and had ZERO
existing test coverage before this change) — rather than refactoring it onto that pattern first,
the corroboration was wired directly in, following the same `corroborate_with_variant` shape: a
confirmed flow triggers a second, independent navigation to the same URL (through the same
`TransportDispatcher.prepare_browser`/`record_browser` audit pair the primary navigation uses),
and only a flow that reproduces is trusted. Wrote the first dedicated test file for this driver
(`tests/scan/test_xss_dom_driver.py`, 5 tests), reusing `test_prototype_pollution.py`'s own
Playwright-mocking pattern rather than inventing a new one. All git-stash-verified. Full suite
green: 778 passed, 3 skipped (Docker-gated).

This closes out every remaining v3 V3 candidate that fit a driver-calls-oracle-directly shape.
What's left — DEFAULT_CREDENTIALS (inverted-polarity design), `_reconfirm_sqli`/DATABASE_ERROR
and BUSINESS_RULE (shared generic-dispatch-loop architecture) — all genuinely need their own
dedicated restructuring session, not a pattern-match to an already-shipped slice.

## v3: V3 11th and final tractable slice — DEFAULT_CREDENTIALS inverted-polarity
## corroboration (2026-09-02)

Revisited once the sweep ran out of clean pattern-matched candidates — the design had been
fully specified when originally deferred, the only open question was rigor, not feasibility.
New shared primitive `confirmation/corroboration.py::corroborate_by_refutation` (the third
alongside `corroborate` and `corroborate_with_variant`): fires a control probe only when the
primary confirmed, and `corroborated = NOT refutation_verdict.is_violation` — a control probe
DELIBERATELY built to fail, whose expected refusal (not another success) is what corroborates.
`default_creds/detector.py::detect_default_credentials` gains optional
`refutation_credential`; once a real pair confirms, the SAME `attempt_login` callback tries one
deliberately-wrong, never-allowlisted pair — its own raise/return contract already IS the
verdict (`LoginError` = correctly refused = corroborates; an unexpected captured session or a
transport error = ambiguous = fails closed), no new oracle round-trip needed.
`scan/orchestrator.py::run_default_credentials` wires a fixed control pair with the same
collision-safety check as RATE_LIMIT_ABSENT (skip if it matches a real seeded identity's
username). No opt-in flag: this adds exactly ONE more login attempt on top of the existing,
unchanged, already-bounded primary loop (5 attempts) — a materially smaller addition than
RATE_LIMIT_ABSENT's doubled full burst, and the same "one more probe on an already-confirmed
positive" shape every other default-on slice already uses. 14 new tests (6 for the new
primitive, 5 detector-level, 3 orchestrator-level), all git-stash-verified.

**Update, same day, operator instruction "continue with next phases": `_reconfirm_sqli`
shipped too.** The architectural concern (a shared `reconfirm_candidate()` used by 5 vuln
classes) was real but narrower than first assessed — reading the actual function found a
small, additive fix: `reconfirm_candidate()` gained one optional `second_attempt` parameter
(called via the existing `corroborate_with_variant` only once the primary confirms), and
corroboration metadata is stamped by mutating the `Finding` the caller's `finding_factory`
already built rather than changing that factory's own call signature — so the other 4 classes
(jwt_forgery, xss_reflected, command_injection, information_exposure) needed zero changes.
`_reconfirm_sqli` now returns `(evidence, second_attempt)` instead of bare evidence; the
closure injects a double-quote probe (vs. the primary's single quote) at the same parameter —
the VARY shape (like JWT_FORGERY), not the AUTH_BYPASS trap, since an unsanitized SQL
concatenation doesn't discriminate between quote styles. A real test-authoring bug was caught
and fixed along the way (not a production bug): the first version of the corroboration test's
fake oracle client checked for a real `_SQL_ERROR_SIGNATURES` string that's ALWAYS present in
every `DifferentialEvidence`'s own JSON dump (it's a config field, not response content),
making the fake client confirm unconditionally — caught by the "fails closed" test failing,
fixed with a synthetic marker instead. 3 new tests, git-stash-verified against the real
production reconfirm path end to end.

**This closes 12 of the v3 V3 sweep's candidates.** BUSINESS_RULE's 4 templates were
investigated too and found to have TWO distinct, real safety concerns, not just generic
restructuring difficulty: (1) "vary the violating value" (a second out-of-bounds
quantity/price) is AUTH_BYPASS-unsafe here — unlike JWT_FORGERY's shared-flaw symptoms or
`_reconfirm_sqli`'s quote-style variants, real apps plausibly validate negative-quantity and
absurd-quantity abuse via INDEPENDENT checks, so requiring both to succeed would repeat the
exact AUTH_BYPASS mistake already reverted; (2) "repeat the same replay" (the DIFFERENTIAL
family's own established safe shape) needs a SECOND IDENTITY's fresh session to avoid
colliding with the target's own resource-consumption state (a repeated order/coupon replay
under the SAME identity risks a false non-corroboration) — but `run_business_logic` has no
`identities` parameter at all today, unlike every other slice that needed one. Deferred with
this precise reasoning, not generic reluctance — a future session should thread `identities`
through first, then build second-identity repeat-and-vote corroboration, and explicitly avoid
the vary-the-value approach.

**The v3 V3 corroboration sweep is now complete as far as it can honestly go**: 12 slices
shipped, 1 precisely-diagnosed-and-deferred (BUSINESS_RULE).

## Next-phase audit + first two items shipped (2026-09-03)

Operator: "continue with next phases." Ran a 6-agent background audit before picking anything,
since the plan's own "Implementation status" tracker had already proven stale (V4/V2 shipped
later but never marked; V7's PDF/DOCX export turned out already fully wired). Findings: V1's
scope-narrowing and credential-role-fidelity pieces are already shipped (contrary to plan
framing); V5 (Burp MCP) has no live instance right now (verified fresh via curl — connection
refused) and zero wiring code, so it stays excluded; V6's "chain-of-custody view" line item is
also already shipped; V7's format export is done but 4 content fields (CVSS vector, CWE, Steps
to Reproduce, PoC) are genuinely missing; all 5 known tail items (W4b, freeform payloads, live
proxy, response-content-aware review, Exploit-DB/PoC) reconfirmed still open, with wordlist
depth escalation the one genuinely small, safely-buildable exception.

Shipped, in order: (1) **CWE-id lookup** — a `_CWE` table in `report/professional.py`, same
honesty discipline as the existing `_WSTG` table (real MITRE ids only, generic fallback for the
few uncertain classes), threaded through `vuln_class_context` so report and GUI both render it;
5 new tests. (2) **Autonomous wordlist escalation** — the disclosed V2 follow-up
(`_wordlist.py`'s own docstring flagged this as deferred): new `recon/wordlist_escalation.py`
mirrors `depth_escalation.py`'s nmap pattern, with one real design difference — wordlist size is
linearly ordered so its floor logic is OR/max-like, while the tech hint stays
authoritative-override like nmap's script category. Wired into `entrypoint.py` for any
content-discovery tool yielding zero endpoints, not just nmap-specific; new GUI opt-in
checkbox. 26 new tests. (3) **Confirmation-card scope textarea** — `cc-scope`/`cc-outscope`
swap `<input>` for `<textarea>`; `ScopeGuard.from_raw` now splits on commas OR newlines so the
taller box's natural one-per-line input actually parses. Verified live via Playwright. (4) **Stop
over-truncating the operator's objective** — a full grep found 13 sites (not just the one the
audit flagged) sharing an identical `operator_prompt[:500]` cap; bumped all uniformly to 2000
characters. (5) **skip_tools intake** — the audit had flagged this as "unverified feasibility";
checked the actual dispatch loop first and found `initial_names`/`candidate_names` (unlike
`skip_phases`) IS the very first point any recon tool name is considered, so filtering both at
that point is safe with no "already ran before the check" hole. Wired end to end: `scan_target`
param → `scan_all_classes` passthrough → GUI intent extraction + confirmation-card field +
`/api/scan` parsing. Also fixed `_INTENT_PROMPT`'s "goal" field to stop force-compressing a rich
objective to one sentence, the original V1 complaint. Disclosed limit: recon tools only, not
signal-gated tools (different dispatch path). All five git-stash-verified; item 4's full-suite
sweep (1765 passed) and item 5's (835 passed) given how many files each touched.
