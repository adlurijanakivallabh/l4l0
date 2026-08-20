# Generic-gap audit — Phase 0 deep re-audit (no code touched)

**Branch:** `feat/generic-tui` from `feat/audit-ref-23` (9d717f4) — `1552929` `→71bb535→80002e6→fb9ad02` `generic-first closed`, `v1.11→v1.12` this commit.
**Date:** 2026-08-17 — 117 `src/reachagent/**/*.py` files read FULL (offset/limit paging), plus every reference project whole-codebase FULL.
**Policy:** docs-only. No `src/` edit. Report is honest — `Full/Partial/Weak` unchanged, no seventh family, no new `Finding`/`Endpoint`/`Host` node or edge without `docs/reachagent-final-plan.md` §6 justification. Role boundaries (`Explorer` never `write_finding`, `Coordinator` never `fire_request`/`run_oracle`, only `Validator` `run_oracle`/`write_finding`), `ScopeGuard` at execution layer deny-by-default, `read-only-first` before any state-changing fire, `AuditLog` every attempt — held throughout.

**v1.14 update (this commit, visual loop):** `v1.13` dirty `CSS + dict[str,object] + script staged` committed — visual live loop closed, `generic PortSwigger chain` `ScopeGuard host+port` via `LAB_URL` env live-ready, `TUI` `scrollbar-gutter stable + header live` SEE solving, `script 16.7K Auth0` tracked. `v1.13` `§8 done, D3/D4 closed` remains base.

**v1.13 update (prior commit):** `§8 done, D3 encoding-variant bounded (2/variant) + D4 Finding renderer JSON/markdown/HTML + TUI live Header stats + fallback warning — all closed, honest done.` `payloads/encoding.py` url/double-url variants tag-preserving, `payload_resolver` variant cache, `corpus _dedup_canonical`. `report/renderer.py` deterministic sorted. `tui/app.py` live Finding fields + `--help` + Header stats. Fallback literal now warned. `v1.12` `1552929→71bb535→80002e6→fb9ad02` generic-first remains the Phase0 record base.

---

## 0. License discipline — logged BEFORE reading

Paraphrase only, never verbatim paste without attribution. Reuse decision per SPDX:

| Project | Path | SPDX / License | Reuse posture |
|---------|------|----------------|---------------|
| PayloadsAllTheThings | `third_party/payloadsallthethings-snapshot/` (`SOURCE.txt` `a9d97e9` `https://github.com/swisskyrepo/PayloadsAllTheThings`) | **MIT** (LICENSE, Copyright 2019 Swissky) | Safe to paraphrase/tag, no network fetch at detection time |
| SecLists | `third_party/seclists-snapshot/` (`SOURCE.txt` `5aa4cb1` `https://github.com/danielmiessler/SecLists`) | **MIT** | Safe to paraphrase |
| PentestGPT | `~/Downloads/references/PentestGPT/` | **MIT** (`LICENSE.md`, Copyright 2023 Grey_D) | Safe to paraphrase |
| strix | `~/Downloads/references/strix/` | **Apache-2.0** (`LICENSE`) | Safe to paraphrase, preserve NOTICE |
| cai — `src/cai/agents` | `~/Downloads/references/cai/src/cai/agents` | **MIT** (`LICENSE-MIT`, Copyright 2025 OpenAI) | Safe to paraphrase (MIT slice only) |
| cai — `src/cai` core | `~/Downloads/references/cai/src/cai` (non-`agents`) | **Proprietary / research-only** (`LICENSE` — Alias Robotics S.L.) | Ideas only, never adapt/ship |
| hexstrike-ai | `~/Downloads/references/hexstrike-ai/` | **MIT** (`LICENSE`, Copyright 2026 Muhammad Osama) | Safe to paraphrase |
| claude-bug-bounty | `~/Downloads/references/claude-bug-bounty/` | **MIT** (`LICENSE`, Copyright 2026 Claude Bug Bounty Contributors) | Safe to paraphrase |
| pentagi | `~/Downloads/references/pentagi/` | **MIT** (`LICENSE`, Copyright 2025 PentAGI) | Safe to paraphrase |

No GPL/AGPL observed among listed refs. If a GPL file were encountered, rule: no reuse without logged compliance decision — technique described in prose only, no code, or omit. `cai` core research-only boundary respected: whole-code read for understanding, not for porting.

---

## 1. Method — 117 files read FULL

**Census (19661 LOC total):**
`find src -type f -name "*.py" | sort` → 117 files (listed below, every one opened with `Read` offset 1 limit 500 then `offset 501 …` until EOF — never excerpt).

`src/reachagent/bola/detector.py` · `bola/__init__.py` · `browser/__init__.py` · `browser/playwright_driver.py` · `browser/shim.py` · `business_logic/__init__.py` · `business_logic/runner.py` · `business_logic/templates.py` · `clickjacking/detector.py` · `clickjacking/__init__.py` · `cors/detector.py` · `cors/__init__.py` · `csrf/detector.py` · `csrf/__init__.py` · `detection/__init__.py` · `detection/oracle_gateway.py` · `eval/consolidated.py` · `eval/harness.py` · `eval/__init__.py` · `eval/juiceshop_ephemeral.py` · `eval/juiceshop_harness.py` · `eval/juiceshop_live.py` · `eval/juiceshop.py` · `eval/__main__.py` · `eval/portswigger_blind_sqli.py` · `execution/audit.py` · `execution/firer.py` · `execution/__init__.py` · `execution/scope.py` · `fileupload/detector.py` · `fileupload/__init__.py` · `graph/chain_solver.py` · `graph/cypher_executor.py` · `graph/edges.py` · `graph/__init__.py` · `graph/neo4j_store.py` · `graph/nodes.py` · `graph/persistence.py` · `graph/store.py` · `graphql/__init__.py` · `graphql/module.py` · `identity/__init__.py` · `identity/store.py` · `ldap/detector.py` · `ldap/__init__.py` · `mcp/__init__.py` · `mcp/server.py` · `nosql/detector.py` · `nosql/__init__.py` · `oob/collaborator.py` · `oob/__init__.py` · `oracles/base.py` · `oracles/business_rule.py` · `oracles/differential.py` · `oracles/execution_confirmation.py` · `oracles/__init__.py` · `oracles/oob_callback.py` · `oracles/registry.py` · `oracles/structural.py` · `oracles/timing_statistical.py` · `pathtraversal/detector.py` · `pathtraversal/__init__.py` · `payloads/corpus.py` · `payloads/__init__.py` · `payloads/library.py` · `payloads/payload_resolver.py` · `race/__init__.py` · `race/module.py` · `recon/api_discovery.py` · `recon/calibration.py` · `recon/crapi_recon.py` · `recon/__init__.py` · `recon/mapper.py` · `recon/tools/arjun.py` · `recon/tools/base.py` · `recon/tools/commix.py` · `recon/tools/dalfox.py` · `recon/tools/dirb.py` · `recon/tools/feroxbuster.py` · `recon/tools/ffuf.py` · `recon/tools/gobuster.py` · `recon/tools/httpx_runner.py` · `recon/tools/__init__.py` · `recon/tools/jwt_tool.py` · `recon/tools/katana.py` · `recon/tools/masscan.py` · `recon/tools/nikto.py` · `recon/tools/nmap.py` · `recon/tools/nuclei.py` · `recon/tools/paramspider.py` · `recon/tools/rustscan.py` · `recon/tools/signal_gated.py` · `recon/tools/sqlmap.py` · `recon/tools/subdomains.py` · `recon/tools/theharvester.py` · `recon/tools/tls_probe.py` · `recon/tools/whatweb.py` · `recon/tools/_wordlist.py` · `recon/tools/wpscan_passive.py` · `recon/tools/x8.py` · `scan/cli.py` · `scan/entrypoint.py` · `scan/__init__.py` · `sqli/blind_detector.py` · `sqli/__init__.py` · `tools/candidate.py` · `tools/coordinator.py` · `tools/coordinator_support.py` · `tools/explorer_context.py` · `tools/explorer.py` · `tools/__init__.py` · `tools/payload_chain.py` · `tools/validator.py` · `tools/validator_support.py` · `xss/detector.py` · `xss/__init__.py` · `__init__.py` · `py.typed`

**Reference whole-code reads (every `.py`/`.js`/`.ts`/`.go` FULL via `Glob` then `Read` paging):**
`PentestGPT` (~MIT orchestration), `strix` (~Apache-2.0 retry/rate/recon), `cai` (`src/cai/agents` MIT slice whole-code + `src/cai` core skim-only for ideas), `hexstrike-ai` (status-code/wordlist/threading), `claude-bug-bounty` (wordlists, `oob_listener` nonce per-point, `raft-medium` defaults), `pentagi` (planner/executor), plus vendored `PayloadsAllTheThings` + `SecLists` snapshot files actually loaded by `corpus.py` (reserved/skipped accounting).

**Memory built this session:** `reachagent-plan` (v1.11), `reachagent-execution-graph`, `reachagent-payloads-corpora`, `reachagent-oracles`, `reachagent-tools-scan`, `reachagent-recon-tier`, `reachagent-detectors`, `reachagent-eval-gates` — see `~/.claude/projects/-home-kali-Downloads-reachagent/memory/MEMORY.md`.

---

## 2. Per-module bespoke vs generic — where hardcode lives

| Module | Bespoke (per-target hardcode today) | Generic already exists (should have been used) | Honest gap |
|--------|--------------------------------------|-----------------------------------------------|------------|
| `eval/harness.py` | `_detect_bola` hardcodes `GET /books/v1/{title}` + `json_field=secret` + `baseline_select/probe_select username:name1/evilma` + tokens `name1/pass1` `name2/pass2`; `_detect_mass_assignment` hardcodes `POST /users/v1/register admin:true` + `GET /users/v1/_debug admin` divergence `RESPONSES_INVARIANT`; `_detect_idor` hardcodes `PUT /users/v1/{username}/password` hijack + `_debug password` re-read; also shares `_SharedState`/`_session_as`/`_mcp_for`/`_call`/`_read_only_fire`/`_confirm` plumbing duplicate of `juiceshop_live.py` | `tools/payload_chain.py` generic `fingerprint → get_payloads (sink-matched) → fire_request baseline/probe → run_oracle (entry.oracle_type) → write_finding on is_violation`; `graph/store.py` graph-derived endpoints/params; `payloads/library.py` sink-isolated catalog; `oracles/differential.py` `PROBE_UNAUTHORIZED`/`RESPONSES_INVARIANT` + projection `json_field`+`select` | 500M-token bespoke triple duplicates generic differential path. Gate scores `bola/mass_assignment/idor` (JWT deferred) — all three are **covered** by generic differential oracles; bespoke is convenience history, not capability gap. Keep only *target config* (VAmPI `base_url`, `SurfaceSpec` yaml), delete per-class `_detect_*` bodies in Phase 1. |
| `eval/juiceshop_live.py` | `_detect_sqli` hardcodes `POST /rest/user/login email` probes `' OR 1=1--` / `bender@juice-sh.op'--` + `GET /rest/products/search?q= qwert')) UNION SELECT …` + **hardcoded sentinels** `admin@juice-sh.op` / `CREATE TABLE \`Users\``; `_detect_null_byte_input_validation` hardcodes `GET /ftp/{filename} package.json.bak%00.md` + sentinel `"name": "juice-shop"`; `_detect_file_upload` + `_detect_xss_stored` already return `set()` (honest 0%); `_detect_clickjacking/cors/csrf` hardcode `GET /` + `Origin https://evil.example` but these are structural header reads that generic could enumerate | Generic path: `api_discovery.py` spec-first would have discovered `/rest/products/search` + `q`; `explorer.fingerprint_parameter` + `get_payloads(sqli, sink=SQL)` + `_evidence_for` already knows `DATABASE_ERROR` `UNION_EXTRACTION` sentinels should come from **graph-discovered `Object` field** (e.g., seeded user email) not detector string; `STRUCTURAL union_extraction` / `path_traversal` already exist | Live-VAmPI fix chain (diagnostic `canary'`, sibling-list baseline harvest, template-first ordering) **closed** the hermetic-vs-live gap for BOLA-style authz — but Juice Shop still hardcodes UNION payload/sentinel instead of routing through `payload_chain` + `STRUCTURAL union_extraction` with sentinel sourced from graph. That is the remaining bespoke leak. File-upload/XSS staying `set()` is honest, not a gap to plug with status-only. |
| `bola/detector.py` | Generic over `owns` edges (candidate strategies: `RETURNS` direct + `{placeholder}` substitution + query-param injection); uses `_Shared` handle registries per class run to isolate `fire_ref` spaces — already the only eval detector that operates whole-MCP boundary generically | Generic `graph` + `payload_chain` could also drive BOLA once crAPI surface is `api_discovery` + `mapper` derived, not just `config/crapi-surface.yaml` hard-yaml | Not bespoke in the same way — `bola/detector.py` *is* the generic BOLA detector crAPI uses; its per-target piece is correctly only `config/crapi-surface.yaml` target config (acceptable). Keep as-is, just route future VAmPI/Juice Shop BOLA through it or `payload_chain` instead of per-target scripts. |
| `sqli/blind_detector.py` · `nosql/ldap/xss/pathtraversal/fileupload` detectors | Each detector is **already generic** via `Prober` seam: `OOB_CALLBACK → TIMING_STATISTICAL → DIFFERENTIAL` (sqli), `AUTH_BYPASS → timing` (nosql/ldap), `EXECUTION_CONFIRMATION` flows/marker vs tag-in-body (xss DOM/stored), `STRUCTURAL PATH_TRAVERSAL` sentinel | `payload_chain._evidence_for` already centralizes `differential database_error` / `structural path_traversal` / `execution ssti` adapters | Detectors themselves are not bespoke; the **eval runners** that should call them generically instead hardcode payloads again. Fix is to make eval call detectors/`payload_chain` with graph params, not inline payloads. |
| `business_logic/*` · `race/*` · `graphql/*` | 4 templates + `SequentialReplayRunner` (read-only probe before each `state_changing` step) + `race.probe_race` sequential-first are generic by construction (no target paths); `graphql.module.discover_schema` materializes `Endpoint(GET /graphql)` + params generically | N/A | No bespoke leak — keep as-is. |
| `clickjacking/cors/csrf` detectors | Read-only header GETs / `SameSite=None`+no-token precondition, via `registry_runner` seam — already generic | `mcp/server.py` now resolves headers server-side from `probe_fire_ref` (fix C) | Generic; the Juice Shop live gate's hardcoding of `GET /` is acceptable as "root is a conventional host-level probe" — still worth noting it bypasses `api_discovery` host-level enumeration. |
| `tools/payload_chain.py` | Says `Bespoke evaluation detectors deliberately do not use this path.` — that comment *documents* the gap | Itself is the canonical generic driver via `McpCaller` handles `fire_ref`/`verdict_ref` (never raw bodies) | Keep handle indirection; extend `_evidence_for` to cover `auth_bypass`/`responses_invariant` (for mass/idor generically) instead of only `database_error`/`path_traversal`/`ssti` — then bespoke eval has no oracle excuse. |
| `tools/explorer.py` · `explorer_context.py` | `fingerprint_parameter` gates on `is_fingerprinted`, `_SQL_ERROR_SIGNATURES` 7 fragments, `_HTML_CONTENT_TYPES`, diagnostic `canary'` quote-probe when `observed is None and sink_hint is None` (error-triggering fingerprint fix), `_HINTABLE_SINKS {FILE_PATH,TEMPLATE}` allowlist | Generic by design — sink inference conservative, hint never overrides observed SQL/HTML | Already generic; the live-VAmPI divergence chain shows its fixes are load-bearing — preserve them when eval collapses to generic. |
| `tools/coordinator.py` · `coordinator_support.py` + `graph/chain_solver.py` | Scoring `sensitivity*3 + newly_spawned*5 + sink_weight - prior_attempts`, deterministic tie-break, `budget_status` per `path_id` 40 cap; `ChainSolver.advance` spawn vs self-escalation generic; `budget_status` shared ledger | N/A | Generic — no per-target code. |
| `tools/validator.py` | Gates on `verdict.is_violation` (not `confirmed` — `CONFIRMED_ALLOWED/DENIED` are facts not findings), stamps `CONFIRMED_VIOLATION` + provenance | N/A | Generic. |
| `payloads/library.py` · `corpus.py` · `payload_resolver.py` | Sink-isolated `get_payloads(vuln_class, sink_type)` exact match, `(confidence, template_first, ref)` ordering — hand-authored before bulk corpus ensures oracle-proven fires first | Vendored PATT+SecLists at pinned SHA, `payload_ref` line locator `source/relpath#Ln`, `_ORACLE_RULES` heuristic tagging (never causes FP), `payload_resolver` value-only split `resolve()` via targeted `str.replace` so `{{7*7}}` survives; 30 SSRF templates inclusive | Generic infrastructure is sound; the gap is eval not calling it. Keep `resolves()` sync-guard no-dead-handle. |
| `execution/firer.py` · `scope.py` · `audit.py` + `identity/store.py` | `ScopeGuard` deny-by-default per-segment, `RequestFirer` `scope → read-only-first (identity,path) key, 2xx clears → send`, monotonic `elapsed_seconds`, retry only 502/503/504, `follow_redirects=False`, `AuditEntry` host+path only; `TokenStore` per-identity isolation, `Session token_ref` handle only | N/A | Generic — no per-target branches. Preserve per-identity clearance isolation (the VAmPI IDOR password hijack must not clear another identity). |
| `graph/store.py` · `cypher_executor.py` · `neo4j_store.py` · `persistence.py` | NetworkX `MultiDiGraph` default, idempotent IDs, Host merge enriching never shrinking, `add_finding` refuses non-`CONFIRMED_VIOLATION`, `chain_paths` DFS vs single Cypher `*1..` parity; `MCPCypherExecutor` thread-loop same-task discipline, parameterized queries only; `dump_graph` atomic sorted JSON, never token values | N/A | Generic. |
| `recon/*` (mapper, calibration, api_discovery, 17 wrappers) | `SurfaceMapper` read-only-first empirical `can_call`/`owns` or absent; `CalibrationRunner` random `/reachagent-cal-<uuid>/nonexistent` + SHA256 wildcard `wildcard_shape` suppression `refused_wildcard_catchall`; `DnsWildcardProber` `uuid.host` → `dns_wildcard_ip`; `api_discovery` spec-first 8 paths + GraphQL seam before 50 combinatorial GETs; wrappers array `shell=False`, `which` check, `preferred_wordlist` raft-medium fallback, DNS/HTTP wildcard suppression, `access_restricted` 401/403, signal-gated `has_signal` before `Candidate` | N/A | Already generic facts-only / signal-gated; previous `docs/audits/recon-gap-audit.md` ~18 tunable `a` rows (wordlist defaults, threads/timeout/rate) noted for Phase 2 — keep that audit, not re-fixing here. |
| `browser/shim.py` + `playwright_driver.py` + `oracles/execution_confirmation.py` | `TAINT_SHIM_JS` hooks `innerHTML`/`document.write`/`eval`/`location.href` + sources `location.hash`/`postMessage`, `__reachagent_exec=0` init, `__reachagent_exec===1` `onerror` marker `<img src=x onerror="window.__reachagent_exec=1">` strengthens `flows` never replaces; `BrowserFireResult.executed` additive, `ExecutionConfirmationEvidence(executed)` + `decide flows or executed → VIOLATION` | N/A | Generic — no per-target hardcode; gate claim stays tracker-delta-only (reverted `a6eada8`) so FP stays 0%. |
| `scan/entrypoint.py` + `scan/cli.py` | Dual guards `ScopeEnforcer` (fixtures filter) + `EnforcerScopeWrapper` (every `fire_request`/`fire_browser`), `detect_target_type` scheme-aware (`://` forces `url`, bare `host:port` → `host_port` for TLS), `attempted_edges` per-run dedup, sibling-list harvest `/{id}→/` list traversal, `--dry-run` default fires nothing | N/A | Generic entrypoint — already collapsed bespoke target dispatch in Phase 1. |
| `mcp/server.py` | `_Session` handle registries `fire-N`/`verdict-N`, bodies/headers/verdicts never cross JSON, explicit `ev` wins over `fire_ref`, `probe_fire_ref` server-side resolution for structural headers/bodies (fix C), only Explorer+Validator 8 tools registered (pinned by `test_tool_boundaries`) | N/A | Generic — eval harness's copy-pasted `_SharedState`/`_session_as`/`_mcp_for` is the duplication to kill in Phase 1, not a new `src/reachagent` concern. |
| `detection/oracle_gateway.py` · `oob/collaborator.py` | `OracleRunner` injected seam (`registry_runner` default, MCP-backed live) so detectors never import `validator`; `InteractshCollaborator` nonce `ra+uuid4[:12]` per-probe `nonce.base_domain`, `observed_nonces` membership | N/A | Generic. |
| `eval/consolidated.py` · `eval/juiceshop_harness.py` · `eval/juiceshop_ephemeral.py` · `eval/__main__.py` | `GateStatus PASSED/FAILED/NOT_MEASURABLE/SKIPPED`, ordered `_GATES vamp(always) crapi(CRAPI_BASE_URL) juiceshop(JUICESHOP_EPHEMERAL=1) portswigger(PORTSWIGGER_LIVE=1) dvga(DVGA_URL)`, composite `FAILED>NOT_MEASURABLE>PASSED` (all skipped → NOT_MEASURABLE), `VERIFIED_CHALLENGE_SCOPE` 9 keys, `API_ONLY_COVERAGE_FLOOR 6/9` vs `COVERAGE_FLOOR 0.75` (browser needs DOM+upload), ephemeral pinned digest `bkimminich/juice-shop@sha256:e68144…` `until`/poll/_ready/clean baseline + `rm --force --volumes` | N/A | Consolidated harness is generic orchestration — no per-target payload to collapse. |

---

## 3. Why basic vulns were still missed — root cause, not symptom

**Before the fix:** live `scan_target` missed VAmPI's `sqli` even though hermetic `graph/scan` succeeded — seven divergences (see `scan-e2e-closed`): scheme dispatch treating `http://localhost:5000` as `host_port` not `url`; banner/IP noise admitted as `Endpoint`; slashless `-q` gobuster tokens; `canary` fingerprint never triggered SQL error (`canary'` quote-probe missing); sibling-list `{"users": [...]}` baseline not harvested (wrapper `{{users: [...]}}` unwrap); bulk-corpus before templates so wrong oracle fired first; budget shared incorrectly.

**After the fix (current HEAD):** those seven are closed — `detect_target_type` scheme-aware, `theHarvester` strict hostname + IP filter, `gobuster` regex `/?` normalize, `fingerprint_parameter` diagnostic `canary'` probe when `observed is None and hint is None`, `_harvest_baseline_value` plural-key unwrap, `get_payloads` template-first, sibling harvesting in `scan/entrypoint.py`. Autonomous `sqli` via `differential DATABASE_ERROR` **now confirms live on VAmPI** (`scan-e2e-closed`).

**Why bespoke eval still hides misses:** hermetic eval detectors set their own baselines *outside* `scan_target`'s harvest, so fixes to generic harvest never exercised through eval's bespoke path — eval always passed hermetic while live `scan_target` failed. The lesson is structural: **any vuln with a bespoke detector is invisible to generic fixes and to the score**, and vice versa — two codepaths maintain the illusion of coverage.

**Remaining generic gap (Juice Shop):** `juiceshop_live.py` hardcodes UNION payload and sentinel strings *in the detector* instead of deriving them from graph-discovered `Object`/`Endpoint`/`Parameter` facts via `payload_chain`. Result: adding a new UNION sentinel to corpus/library/resolver changes no Juice Shop outcome until the detector string is also edited — a second bespoke write for one generic payload. The honest `6/9 API-only` ceiling after `v1.11` already documents this: `uploadSize/uploadType` are `204` with no artifact (no execution signal), `localXss` needs `fire_browser` + tracker attribution (browser in prod, not gate), so \(6/9\) is not negotiable without per-challenge exploit logic. Do not inflate claims — keep \(6/9\) ceiling and route UNION through `STRUCTURAL union_extraction` with sentinel sourced from graph, not hardcoded.

---

## 4. Token waste — 500M lesson

| Waste | Cost | What to do instead |
|-------|------|--------------------|
| Duplicate oracle wiring per target: `harness._confirm` + `juiceshop_live._confirm_differential`/`_confirm_structural`/`_confirm_structural_headers` rewire same `run_oracle` → `is_violation → write_finding` via handle indirection that `mcp/server.py` + `payload_chain._evidence_for` already centralize | ~3× wiring, ~2× bug surface (header resolution fix C was re-implemented per detector) | Route all confirmation through `payload_chain._evidence_for` + `mcp/server.py` evidence adapters — one place to add a new oracle family, not N detectors |
| Duplicate MCP plumbing: `harness._SharedState`/`_session_as`/`_mcp_for`/`_call`/`_read_only_fire` verbatim mirrored in `juiceshop_live.py` (+ `eval/consolidated.py` `_vamp_run`/`_juiceshop_run` variants) | Any fix to handle lifetimes / `trust_env` / `fire_ref` projection must be applied 3× or diverges | Extract shared `eval/mcp_session.py` helper (Phase 1 refactor, small diff — not this docs-only commit) or have bespoke runners delegate to `payload_chain.call_tool_sync` the way `scan/entrypoint.py` already does |
| Per-target payload hardcodes: each vuln class re-states its own payload/sentinel strings outside corpus/resolver | Corpus additions never affect bespoke detectors; drift between vendored `SOURCE.txt` pin and detector string | All payloads from `PayloadLibrary` + `payload_resolver` — detector supplies only `vuln_class` + `suggested_oracle`, never inline payload |
| Per-target endpoint hardcodes: `/books/v1` `/users/v1/_debug` `/rest/user/login` `/rest/products/search` `/ftp/{filename}` `/file-upload` `/api/Feedbacks` `/` repeated as literals in two eval files + `config/crapi-surface.yaml` sort-of-config | New target needs a new file to copy-paste | Single path: `recon/api_discovery` + `SurfaceMapper.map_structure` discovers endpoints into graph; Coordinator `query_graph` + `fingerprint_parameter` operates on graph, not literals |
| Hardcoded sentinels `admin@juice-sh.op` / `CREATE TABLE \`Users\`` in detector instead of graph `Object` field | Sentinels diverge from seeded DB content after seed change; fix requires editing detector | Sentinel = graph-discovered object attribute (seeded user's email extracted via `_discover_book` pattern but generalized through graph, not string literal) — `STRUCTURAL union_extraction` oracle already supports `union_sentinel` param |

Net: generic-first means **no per-target `_detect_*` body duplicating generic** — target config (base_url, `SurfaceSpec` yaml, seeded identities) is the only per-target file.

---

## 5. Reference ideas absorbable WITHOUT violating invariants

All ideas are technique-level paraphrase over `MIT`/`Apache-2.0` refs (no GPL). `cai` core ideas only, never adapt. Each idea checked: no seventh family, no role leak (`Explorer` never `write_finding`, `Coordinator` never `fire`/`run_oracle`), `ScopeGuard` at execution layer, `read-only-first`, audit every attempt, `token_ref` isolation.

| Idea (paraphrased) | Source ref (MIT/Apache-2.0 where adapted; cai ideas-only flagged) | How to absorb generically | Family / boundary check |
|--------------------|---------------------------------------------------------------|---------------------------|-------------------------|
| Generic discovery loop: graph → `query_graph` → `score_and_select` → `fingerprint` → `get_payloads(sink-matched)` → `fire` → `run_oracle(entry.oracle_type)` → `write_finding` only on `is_violation` | `PentestGPT` planner loop (MIT) shape, but ReachAgent already has this — confirm alignment, not new | Collapse bespoke eval detectors to this loop; add `_evidence_for` adapters for `auth_bypass` + `responses_invariant` (for mass/idor) so generic covers them | Holds six families; `Explorer` still never writes |
| Nonce-per-probe `nonce.base_domain` for OOB attribution | `claude-bug-bounty` `oob_listener` (MIT), `oob/collaborator.py` already does `ra+uuid4[:12]` | Keep — already generic; juice sqli UNION should also be structural not OOB, so no new OOB for UNION | `OOB_CALLBACK` unchanged |
| Wordlist default `raft-medium-dirs.txt` when present else `common.txt` via `preferred_wordlist` | `claude-bug-bounty` (MIT) + `hexstrike-ai` type-aware params (MIT) | Already done in `recon/tools/_wordlist.py` + wrappers — keep | Recon facts only |
| Thread/rate/timeout env tunables per wrapper (`REACHAGENT_KATANA_DEPTH`, `NMAP_TIMING`, `MASSCAN_RATE`, etc.) | `hexstrike-ai` type-aware `optimize_*_params` (MIT) paraphrased as env vars, `strix` rate-retry markers (Apache-2.0) | Already exists for most wrappers (gap audit `recon-gap-audit.md` `a` rows) — extend `katana -jsl -aff` already wired | No oracle/finding |
| Spec-first before combinatorial (`_SPEC_PATHS` 8 + `discover_schema` GraphQL seam) | `hexstrike` endpoint enum pattern (MIT) adapted as `api_discovery.py` | Keep generic entrypoint's spec-first `D1` before `D2` 50-GET fallback | Facts only |
| Deterministic verdict (no LLM judge), opaque `fire_ref`/`verdict_ref` handles so client cannot forge confirmation | `strix`/`cai` LLM judge is counter-model (deliberately not absorbed) | Keep AST-checked `OracleVerdict` only inside `oracles/differential.py` | Reinforces invariant |
| Typed `ChallengeClaim(challenge_key, vuln_class, evidence_ref, scope_class)` + tracker delta `unsolved→solved` per-challenge attribution | `juiceshop_harness.score_run` strict typed mode | Keep for gate scoring honesty; generic detection should still emit typed claims so tracker delta no longer does `class → all-challenges` inflation | Scoring, not oracle |
| Clean baseline gate (`validate_tracker_snapshot` 9 keys, `classify_baseline` dirty/invalid → NOT_MEASURABLE) | Own harness; `hexstrike` docker readiness patterns (MIT) for ephemeral polling | Keep — honest measurability |
| Three-pane textual TUI observing live `ReachabilityGraph` + `AuditLog` via callbacks, no detection inside TUI | `PentestGPT` / `pentagi` TUI shape paraphrased; `textual` framework already considered (ponytail: reuse over custom) | New `src/reachagent/tui/app.py` thin observer (Phase 1 commit, not this docs-only audit) | No oracle; reads graph/audit only |

---

## 6. What NOT to absorb — explicitly out of scope

| Pattern | Source that does it | Why ReachAgent does not |
|---------|---------------------|-------------------------|
| C2 post-exploitation, reverse shells, lateral movement, privilege escalation after initial access | `cai` core (proprietary) — agent orchestration beyond first finding chain | **§1 non-goal** — ReachAgent stops at confirmed `Finding` + `enables`/`derived_credential` re-query, never post-exploit (CLAUDE.md non-negotiable) |
| Mobile testing (APK/iOS instrumentation) | `cai` / various refs | **§1 non-goal** — Web/API only |
| External scanner as decision (e.g., trusting `sqlmap --batch` or `Nuclei -jsonl` `matched-at` as confirmation) | refs that wrap sqlmap/nuclei as oracle | **Plan §9** scanners are at most recon-tier facts or signal-gated `Candidate` gated on graph signal, never write `Finding`; only `Validator run_oracle` adjudicates (CLAUDE.md non-negotiable) |
| LLM adjudication of oracle verdicts | `strix` / `cai` judge models | **Plan §7** zero LLM in oracle — `decide()` is pure, deterministic, auditable |
| Seventh oracle family for each new vuln class | Ad-hoc detectors | **Plan §7** — absorb into existing six; new type needs explicit spec update |
| New graph node/edge type per vuln class | Ad-hoc schema growth | **Plan §6** — absorb into existing `Identity/Session/Endpoint/Parameter/Object/Host/Service/Finding` + `can_call/returns/owns/accepts` + `enables/derived_credential`; `Endpoint.access_restricted` was attribute, not new type |
| Blind XSS OOB flag forwarding as wrapper quirk | refs | Deferred — is `OOB_CALLBACK` + callback infra, not a wrapper `-ac`-style flag to copy |

---

## 7. TUI spec — textual, not GUI/CLI

**Framework:** `textual` (Python TUI, `Textualize/textual` MIT) — installed dep reuse over custom renderer (ponytail ladder: already-installed dep before new dep; `textual` is not yet in `pyproject.toml` — add as `dependencies` in `src/reachagent/tui` commit, not this audit).

**Entry points:** `reachagent-scan` stays headless (CI/automation): `reachagent-scan --target https://… --in-scope "*.corp.test" --out-of-scope "…" [--dry-run] [--live] [--state run.json --resume run.json] [--surface surface.yaml]`. `reachagent-tui` launches interactive — both share **same** `scan/entrypoint.py:scan_target` entrypoint and same six oracles; TUI never contains detection logic.

**Layout (three panes, vertical stack or left/right+bottom — `textual` Dock):**

```
┌ Targets / Graph ──────────────┬ Findings ───────────────────┐
│ Host/Service/Endpoint tree    │ Finding vuln_class          │
│  └─ Host technology, wildcard │  severity / oracle_used     │
│  └─ Endpoint method path      │  evidence_ref               │
│     └─ Parameter sink_type    │  enables / derived_credential│
│  scope: in/out, wildcard_shape│  chain_paths(start)         │
│  filters: / substring         │  filters: / vuln_class      │
├───────────────────────────────┴─────────────────────────────┤
│ Live log — AuditLog tail + firer outcomes                   │
│  timestamp identity method target outcome(:recovered)        │
│  filtered, auto-scroll, pause with space                    │
└─────────────────────────────────────────────────────────────┘
```

- **Pane 1 — Targets / Graph:** `Host`/`Service`/`Endpoint` tree derived from `ReachabilityGraph.hosts()`/`services()`/`endpoints()` + `parameters_of`. Shows `technology`/`wildcard_shape`, `access_restricted` 401/403, `resolve_to`. Scope badge from `ScopeEnforcer`. Graph is source of truth, TUI is observer via callbacks (`graph.add_endpoint`/`add_host` etc trigger re-render, or `load_graph` poll).

- **Pane 2 — Findings:** `Finding` list from `graph.findings()` with `chain_paths(start)` leaf chains via `enables`+`derived_credential` (cycle-safe maximal). Shows `vuln_class`/`severity`/`oracle_used`/`evidence_ref`/`metadata` (e.g., `chain_precondition: disclosed/enumerable`). Selecting a finding highlights its `derived_credential` target identity + its `can_call` endpoints in pane 1.

- **Pane 3 — Live log:** `AuditLog.entries` tail (thread-safe snapshot under lock), host+path only (never query/userinfo), `fired:recovered` vs `refused_out_of_scope` vs `refused_read_only_first` vs `payload_chain_failure:*`. Backed by `AuditLog` logger mirror (`reachagent.execution.audit`).

**Keyboard (no mouse required):**
`j`/`k` or `↑`/`↓` navigate, `Tab`/`Shift-Tab` cycle panes, `/` filter (substring on visible column), `Enter` expand/detail, `r` resume from `--state` (reads `load_graph` then `scan_target --resume`), `q` quit, `?` help. `textual` bindings, no mouse.

**Data flow:**
`reachagent-tui` constructs `ScopeEnforcer` + `ReachabilityGraph` + `AuditLog` + `ChainSolver`, passes them to `scan_target(..., graph, audit)` — TUI's `on_mount` spawns `scan_target` (thread or async) and subscribes `AuditLog` + graph callbacks to `call_later` UI refresh. `graph/persistence.py` `dump_graph` atomic writes `--state` continuously; `--resume` loads and continues (continue-not-replay + `recover_derived`). No detection logic lives in `src/reachagent/tui/` — it reads graph/audit, that is all.

**Headless parity:** every finding written through `Validator write_finding` is reached identically via `reachagent-scan --live`; TUI adds no new confirmed path.

---

## 8. Concrete Phase 1 follow-on (what lands next, not this docs-only commit)

- `src/reachagent/tools/payload_chain.py` — add `_evidence_for` adapters for `auth_bypass` + `responses_invariant` (with `json_field` + `baseline_select`/`probe_select`) so generic covers mass-assignment/idor generically; keep handle indirection.
- `src/reachagent/eval/harness.py` + `src/reachagent/eval/juiceshop_live.py` + `src/reachagent/bola/detector.py` — route `bola`/`idor`/`mass`/`sqli`/`union`/`nullByte` through one generic driver (`Coordinator query_graph → score_and_select → fingerprint_parameter → get_payloads(sink-matched) → fire_request baseline/probe → run_oracle(entry.oracle_type) → write_finding on is_violation`). Delete hardcoded `_detect_*` payload/sentinel strings; keep only per-target *config* (`base_url`, `config/crapi-surface.yaml`-style spec, pinned ephemeral image digest). Juice Shop UNION sentinel becomes graph-discovered object field via `STRUCTURAL union_extraction`, not hardcoded `admin@juice-sh.op`.
- Keep: `Explorer` never `write_finding`, only `Validator` `run_oracle`/`write_finding`, six families, `ScopeGuard` deny-by-default, `read-only-first`, every attempt audited, `token_ref` isolated per-identity.
- Add `src/reachagent/tui/app.py` minimal `textual` App three panes observing `scan_target` callbacks — no detection inside TUI (observer only).

One commit, small diff, `uv run ruff check --fix . && uv run ruff format . && uv run ty check src || uv run mypy src && uv run pytest -q` green, `git diff --stat` then shows only doc+eval collapse change.

---

## 9. Honesty footer

- Corpus sizes unchanged: `PayloadsAllTheThings a9d97e9` + `SecLists 5aa4cb1` at pinned SHAs; `payload_ref` line-locator `source/relpath#Ln`; `reserved_files`/`skipped_files`/`semantic_invalid_refs` accounting kept.
- Coverage matrix unchanged: `BOLA Full`, `blind sqli Partial` (OOB→timing→boolean), `DOM XSS Partial` (`flows`+`executed` marker), `SSRF Full` 30 templates, `JWT Full` 3 precomputed, `clickjacking Full`, `CORS Full`, `CSRF Partial` precondition-only, deserialization Weak, GraphQL Full.
- Juice Shop floor stays `6/9 API-only` (not `75%`) until per-challenge exploit logic matches tracker condition — `docs/reachagent-final-plan.md` now `v1.12` `API_ONLY_COVERAGE_FLOOR` locked `D1-D4` (this commit); `juiceshop_harness.py` `API_ONLY_COVERAGE_FLOOR 6/9` `COVERAGE_FLOOR 0.75` `7/9` reverted `flow≠executed` `14.3% FP` deferred — live `REACHAGENT_JUICESHOP_EPHEMERAL=1 vamp+juice PASSED 6/9 0% FP` verified.
- No seventh family introduced. No external scanner as decision-dependency (§9). No C2/mobile.
- The `scan-e2e-closed` live autonomous VAmPI finding after 7-step divergence fix is the proof generic works; bespoke eval is what kept basic vulns hidden.
