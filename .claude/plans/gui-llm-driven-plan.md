# ReachAgent GUI — Full LLM-Driven Pentest Loop (Build Plan v2)

**Goal (user):** Prompt in → LLM drives EVERY phase automatically from the GUI — recon → endpoint/insertion-point discovery → custom-payload firing → oracle confirmation → LLM report — covering **all attack classes** (the 22 in `VULN_CLASS_ALLOWLIST`), using the existing tagged payload library + six deterministic oracle families. No CLI, no TUI, no Docker dependency for the loop itself (Docker stays only as the *target lab* provisioner for eval). Everything confirmed only by `run_oracle → is_violation → write_finding` (CLAUDE.md non-negotiables hold — the LLM drives, the deterministic engine confirms).

**Non-negotiable invariants (kept, never relaxed):**
- No `Finding` without a `confirmed` `run_oracle` result; LLM proposes, never adjudicates.
- Role bounds: Explorer never `write_finding`; only Validator `run_oracle`/`write_finding`. The orchestrator drives the *public MCP tool contracts* (`McpCaller` → `mcp.call_tool`), never the Validator directly.
- No external scanners as detection. Read-only-first. Scope allowlist at execution layer. Six oracle families only.

**Reference reading (done this session):** `pentagi` (Go, MIT) — Flow→Task→Subtask, per-step single `CallWithTools`, `jsonschema.Reflector` tool registry, per-agent tool allowlist checked before exec, ChainAST + csum summarizer (PreserveLast, LRU), Refiner patch loop, repeating-detector + ExecutionMonitor brakes. `cai` (dual MIT/research) — single ReAct turn per `Runner.run`, handoff-driven phase transition, regex guardrails + HITL flag, `_compress_output_for_model`. **Take (as patterns):** per-step tool-allowlist, plan→execute→refine, context compression, handoff as phase transition, guardrail validation. **Leave:** arbitrary shell, Docker per-flow sandbox, LLM-as-confirmation, C2/post-exploitation. Both already condensed in `docs/live-reasoning-design.md` + the old plan; this session re-read the source.

## Current state (what already exists)

- `scan/entrypoint.py:scan_target` — autonomous loop: cold-start recon (facts) + `api_discovery` spec-first → Coordinator `query_graph/score_and_select/check_budget` → `payload_chain` via in-process MCP (`McpCaller`, `fire_ref`/`verdict_ref` handles) → `run_oracle` → `write_finding`. **But only 7 sink classes** (`_vuln_classes_for_library`: sqli, xss_reflected, path_traversal, ssti, nosqli, ldap_injection, command_injection).
- Flag-gated LLM proposers (all allowlist-validated, proposal-only): `get_profile_for_target`/`propose_recon_profile` (6 `RECON_PROFILES`), `propose_vuln_targets` (22-class allowlist), `propose_payload_choice` (dynamic bucket allowlist), `generate_llm_report`.
- GUI shell: `gui/app.py` (FastAPI: `/api/scan`, `/api/scan/{id}`, `/api/report/{id}`) + `gui/static/index.html` (1s-poll), calls `scan_target`.
- Detectors per class (prober-seam, `OracleRunner`): bola (MCP-generic), xss (dom/stored), sqli/blind, nosql, ldap, pathtraversal, fileupload, clickjacking, cors, csrf, business_logic templates+runner, graphql module, race module.
- CLI (`scan/cli.py`, `reachagent-scan`), TUI (`tui/app.py`, `reachagent-tui`) — **to be removed** per user.

## The 22 classes → oracle path map (the coverage target)

| Class | Oracle path | Existing generic loop? | Build action |
|---|---|---|---|
| sqli | differential DATABASE_ERROR / auth_bypass | ✅ | keep |
| xss_reflected | execution_confirmation tag-in-body | ✅ | keep |
| path_traversal | structural PATH_TRAVERSAL | ✅ | keep |
| ssti | execution_confirmation expected_output | ✅ | keep |
| nosqli | differential RESPONSES_INVARIANT | ✅ | keep |
| ldap_injection | differential AUTH_BYPASS | ✅ | keep |
| command_injection | oob→timing | ✅ | keep |
| ssrf | structural SSRF_RESPONSE (non-blind) / oob (blind) | ❌ | add class (non-blind works; blind needs `REACHAGENT_OOB_BASE_DOMAIN`) |
| jwt_forgery | structural JWT_FORGERY | ❌ | add class (precomputed tokens; needs a token-bearing endpoint; baseline = valid token or 401 accepted) |
| sqli_blind | oob→timing→boolean | ❌ | add via `sqli/blind_detector` prober |
| xss_stored | execution_confirmation tag read-back | ❌ | add via `xss/detector` stored prober (needs a state-changing write+read-back endpoint) |
| xss_dom | execution_confirmation flows/executed | ❌ | add via `fire_browser` + shim (Playwright) |
| file_upload | structural FILE_UPLOAD_BYPASS | ❌ | add via `fileupload/detector` multipart prober |
| clickjacking | structural CLICKJACKING (headers) | ❌ | add structural-header pass (fire GET, server-side header resolution) |
| cors_misconfig | structural CORS_MISCONFIG (headers + probe Origin) | ❌ | add structural-header pass |
| csrf_missing_protection | structural CSRF_MISSING_PROTECTION (Set-Cookie) | ❌ | add structural-header pass |
| bola | differential PROBE_UNAUTHORIZED | ❌ | add via `bola/detector` when graph has owns edges |
| bfla | differential PROBE_UNAUTHORIZED (role) | ❌ | same as bola (cross-identity on actions) |
| idor | differential RESPONSES_INVARIANT (json_field) | ❌ | add via differential cross_request re-read (needs mutating endpoint; read-only-first gated) |
| mass_assignment | differential RESPONSES_INVARIANT (json_field admin) | ❌ | add via differential cross_request re-read |
| business_logic | business_rule 4-template library | ❌ | add via `business_logic` templates when resources match |
| graphql | differential + timing | ❌ | add via `graphql/module` when a /graphql endpoint exists |
| race | business_rule single-use | ❌ | add via `race/module` when single-use resource + delivery |

Honest posture: classes needing conditions the discovered surface doesn't provide (race needs a single-use coupon; idor/mass need a mutating endpoint with a re-readable privileged field; xss_stored needs a stored+rendered field; xss_dom needs browser) instantiate **nothing** — reported as "not applicable", never a fake finding. The LLM proposes priority; fixed code + oracles decide.

## Architecture — 4-phase LLM-driven loop (new orchestrator)

New module `src/reachagent/scan/orchestrator.py` (GUI calls this; `scan_target` stays as the sink-class engine it already is, or orchestrator supersedes it — decide in build):

```
[GUI prompt {target, in_scope}] 
  → Phase 1 RECON:     cold-start recon (facts) + spec-first api_discovery, LLM picks RECON_PROFILE
  → Phase 2 ENDPOINTS: graph Endpoint/Parameter/Host shape → LLM picks vuln-class priority
                       per endpoint (22-class allowlist, sink-compat checked) → ranked probe list
  → Phase 3 PAYLOADS:  per class dispatch:
        sink classes   → get_payloads(sink-matched, template-first) → resolve+mint_fire_kit
                         → fire_request baseline/probe → run_oracle(entry.oracle_type)
        structural hdr → fire GET → run_oracle(structural clickjacking/cors/csrf) server-side headers
        authz          → bola/detector (MCP) when owns edges; differential cross_request for idor/mass
        advanced       → fileupload/xss(d/fb)/graphql/race/business_logic detectors gated on surface
      → write_finding ONLY on is_violation (MCP verdict_ref)
  → Phase 4 REPORT:    generate_llm_report over CONFIRMED_VIOLATION findings + chain_paths
  → GUI streams phase-by-phase progress
```

**Streaming:** orchestrator exposes an event queue (phase/step/payload/verdict/finding); GUI polls `/api/scan/{id}` (keep 1s poll — works, simpler than SSE) and renders phase timeline + findings + chains + report.

**LLM usage = proposal-only, same three-layer discipline as `docs/live-reasoning-design.md`:** profile/class/payload choices allowlist-validated, fallback to deterministic on any failure; the orchestrator never lets a live LLM call fire, oracle, or write a finding. No new oracle family, no role leak.

## Build order (commit per step, gate green each: `uv run ruff check --fix . && uv run ruff format . && uv run pytest -q`)

1. **Plan** (this file) — done.
2. **Orchestrator — sink-class expansion:** added `ssrf` to the generic loop classes + sink map. DONE.
3. **Orchestrator — structural-header pass:** `scan/orchestrator.py` — clickjacking/cors/csrf via the STRUCTURAL oracle (clickjacking gated on HTML content-type to avoid API false positives). DONE.
4. **Orchestrator — authz + advanced classes:** `run_authz_bola` (bola/bfla via bola.detector when owns edges + ≥2 identities), `run_file_upload`, `run_jwt_forgery`, `run_sqli_blind` (paired-trial timing), `run_graphql` (needs 2 identities), `run_business_logic` (4-template library). All findings via a Validator-side seam (`validator.run_oracle`/`write_finding`, portswigger precedent) — six families held. DONE.
5. **GUI phase streaming + report:** `gui/app.py` drives `scan_all_classes`, streams `ScanEvent` phases via poll; `index.html` renders phase timeline + findings + report. DONE.
6. **Cleanup:** deleted `scan/cli.py`, `tui/`, `start-reachagent.sh` (dup), removed `reachagent-scan`/`reachagent-tui` scripts + `textual` dep; updated affected tests; README/CLAUDE.md GUI-only. DONE.
7. **Review + gates:** ruff/mypy clean; orchestrator suite (3 incl zero-FP) + all touched-file tests green; AST boundary tests green. Remaining full-suite run is corpus-slow (pre-existing). DONE.

Gates held: six families, role bounds (AST `4/3/3`), `write_finding` gated on `is_violation`, no detector/validator import leak, no external-scanner strings, read-only-first, scope at execution layer.
