# ReachAgent — Web/API Exploitation Agent
### Final Project Plan (July 2026)

**Status: Locked — v1.16.** Changes from v1.15: **Phase H generic-coverage pass** — DOM XSS taint shim gains four new hooked sinks (`outerHTML`, `insertAdjacentHTML`, string-argument `setTimeout`/`setInterval`), each verified against a real Chromium browser in `tests/phase3/test_browser_integration.py`; a brand-new `web_cache_poisoning` class (§5 Weak → Partial) — new `StructuralCheckType.WEB_CACHE_POISONING` branch confirms an unkeyed header (`X-Forwarded-Host`) replayed from a shared cache into an independent, header-free re-read of the same run-unique cache-busted URL (`cachepoisoning/detector.py`, `run_cache_poisoning`). Also: `eval/juiceshop.py`'s optional PortSwigger invariant now catches `httpx.HTTPError`/`IdentityConfigError` around the live lab probe (found via a real expired-lab `httpx.ReadTimeout` that had been silently discarding an already-completed Juice Shop measurement) — no oracle/detector change, resilience only. Juice Shop's 6/9 (66.7%) ceiling is unchanged and deliberately not chased further: the two upload challenges give zero observable signal (`204` regardless of validity) and the DOM-XSS challenge only credits one exact hardcoded payload via the target's own tracker — both documented target-specific walls, not capability gaps (§5 ratings stay honest per class, not per named challenge). No seventh oracle family — the new check type lives inside the existing STRUCTURAL family; six `OracleMechanism` values unchanged.

**Status: Locked — v1.15.** Changes from v1.14: **coverage-completeness pass** (rebuild-v2 branch, ongoing) — classes the coverage-gap investigation found undriven despite already appearing in `ALL_CLASSES`/the matrix below are now wired: `mass_assignment` (differential oracle, independent-reread-after-write, was silently reporting not-applicable on every scan), `xss_stored` (reuses the existing `xss/detector.py` stored path with a no-op DOM probe — DOM XSS stays separately driven by `run_xss_dom`), a brand-new `open_redirect` class (new `StructuralCheckType.OPEN_REDIRECT` branch — attacker URL echoed verbatim into a 3xx `Location` header), `race` (reuses `race/module.py`'s existing `probe_race` — required first excluding `SINGLE_USE_REUSE` checks from `run_business_logic` so the same limited resource is never consumed twice), and a brand-new `xxe` class (blind OOB exfiltration — fires the previously-orphaned `sqli_blind/oob-xxe-exfil` template against spec-declared XML endpoints, confirmed via the existing `oob_callback` oracle, gated on `REACHAGENT_OOB_BASE_DOMAIN`). Also fixed a `driven_classes` staleness bug where `xss_dom` was already driven but missing from the set, producing a spurious contradictory event on every scan. **Status: Locked — v1.14.** Changes from v1.13: **visual live loop** — TUI `CSS scrollbar-gutter stable` + `Header` live stats, `scripts/portswigger_academy_login.py` staged `16.7K` Auth0 `playwright` env-only `LAB_URL/TOKEN` via `ScopeGuard` host+port, `generic PortSwigger chain` live-ready via `McpCaller` handle `fire_ref/verdict_ref`. Keeps `6/9` honest. **Status: Locked — v1.13.** Changes from v1.12: **hardening batch** — TUI live Finding fields + `--help` + Header stats, encoding-variant bounded (url/double-url, `payloads/encoding.py` + `payload_resolver` variant cache, `corpus _dedup_canonical`), `report/renderer.py` deterministic JSON/markdown/HTML, `.github/workflows/ci.yml` ruff+format+ty/mypy+pytest+docker VAmPI/juice gates, `tests/e2e/test_scan_e2e.py` hermetic generic findings, fallback sentinel warned. Keeps `v1.12` generic-first. **Status: Locked — v1.12.** Changes from v1.11: **generic-first closed end to end** — enumerate → identify endpoints → find vulns via `fingerprint_parameter → get_payloads(sink-matched, template-first) → resolve_entry + mint_fire_kit → fire_request baseline/probe → run_oracle(entry.oracle_type) → write_finding on is_violation` with opaque `fire_ref`/`verdict_ref` handle indirection, no per-target payload literal beyond fallback. `1552929` deep re-audit (117 files + refs whole-code, MIT×5/Apache-2.0×1/cai dual, generic vs bespoke gap) → `71bb535` dedup `~80×3` `eval/mcp_session` single helper + `_evidence_for AUTH_BYPASS/RESPONSES_INVARIANT/union_extraction/jwt_forgery/ssrf_response/OOB_CALLBACK` + textual `tui/app.py` 3-pane observer (`Tree` Host/Service/Endpoint+scope tech/wildcard_shape/access_restricted, `DataTable` `Finding` + `chain_paths`, `Log` `AuditLog` tail, `Header/Footer`, `j/k Tab / filter q quit`, `0.5 s` poll, shares `scan/entrypoint:scan_target` with headless `reachagent-scan --target --in-scope --live`) → `80002e6` wiring `harness/juice` via `_generic_confirm(..., kit={axis,expectation,json_field,select})` + `graph.objects()` sentinel fallback → `fb9ad02` polish `Footer` bindings/doc mirroring §14 Phase 2. The `7-step hermetic-vs-live VAmPI` chain is preserved (`--surface` seeding, diagnostic `canary'` fingerprint, sibling-list baseline `/{id}→/` harvest, `template-first` ordering). `17 wrappers + calibration` random-uuid/SHA256 wildcard + `DnsWildcardProber` + `spec-first api_discovery` honest, `multi-channel OOB additive`, `401/403 restricted-surface`, `durable dump/load+resume RECOVER` (`persistence.py` §12), `SSRF 21,130 entries` payload-backed (`payloadsallthethings a9d97e9`, `seclists 5aa4cb18`, network-free), `execution-marker __reachagent_exec` additive (`flows+executed` → violation, `flows` alone stays violation), `6/9 API-only floor` unchanged (`uploadSize/uploadType` uncredited `204`/no artifact, `localXss` needs `fire_browser` tracker attribution — why `7/9` reverted `flow≠executed` `FP 0→14.3%`), `Ful/Partial/Weak` unchanged, `six OracleMechanism` only, `role bounds` (`Explorer` never `write_finding`/`run_oracle`, `Coordinator` never `fire`/`run_oracle`, only `Validator` `run_oracle`/`write_finding` AST pin `4/3/3`), `ScopeGuard` deny-by-default execution layer `scope→read-only-first→send`, audit every attempt, `token_ref→TokenStore`, handle indirection.

**Status: Locked — v1.10.** Changes from v1.9: Phase 3 Juice Shop UNION and schema challenge claims now require exact extraction-only sentinels through the existing STRUCTURAL oracle. Fresh-container validation recovered two over-corrected claims, establishing a measured API-only ceiling of 6/9 (66.7%). Upload size/type still lack distinguishable retrieval or execution evidence, and local XSS still requires browser DOM attribution; 75% (7/9) remains outside API-only reach. No new oracle family, no §5 rating change.

**Status: Locked — v1.7.** Changes from v1.6: the recon and signal-gated tool lists in §9 expand from a handful of named examples to a comprehensive, categorized set covering network/service recon, subdomain/content discovery, CMS/framework fingerprinting, and exploitation-assist tooling. HexStrike AI (and similar all-in-one autonomous pentest-agent frameworks) evaluated and explicitly excluded as an orchestrator — its own autonomous decision-making and exploit-generation duplicate what run_oracle exists to do; the individual underlying tools it wraps (nmap, amass, gobuster, nuclei, etc.) remain available through ReachAgent's own tiers directly. No new oracle family, no tier-rule change.

**Status: Locked — v1.6.** Changes from v1.5: payload corpora expand from a curated tagged subset to full vendored PayloadsAllTheThings and SecLists repositories (§9/§12); the signal-gated exploitation tier (§9) is activated for sqlmap, nikto, dirb, ffuf, and feroxbuster — each still gated on an existing graph signal for its class, output still an unverified candidate routed through run_oracle. No tier rule changed, no new oracle family, nothing tool-sourced is ever written as confirmed without run_oracle.

**Status: Locked — v1.5.** Changes from v1.4.1: client-side structural classes (clickjacking, CORS misconfiguration, CSRF) added to §5/§7; the §9 external-scanner rule is formalized into three behavior-defined tiers (recon/transport facts vs. signal-gated exploitation candidate sources vs. transport-aggregator MCPs); public payload corpora (PayloadsAllTheThings, SecLists) named as tagged reference sources in §9/§12; CVE-match added as an evidence type under STRUCTURAL_VERIFICATION (§7); fingerprint_parameter gains context-aware class-prioritization in §13. No seventh oracle family — all new classes route through the existing structural-verification mechanism.

**Status: Locked — v1.4.1.** Changes from v1.4: `fire_browser` added to §13 core manifest as an Explorer-owned browser-side tool for Phase 3 DOM taint-tracking, resolving the open verification question from v1.3.

**Status (v1.4):** Supersedes all prior drafts. Changes from v1.3: tool calling promoted to a first-class design element — §13 now opens with the tool manifest and a full worked trace (fingerprint → sink-matched selection → mutation → oracle verification) instead of leading with MCP servers; role boundaries are now defined by tool access, not just description (§4, §13). External scanners (sqlmap, Nuclei, ZAP, and Burp/Caido's own built-in scanners) are explicitly excluded as core dependencies (§1, §9, §13), with a deferred, optional ingestion mode specified that still requires every imported candidate to pass `run_oracle` before being confirmed.

---

## 1. Positioning

> ReachAgent does not try to out-scan existing tools on single-request vulnerability detection — that space is commoditized. It targets what the field still does poorly: **confirmed, multi-hop attack chains that cross vulnerability classes**, found via a live reachability graph and deterministic verification instead of LLM judgment.

Every rating and design choice below is tied to a specific, cited reason, not a plausibility judgment — because an ungrounded confidence rating in the tool's own coverage claims is the same failure mode the deterministic-verification principle exists to prevent.

**Explicitly out of scope, by design:** C2/post-exploitation tooling and mobile targets. Where a finding confirms code execution (e.g. command injection), the system stops at confirmation — it does not pivot into interactive shell access or persistence.

**Also explicitly out of scope: orchestrating external scanners as the detection mechanism.** sqlmap, Nuclei, ZAP, and similar tools are not shelled out to or wrapped as part of how ReachAgent decides what's vulnerable — see §9 for why, and for the deferred, optional exception.

---

## 2. Core design principles

| Principle | Description |
|---|---|
| **Deterministic verification** | No finding is reported unless a scripted, non-LLM check confirms it. LLM judgment proposes candidates; it never adjudicates them. |
| **Graph-centric** | Every confirmed finding writes structured facts into a shared reachability graph — nothing lives only in a report string. |
| **Multi-class chaining** | Findings across different vulnerability classes connect through one uniform mechanism, not bespoke per-pair logic. |
| **Safety first** | Read-only testing by default, strict scope enforcement, no destructive actions without explicit escalation. |
| **Cost aware** | Expensive reasoning models are reserved for strategy and verification; high-volume execution runs on cheap/fast models. |

---

## 3. High-level architecture

```mermaid
flowchart TD
    A[Target + Scope + Test Identities] --> B[Recon and Surface Mapping]
    B --> C[Reachability Graph]
    C --> D[Coordinator Agent]
    D --> E[Explorer Agent]
    E --> F[Execution Layer]
    F --> G[Validator Agent]
    G -->|Confirmed Finding| C
    G -->|Inconclusive| C
    C --> H[Chain Solver]
    H -->|New Identity / Session / Edge| C
    H --> I[Report + PoC Generator]
```

The loop that matters is `C → D → E → F → G → C`: every test result, confirmed or not, writes back into the graph, so coverage is tracked and nothing gets retested. The **Chain Solver** is what turns single findings into attack paths — it runs reachability queries over the graph and, when it finds a finding that produces a new credential or privilege, feeds a new node back into `C`, which reopens the search from that point. This feedback loop is the entire mechanism behind cross-class chaining (§8).

---

## 4. Agent roles

| Role | Responsibility | Model tier |
|---|---|---|
| **Coordinator** | Owns the graph; decides what to test next by querying untested edges and newly spawned nodes; prioritizes chain-completing tests over fresh exploration | Sonnet-tier — needs real reasoning over graph state |
| **Explorer** | Sink fingerprinting, payload selection and firing, raw response classification — highest call volume | Haiku-tier — cheap and fast |
| **Validator** | Independently re-derives confirmation using deterministic oracles only; has no access to or incentive to agree with the Explorer's classification | Sonnet-tier, constrained to pre-defined verification procedures, not open-ended judgment |

**Each role's authority is enforced by which tools it can call, not just by this description.** The Explorer can generate candidates but never confirm them; only the Validator can write a `Finding`. See §13 for the exact tool contracts and why those boundaries are implemented in code, not just stated as policy.

### Coordinator prioritization rule

The Coordinator does not test edges in discovery order. Every untested `(identity, endpoint)` edge is scored, and the Coordinator always pops the highest-scoring edge off a priority queue that gets re-scored whenever the graph changes — a new `Finding`, a new spawned `Identity`/`Session`, or a budget cap tripping on the current path:

```
score = (object_sensitivity_tier × 3)
       + (is_newly_spawned_identity × 5)
       + sink_severity_weight
       − prior_attempts_in_neighborhood
```

- **`object_sensitivity_tier`** (0–3): how sensitive the endpoint's data or action is — 0 public, 1 user-owned, 2 cross-user, 3 admin/system.
- **`is_newly_spawned_identity`** (0/1): whether this identity or session was created by the Chain Solver via a `derived_credential` edge earlier in the current run. Weighted heaviest of all terms — this is what makes the Coordinator finish a chain it just found instead of wandering off to fresh, disconnected exploration.
- **`sink_severity_weight`**: derived from the parameter's `inferred_sink_type` — RCE-adjacent sinks (`shell`, `deserialize_target`) score higher than lower-impact sinks (`html_reflection`).
- **`prior_attempts_in_neighborhood`**: count of already-tested edges within one hop of this one — discourages redundant local exploration once a region of the graph is saturated.

This is what makes "prioritizes chain-completing tests over fresh exploration" a concrete, implementable rule rather than an aspiration.

---

## 5. Vulnerability coverage matrix

Ratings track **oracle wiring**, not payload volume: seeding thousands of vendored corpus payloads (§9/§12) expands the *set* a class can be probed with but never moves a Full/Partial/Weak level — a level changes only when a new §7 oracle mechanism confirms (or fails to confirm) the class. The corpus vendoring in v1.6+ therefore leaves every rating below unchanged.

Ratings are calibrated against published results and documented technique limitations, not estimated.

| Class | Support | Primary oracle | Basis |
|---|---|---|---|
| BOLA (cross-identity read) | **Full** | Cross-identity differential diff | Core mechanism of the graph design; read-only-first, always on |
| IDOR (cross-identity write) | **Partial, opt-in** | Cross-identity differential diff on a state-changing write | Confirms a PUT/PATCH against another identity's live object succeeds when it should be refused — the one detector whose confirmed path mutates real cross-user data. Gated behind `allow_cross_user_writes: bool = False` (default off); DELETE excluded even when enabled (irreversible destruction is out of scope for this opt-in). Candidate discovery is narrower than BOLA's three strategies: only an owned object whose `instance_key` substitutes into a `{placeholder}` write-endpoint path |
| BFLA | **Full** | Cross-identity differential on role-gated actions | Same mechanism applied to actions |
| Business logic — known patterns (limit overrun, workflow-order bypass) | **Partial** | 4-template library: single-use reuse, quantity/limit, price/parameter tamper diff, step-order check | Covers the common pattern set via recon-instantiated templates, not hand-modeled per target |
| Business logic — novel/unprecedented | **Weak** | None generic | No oracle exists for a rule the system was never told |
| SQL Injection (error/boolean) | **Full** | Differential + DB error signature | Deterministic, low-noise |
| SQL Injection (blind) | **Partial** | OOB callback (primary), paired-trial timing with negative control (fallback) | OOB-capable targets approach Full; timing-only remains noisy — matches published 0% baseline for naive timing-only detection |
| NoSQL Injection — auth bypass | **Full** | Operator-injection differential diff | |
| NoSQL Injection — blind/deep extraction | **Partial** | Paired-trial statistical oracle, reused from blind SQLi | Same statistical caveats as blind SQLi |
| Command Injection | **Full** | OOB callback (primary), timing (fallback) | |
| LDAP Injection — auth bypass | **Full** | Wildcard/filter differential diff | |
| LDAP Injection — blind extraction | **Partial** | Paired-trial statistical oracle | No OOB channel exists for this class — ceiling is lower than SQLi's |
| XSS — Reflected | **Full** | Headless browser execution confirmation | Confirms the script *ran*, not just reflected — works regardless of cookie flags |
| XSS — Stored | **Full** | Headless execution confirmation on a triggering second view | |
| XSS — DOM-based | **Partial** | Execution confirmation, fed by Playwright taint-tracking shim (hooks `innerHTML`/`outerHTML`/`insertAdjacentHTML`/`document.write`/`eval`/string-arg `setTimeout`/`setInterval`/`location.href`) | Systematic discovery now, but bounded by a hand-maintained sink/source hook list |
| SSRF (non-blind) | **Full** | Response content confirms internal reachability | Payload-backed since v1.11: hand-tagged cloud-metadata / internal URL set confirmed by the existing STRUCTURAL `SSRF_RESPONSE` check type (sentinel-in-body, same shape as UNION_EXTRACTION) |
| SSRF (blind) | **Full** | OOB collaborator callback | Payload-backed since v1.11: hand-tagged callback set (http/https/file/gopher/redirect-chain) carrying `{nonce}.{collab}` |
| XXE (blind, OOB exfiltration) | **Partial** | OOB collaborator callback | One hand-authored template (`sqli_blind/oob-xxe-exfil`), fired only against endpoints whose spec-declared request Content-Type is XML — sink-matched, not a content-type guess. Ceiling is lower than SSRF's: no non-OOB fallback exists, and only spec-discovered XML endpoints are reachable (no bulk corpus folder consumed — see `corpus._RESERVED_CLASS_TOKENS`) |
| SSTI / Template Injection | **Full** | Differential math-expression evaluation | Deterministic, low-noise |
| Mass Assignment | **Full** | Schema diff + independent re-read confirming the effect | |
| Auth & JWT issues (alg confusion, `none`, weak secret, `kid` injection) | **Full** | Structural — forged token grants access or it doesn't | Payload-backed since v1.11: none-alg / HS256-key-confusion / weak-secret precomputed tokens feed the existing `jwt_forgery` STRUCTURAL branch (`kid` injection still not payload-backed) |
| File Upload (type/extension bypass) | **Full** | Retrieval/execution confirmation | |
| Path Traversal | **Full** | Retrieval of known out-of-scope file, content-matched | |
| Race Conditions | **Partial** | Sequential-replay-first, escalating to single-packet concurrent delivery; reuses the business-logic anomaly-check oracle | No fuzzable signature exists for this class — ceiling doesn't move with better engineering, only efficiency does |
| Insecure Deserialization | **Weak** | Canary-object precondition detection only | Gadget-chain generation is a specialized, per-language research problem, not a generic payload-library task |
| GraphQL — resolver-level BOLA | **Full** | Field-level differential oracle | Route-level auth checks often don't propagate to individual resolvers |
| GraphQL — batching/alias auth bypass | **Full** | Deterministic — was the rate limit enforced under batching | |
| GraphQL — introspection/schema recovery | **Full** | Direct query if enabled; field-suggestion inference if disabled | |
| GraphQL — depth/complexity DoS | **Full** | Multi-trial complexity-regression against a measured baseline curve | Self-contained, repeatable measurement — no per-target hardcoded threshold needed |
| Clickjacking | **Full** | Structural — response lacks BOTH `X-Frame-Options` AND CSP `frame-ancestors`, confirmed against a framing-attempt render | Deterministic header check; finding requires both defenses absent, not just one |
| CORS misconfiguration | **Full** | Structural — reflected/permissive `Access-Control-Allow-Origin` **with** `Access-Control-Allow-Credentials: true` | The credentialed-reflection pair is the actual finding; a bare `ACAO: *` without credentials is not written as a violation |
| Open redirect | **Full** | Structural — attacker URL injected into a redirect-shaped query parameter (`redirect`/`next`/`returnUrl`/...) echoed verbatim into a 3xx `Location` header | Deterministic single-probe header check, same shape as clickjacking/CORS; the firer never follows the redirect (§10), so the attacker destination is never visited |
| CSRF (missing protection) | **Partial** | Structural — session cookie is sent cross-site (`SameSite=None`) with no anti-CSRF token mechanism present: the deterministic precondition that leaves the app open to forgery. Header/cookie evidence resolved server-side via `run_oracle` | Confirms a precondition only, not a fired exploit. `SameSite=Lax`/`Strict` or a token present → denied; absent `SameSite` → inconclusive (browsers default to `Lax`, so flagging would overclaim). A confirmed CSRF would require firing a forged cross-origin state-change, which read-only-first (§10) forbids |
| Request smuggling | **Weak** | None generic | CL.TE/TE.CL desync detection is front-end/back-end-pair specific and needs raw socket control the transport layer doesn't expose yet; deferred |
| Web cache poisoning | **Partial** | STRUCTURAL — an unkeyed header (`X-Forwarded-Host`) reflected into a cacheable response, replayed into an independent, header-free re-read of the same run-unique cache-busted URL | Detects unkeyed-header reflection generically; a target using a different unkeyed input (a cookie, a different header) or a cache keyed differently is out of reach without target-specific modeling |
| Multi-hop cross-class chains | **Full — core differentiator** | Chain Solver over `enables` / `derived_credential` edges | See §8 |

---

## 6. Graph data model

The graph has two layers: **structural facts** (what the app actually does) and **finding relationships** (how confirmed vulnerabilities connect to each other). Keeping these separate is what lets chaining stay generic instead of needing bespoke logic for every pair of vulnerability classes.

### Node types

| Node | Key attributes |
|---|---|
| `Identity` | role, auth_state (unauth/user/admin/synthetic), provenance (seeded vs. derived-from-finding) |
| `Session` | token/cookie ref, bound Identity, live/expired status |
| `Endpoint` | method, path, content_type, protocol (REST/GraphQL), graphql_operation_type; optional `technology`/`detected_version` when a stack is fingerprinted per-endpoint (transport-tier attributes, §9) |
| `Parameter` | name, location, inferred_sink_type (sql/nosql/shell/ldap/template/file_path/deserialize_target/html_reflection/url) |
| `Object` | type, owner_identity_ref, sensitivity_tier |
| `Host` | **transport-tier (§9).** address (IP or hostname), hostname, source (which recon tool asserted it), optional technology / detected_version. A discovered subdomain is a `Host` (a subdomain is just a hostname) — no separate `Subdomain` node. Detected CMS/framework/version is an attribute here, never a `Technology` node. Facts only: never a finding status |
| `Service` | **transport-tier (§9).** port, protocol (tcp/udp), service_name, banner, detected_version. A port/service pair is a `Service`. Facts only: never a finding status |
| `InternalResource` | for SSRF — internal IP ranges, cloud metadata endpoints, OOB collaborator domain |
| `ExecutionContext` | for injection/RCE-class findings — confirms code execution occurred; deliberately not wired to any interactive/post-exploitation tooling |
| `Finding` | vuln_class, severity, oracle_used, evidence_ref, status |

### Structural edges (surface mapping)

| Edge | Meaning |
|---|---|
| `can_call(Identity → Endpoint)` | empirically confirmed authorization |
| `returns(Endpoint → Object)` | what an endpoint exposes |
| `owns(Identity → Object)` | intended ownership per app-declared roles |
| `accepts(Endpoint → Parameter)` | endpoint's input surface |
| `reaches(Endpoint → InternalResource)` | SSRF-relevant outbound reachability |
| `authenticates_as(Session → Identity)` | which identity a session currently represents |
| `runs_service(Host → Service)` | **transport-tier (§9).** a host exposes a port/service — the nmap-shaped fact |
| `resolves_to(Host → Endpoint)` | **transport-tier (§9).** a host serves an HTTP path — how a gobuster/whatweb-discovered `Endpoint` attaches to the `Host` that serves it |

Two transport-tier edges are the minimal set: `runs_service` attaches the port/service facts a network scanner (nmap) emits to their host, and `resolves_to` attaches the HTTP-path facts a content-discovery/fingerprint tool (gobuster/ffuf/whatweb) emits to their host. Discovered paths reuse the existing `Endpoint` node rather than a new type, so no third edge or node is introduced — the recon facts are absorbed into the schema, not grown per tool (CLAUDE.md).

### Finding-relationship edges (chain mechanism)

| Edge | Meaning |
|---|---|
| `enables(Finding → Finding)` | finding A's output makes finding B possible — the chain edge |
| `derived_credential(Finding → Session \| Identity)` | a finding that yields a usable session or credential spawns a new node the Coordinator treats as first-class |

Every `can_call` and `Finding` edge carries a status: `confirmed_allowed`, `confirmed_denied`, `confirmed_violation`, or `inconclusive`. **Transport-tier nodes (`Host`, `Service`) and edges (`runs_service`, `resolves_to`) carry no status at all** — they are recon facts, never a `can_call`, never a `Finding`, and are never confirmed by an oracle. A recon fact only becomes actionable when a downstream role turns it into an `Endpoint`/`Parameter` the Explorer probes; the transport tier itself asserts nothing about a vulnerability (§9).

---

## 7. Detection and verification strategy

Still six oracle mechanisms — four of them generalized in v1.2 to absorb previously-weak classes, not a new count. This is what keeps the Validator generic instead of needing a bespoke checker per class:

| Mechanism | Classes it covers |
|---|---|
| **Differential cross-identity/cross-request/cross-condition diff** | BOLA, BFLA, GraphQL resolver BOLA, mass assignment, boolean-blind SQLi, NoSQLi (both sub-cases), LDAP (both sub-cases), business-logic price/parameter tampering |
| **Evaluation/execution confirmation** | SSTI (expression evaluated), XSS reflected/stored/DOM — DOM now fed by a Playwright taint-tracking shim that hooks common sinks (`innerHTML`, `document.write`, `eval`, `location`) and sources (`location.hash`, `postMessage`) to discover candidate flows systematically instead of only confirming guessed ones |
| **Out-of-band callback** | Blind SSRF, command injection, OOB-first blind SQLi (tried before falling back to timing) |
| **Timing/statistical (generalized)** | Time-based blind SQLi/NoSQLi/LDAP, always paired against a negative-control trial to rule out network jitter; GraphQL complexity regression (latency measured as a function of query depth, fit against a baseline curve rather than a hardcoded threshold) |
| **Structural verification** | JWT forgeries, file upload/path traversal (retrieved content matched against a known artifact), clickjacking (both framing defenses absent), CORS misconfiguration (credentialed ACAO reflection), CSRF missing-protection (`SameSite=None` cross-site cookie + no anti-CSRF token — a structural precondition, no forged state-change fired); also CVE-match evidence — a fingerprinted version matched against a known-vulnerable range is treated as structural evidence, still confirmed by this family, never self-reported |
| **Business-rule / invariant anomaly check** | Known business-logic patterns via a 4-template library (single-use reuse, quantity/limit, price tamper, step-order) run as cheap sequential replay; race conditions reuse the *same* anomaly check, escalated to single-packet concurrent delivery only when sequential replay finds nothing — the graph must first identify a consumable/limited resource before this technique is worth pointing at it, and it remains lower-priority than the other five |

**Rule, unconditionally:** the LLM can propose a candidate; only a Validator-run deterministic check produces a `Finding` node.

---

## 8. Multi-hop, cross-class chain discovery

**Mechanism:** any finding that yields a new credential, elevates an identity's effective privilege, or produces attacker-controlled content another principal will render or execute spawns a new `Session`/`Identity` node or a new edge, and the Chain Solver re-runs reachability queries from that point.

**Worked example — the chain from §1's positioning claim:**

```
Low-privilege identity
  → confirmed Stored XSS finding (payload targets an admin-viewed field)
  → Playwright oracle confirms execution in the admin's session context
  → derived_credential edge spawns a new Session node bound to the admin Identity
  → Coordinator re-queries can_call edges for that session
  → discovers an admin-only endpoint that itself has an SSRF-vulnerable parameter
  → confirmed SSRF reaches an internal service via reaches edge
  → enables edge links the XSS Finding to the SSRF Finding
  → Report: one connected chain, not two disconnected low/high-severity bugs
```

Other examples: mass assignment that privilege-escalates the *acting identity itself* (no new node needed — the Coordinator just re-tests that identity's existing `can_call` edges); a confirmed SSRF reaching cloud metadata that yields a usable token (`derived_credential` into a new synthetic `Identity`, tested against internal-only endpoints).

This uniform spawn-and-requery mechanism is the actual differentiator versus every siloed, single-class scanner in the current landscape.

---

## 9. Payload strategy

**Custom, tagged payloads remain a core strength of the system.** ReachAgent's own payload library and its own deterministic oracles are the system of record for what counts as a confirmed finding — nothing is delegated to an external scanner's judgment (see below). The library is seeded from the full PayloadsAllTheThings and SecLists repositories, vendored under third_party/, ingested via a folder-to-(vuln_class, inferred_sink_type) mapping and a regex rule table for oracle_type assignment. Every entry is tagged on ingest; untagged entries are not loadable. Corpora expand the payload set; they never expand what counts as confirmed — every payload, vendored or hand-written, still routes through `run_oracle`.

### The pipeline as actual tool calls

Fingerprinting, sink matching, selection, mutation, and verification aren't abstract steps — each is a named tool call from the §13 manifest, which is what makes the pipeline auditable end to end rather than a description of LLM vibes:

1. **Fingerprint** — `fingerprint_parameter(endpoint, param)`. The Explorer sends a benign canary first and reads reflection behavior, error signatures, and response content-type. This sets `inferred_sink_type` on the `Parameter` node (`sql`, `nosql`, `shell`, `ldap`, `template`, `file_path`, `deserialize_target`, `html_reflection`, `url`, ...). Nothing downstream fires before this completes. Since v1.11, when the benign canary infers **no** sink and no `sink_hint` was supplied, a single **error-triggering diagnostic probe** fires with the quote-appended value `"<canary>'"` — a fingerprinting primitive, not a corpus payload — matched against the SQL error signatures to surface quoted-param error-based SQLi (the live-VAmPI gap: a canary that sits *inside* SQL quotes returns a clean 404, hiding the sink).
2. **Sink-matched selection** — `get_payloads(vuln_class, sink_type)`. Returns only the tagged entries relevant to the inferred sink, ordered by oracle confidence (§7) — OOB-capable entries before pure-timing ones for injection classes, cheap sequential-replay before expensive concurrent delivery for business-logic/race classes. A parameter fingerprinted as `html_reflection` is never handed a SQLi payload, and vice versa.
3. **Light, context-aware mutation** — inside the `get_payloads` → `fire_request(identity, endpoint, payload)` cycle. If a base entry is blocked (a WAF signature match, an unexpected sanitization pattern surfaced during fingerprinting), the Explorer may generate a small variant — always a transformation of a library-anchored entry, never invented from scratch — carrying its parent's `vuln_class`/`sink_type`/`oracle_type` tags forward so it still routes to the correct oracle.
4. **Deterministic verification** — `run_oracle(mechanism, evidence)`, called by the Validator, never the Explorer. Only a `confirmed` result from one of the six families in §7 unlocks `write_finding`, the only tool that commits a `Finding` node.

A full worked trace of this sequence across all three roles is in §13.

Payload library schema:
```
{vuln_class, context, inferred_sink_type, oracle_type, payload_ref, graph_edge_on_success}
```
Sourced and restructured from PayloadsAllTheThings, OWASP WSTG, and PortSwigger Academy. The system's value is in the tagging, sink-matching, and oracle wiring — not in reinventing payload strings.

**Not every class is payload-library-driven.** Business-logic templates and race conditions are request-*sequencing* and *timing-delivery* tests — they skip `get_payloads` entirely. Blind SQLi, NoSQLi, and LDAP extraction share one paired-trial mechanism (a real payload plus a negative control, repeated N times) rather than separate per-class logic.

**v1.11 payload-strategy additions (no new family):**

- **Template-first ordering** — `get_payloads` sorts by `(confidence_rank, is-template-ref, payload_ref)`: hand-authored oracle-proven templates fire before bulk corpus line-locators, so the definitive payload (e.g. the SQLi quote-break `'`) fires at attempt 1 rather than after N MySQL-oriented corpus variants.
- **Sibling-list baseline discovery** — for a path-param endpoint (`/users/v1/{username}`), the differential `DATABASE_ERROR` baseline is harvested from the sibling list endpoint (`/users/v1`, placeholder segment removed): a read-only GET, unwrap any plural-key list wrapper (`{"users": [...]}`), and take the first matching field value. The baseline is then genuinely 2xx-served rather than a literal that 404s — fixing the baseline VALUE, never weakening the oracle's baseline-GRANTED guard.
- **Spec-first API discovery** (`recon/api_discovery.py`) — before any combinatorial guessing, read-only probes for machine-readable specs (`/openapi.json`, `/swagger.json`, `/v3/api-docs`, …) and GraphQL introspection (reusing `graphql.module.discover_schema`); a found spec materializes `Endpoint`/`Parameter` facts exactly. Only when no spec answers does a bounded combinatorial fallback (`{api,rest,v1,v2…} × {users,books,…}`, ≤ ~50 GETs) run. Found-nothing is a valid honest result; two-segment API routes are otherwise not flat-wordlist-discoverable.

### External scanners: explicitly not a core dependency

sqlmap, Nuclei, ZAP, Burp Scanner, Caido's Scanner, and similar tools are not shelled out to, wrapped, or orchestrated as part of detection, in any phase through Phase 7:

- Their detection logic is a black box to the graph — a finding from an external scanner can't be traced back to a specific `run_oracle` mechanism, breaking the invariant that every `Finding` node carries its own confirming evidence.
- Template/signature-based scanners (Nuclei especially) are known to produce false positives against custom application logic — reintroducing exactly the noise the deterministic-verification principle exists to eliminate, just from a different source than an LLM.
- It would blur what ReachAgent actually contributes: the tagged-payload-plus-deterministic-oracle pipeline and the graph built on it, not an aggregation of other tools' output.

**Deferred, optional: an ingestion mode.** A future mode could import external-scanner findings as *candidates* — the same unverified status an Explorer-discovered lead has, never a pre-confirmed `Finding`. An imported candidate still has to pass through `run_oracle` before it's written as `confirmed_violation`, exactly like anything ReachAgent found on its own. Not scheduled in §15; revisit only after Phase 7.

### Tool-orchestration tiers

The external tool universe is large and growing (hundreds of recon, scanner, exploitation, and AI-agent tools). We do not maintain a whitelist. Instead every tool is placed by **what its output is** — a fact, a claim, or a transport — into exactly one of three tiers. None of the three can produce a `Finding`:

| Tier | Output is | Examples (non-exhaustive) | Role in the graph |
|---|---|---|---|
| Recon / transport | A **fact** (endpoint, param, subdomain, detected version) | Nmap, Amass, subfinder, theHarvester (network/service + subdomain recon); ffuf, feroxbuster, dirb, gobuster, katana (content discovery); httpx, wappalyzer, whatweb (CMS/framework fingerprinting); wpscan (passive/fingerprint mode only), nikto (informational mode) | Emitted as transport-tier graph nodes/edges — never a candidate, never a finding |
| Signal-gated exploitation | A **claim** of a vulnerability | sqlmap, Nuclei (template-matched claims), Wapiti, Arachni, Metasploit modules, wpscan (active-check mode), nikto (vulnerability-claim mode), PentestGPT-style agents | Invoked only as a candidate *source*, and only once the graph already holds a signal for that class; output is an unverified candidate that still passes `run_oracle`. Never self-reports a confirmed finding |
| Transport aggregator | A **transport** (carries requests/responses) | HexStrike, Burp/Caido MCP, any multi-tool MCP | A fire transport, not a detector. Built-in scanners stay off (§13) |

**Named activations (v1.6), each gated on an existing graph signal for its class:**

- **sqlmap** — signal-gated exploitation. Invoked only after ReachAgent's own probe has raised a SQLi-class signal on a parameter (a `sql` `inferred_sink_type` or a boolean/timing lead); its output is an unverified SQLi candidate that still passes `run_oracle`.
- **nikto** — signal-gated exploitation. Invoked only after a server/technology or version signal already exists for the class it would claim (e.g. a fingerprinted stack or CVE-range lead); its output is an unverified candidate that still passes `run_oracle`, never a self-reported finding.
- **ffuf, dirb, feroxbuster** — recon / transport, **not** signal-gated. They are content-discovery fuzzers that emit endpoint/path *facts*, not vulnerability *claims*, so they sit in the recon row and feed transport-tier graph nodes/edges — never a candidate, never a finding. They are not gated on a class signal because they make no class claim.
- **nikto, wpscan** (v1.7) — split by output mode, per the tier rule. nikto's *informational* mode and wpscan's *passive/fingerprint* mode emit facts → recon tier; nikto's *vulnerability-claim* mode and wpscan's *active-check* mode emit claims → signal-gated, each gated on an existing class signal and routed through `run_oracle`.
- **All-in-one autonomous pentest frameworks (HexStrike and similar) are not adopted as orchestrators** — their own agentic decision-making would bypass `run_oracle`'s confirmation authority. Their underlying individual tools remain usable via the tiers above.

The tier is decided by the nature of a tool's output, not by its name — any current or future recon/scanner/exploitation tool maps to exactly one tier by this test. A tool that both recons and exploits (increasingly, one autonomous agent does both) is split by output: its facts enter the recon tier, its claims the signal-gated tier. Nothing from any tier is written as `confirmed` without passing ReachAgent's own `run_oracle`. This is the §9 invariant restated at the orchestration boundary, not a loophole around it.

---

## 10. Safety controls

- Strict **scope allowlist**, enforced at the execution layer at call time — not just documented policy
- **Read-only-first**: no state-changing request fires until the read-only case is confirmed safe
- Idempotency/rollback awareness for any test that must hit a mutating endpoint
- Rate limiting and stealth **off by default**, opt-in only
- No destructive actions without explicit escalation
- Isolated session/token store per test identity
- Full, clear logging of every action taken, for audit and reproducibility

---

## 11. Cost controls

- Per-test-path budget cap (~40 tool calls or a fixed $ ceiling) before the Coordinator abandons a path as a dead end — resource consumption correlates negatively with success in published multi-agent pentest results, so this doubles as a stopping heuristic, not just a cost saver
- Prompt caching for recurring context (target fingerprint, graph state, payload library slices)
- High-volume, low-judgment calls routed to the cheapest reliable model; reasoning-tier calls reserved for Coordinator strategy and Validator confirmation

---

## 12. Recommended tech stack

| Layer | Technology |
|---|---|
| Orchestration | Claude API tool use (three-role split); LangGraph is a reasonable orchestration substrate if you want explicit state machines around the agent loop |
| Graph store | NetworkX in-process for Phases 1–2 (fast to iterate); Neo4j once the finding-relationship layer and chain queries are the bottleneck — Cypher fits `enables`/`derived_credential` traversal naturally |
| Execution | HTTPX for request firing, Playwright for browser-context oracles (XSS confirmation, DOM sinks) |
| Proxy | mitmproxy or Caido for capture/replay |
| OOB/collaborator | Self-hosted interact.sh instance |
| Race-condition module | HTTP/2 single-packet delivery (Turbo Intruder's published technique, reimplemented or shelled out to) |
| Payload store | Base slice in YAML; the bulk corpus is the **vendored PayloadsAllTheThings + SecLists snapshot under `third_party/`**, ingested at load time via a folder→(vuln_class, sink) map + a regex oracle-tagging table (§9). Current ingest is ~14.5k entries; `get_payloads` filters an in-memory list in sub-millisecond time, so **SQLite is still deferred** — it becomes warranted only if the `(vuln_class, inferred_sink_type)` lookup is a measured bottleneck (an order of magnitude more entries, or per-request re-loading). Every entry tagged on ingest; raw strings stay behind a `source/relpath#Ln` locator, read on demand (network-free) |
| Reporting | Markdown + JSON for machine-readable chain data, optional HTML render for human review |

---

## 13. Tool-calling architecture

Tool calling is not an implementation detail sitting underneath the three agent roles — it's how those roles are actually defined and bounded. Every capability in §4 through §9 exists as a named tool call, not free-form model behavior.

### Core tool manifest

| Role | Tool | Purpose |
|---|---|---|
| Explorer | `fingerprint_parameter(endpoint, param)` | Sends canary values, sets `inferred_sink_type`; context-aware class-prioritization — the LLM may propose the likely class to probe first, but the oracle still confirms |
| Explorer | `get_payloads(vuln_class, sink_type)` | Sink-matched lookup from the tagged payload library, ordered by oracle confidence |
| Explorer | `fire_request(identity, endpoint, payload)` | Executes an HTTP request via the HTTP client / Burp-or-Caido MCP proxy; returns a network fire handle |
| Explorer | `fire_browser(identity, url, inject_shim=True)` | Drives a Playwright browser context: navigates `url`, installs the §7 DOM taint-tracking shim via `addInitScript` before load, returns a browser fire handle carrying captured taint events. Browser-side transport — distinct from `fire_request`'s network-side transport, not a flag on it. Explorer-owned, same boundary as `fire_request`; the taint evidence it captures is consumed by `run_oracle`'s execution-confirmation family (Validator), never confirmed by the Explorer |
| Explorer | `classify_response(response)` | Raw signal extraction — status, length, error strings; produces a candidate handoff, never a confirmation |
| Coordinator | `query_graph(filter)` | Pulls untested edges, recent findings, spawned identities |
| Coordinator | `score_and_select(candidates)` | Applies the §4 scoring rule, returns the next test |
| Coordinator | `check_budget(path_id)` | Enforces the per-path budget cap (§11) |
| Validator | `run_oracle(mechanism, evidence)` | Executes one of the six deterministic families (§7) — the only tool that can produce a `confirmed` result |
| Validator | `write_finding(finding)` | Commits a `Finding` node — gated entirely behind a `confirmed` result from `run_oracle` |
| Validator | `mark_inconclusive(edge)` | Writes back a negative result so the edge isn't retested |

**Tool access is role-bounded, not just role-described.** The Explorer can call `fire_request` and `fire_browser` but never `write_finding` — it generates candidates, not confirmations. The Coordinator never calls `fire_request` or `run_oracle` directly — only `query_graph`, `score_and_select`, and `check_budget`. Only the Validator can call `run_oracle` and `write_finding`. Implemented as separate tool subsets per role, this is what makes "only a deterministic check can produce a finding" enforceable in code, not just stated as a principle.

### Worked trace — one test, start to finish

```
1.  Coordinator  query_graph(filter: untested edges for identity=user_b)
2.  Coordinator  score_and_select(candidates) → (user_b, /orders/{id}, param=id)
3.  Coordinator  check_budget(path_id) → cleared
4.  Explorer     fingerprint_parameter(/orders/{id}, id) → inferred_sink_type=sql
5.  Explorer     get_payloads(vuln_class=sqli_blind, sink_type=sql) → OOB-capable entries first
6.  Explorer     fire_request(user_b, /orders/{id}, oob_payload) → no callback
7.  Explorer     fire_request(user_b, /orders/{id}, timing_payload) → WAF block observed
8.  Explorer     [light mutation of timing_payload, same tags carried forward]
9.  Explorer     fire_request(...) × N trials + negative control
10. Explorer     classify_response(...) → candidate, timing delta above baseline
11. Explorer →   Validator: candidate handoff
12. Validator    run_oracle(mechanism=timing_statistical, evidence=trials+control) → confirmed
13. Validator    write_finding({vuln_class: sqli_blind, oracle_used: timing_statistical, ...})
14. Graph        edge status → confirmed_violation; Chain Solver re-queries from updated state
```

Every line is a tool call or a direct consequence of one — there's no step where "the LLM just decided it looked vulnerable."

### Supporting MCP integrations

Infrastructure ReachAgent consumes to *implement* the tools above — not a replacement for them, and not a detection mechanism in their own right. Burp's and Caido's own built-in scanners specifically are not used (§9):

| Component | MCP server | Backs which tool |
|---|---|---|
| Browser oracle (XSS execution confirmation, DOM taint-tracking) | **Playwright MCP** — Microsoft's official `@playwright/mcp`, 40+ tools via accessibility-tree snapshots | `fire_browser` (the dedicated browser fire tool, added to the core manifest above for Phase 3 — `fire_request` stays network-side only), and `run_oracle`'s execution-confirmation family. The §7 taint-tracking shim is installed by `fire_browser` via `addInitScript`; this resolves the v1.3 open question of whether the browser integration exposed a sufficient script-injection path |
| Proxy / traffic capture and replay | **Burp Suite MCP Server** (PortSwigger's official extension) or **Caido's MCP integration** — capture/replay only | `fire_request`. Vendor-maintained, the right trust bar for something in the request path |
| Graph store queries (Phase 2+, once past NetworkX) | **Neo4j MCP** — official `neo4j/mcp` | `query_graph`, `write_finding`, `mark_inconclusive` |

### Expose ReachAgent's own tools as an MCP server

Build the manifest above as actual MCP tools starting in Phase 1, not only as internal functions the Coordinator calls once it exists. Before the §4 scoring rule is built, the same tools can be driven by hand from Claude Desktop or Claude Code — a faster debug loop — and nothing changes when the autonomous Coordinator takes over in Phase 5, since it calls the identical tool contracts a human was using.

### Autonomous scan entrypoint + durable state (v1.12)

Since `v1.11` the autonomous loop is **generic-first**: every vuln is found via `scan/entrypoint:scan_target` → `recon/api_discovery` spec-first + `SurfaceMapper` if `--surface` given → cold-start `REACHAGENT_RECON_LIVE` gating → `Coordinator query_graph → score_and_select → check_budget → payload_chain fingerprint → get_payloads(sink-matched, template-first) → resolve_entry + mint_fire_kit → fire_request baseline/probe → run_oracle(entry.oracle_type) → write_finding on is_violation` with `fire_ref`/`verdict_ref` handle indirection. `eval/mcp_session` single helper verifies this harness at three call sites (VAmPI harness, Juice Shop live, crAPI BOLA). `generic-gap-audit.md` documents the removed bespoke `harness.py` / `juiceshop_live.py` endpoint/payload literals now corpus/graph-derived; `payload_chain._evidence_for` honors `PROBE_UNAUTHORIZED/cross_identity` (BOLA), `cross_request RESPONSES_INVARIANT` (IDOR/mass), `DATABASE_ERROR`, `union_extraction/jwt_forgery/ssrf_response/OOB` where sentinels come from `graph.objects()` with hardcoded fallback only when the graph is sparse (hermetic). The CLI is `reachagent-scan --target URL --in-scope PATTERNS [--out-of-scope …] [--surface FILE] [--state FILE] [--resume FILE] [--live]` (`scan/entrypoint.py`, `scan/cli.py`): dry-run default (zero fired); `--live` runs the generic loop until budget exhaustion. `--surface FILE` seeds declared surface through `SurfaceMapper` (optional). `--state`/`--resume` persist/restore graph + ChainSolver ledgers + audit tail (`graph/persistence.py`, deterministic atomic JSON, token VALUES never serialized) so a crashed run resumes continue-not-replay; RECOVER re-surfaces interrupted `derived_credential` pairs and re-queries errored (never inconclusive) edges. Scope allowlist + read-only-first hold on every probe through the gated `RequestFirer`. `reachagent-tui` (`tui/app.py`, `textual` MIT, ponytail reuse) is a pure observer (no oracle/firer beyond reading `AuditLog.entries` + `ReachabilityGraph`) — three panes: `Tree` Host/Service/Endpoint + scope `technology/wildcard_shape/access_restricted`, `DataTable` `Finding` `vuln_class/severity/oracle_used/evidence_ref + chain_paths`, `Log` `AuditLog` tail `fired:/refused_`; `0.5 s` poll via `set_interval`, `Footer` bindings `j/k Tab / filter q quit` (no mouse), shares the same `scan_target` entrypoint so TUI adds no new confirmed path.

### Other integrations — scoped honestly

- **Notification webhook** on any `confirmed_violation` above a severity threshold — optional, fits once the Coordinator exists in Phase 5
- **Ticketing/reporting** (GitHub Issues, Jira) — deferred; Markdown/JSON reporting is sufficient through Phase 7
- **CI/CD triggering** — out of scope, same treatment as the C2/mobile exclusions in §1
- **External scanner ingestion** (sqlmap, Nuclei, ZAP) — deferred and optional per §9, not a Phase 1–7 dependency
- **Recon-tier tool MCPs** (any fact-emitting tool: ffuf/feroxbuster/subfinder/wappalyzer/…) — optional, feed transport-tier structural facts only, per the §9 tier rule; never a detection dependency
- **Signal-gated exploitation-tier tools** (any claim-emitting tool: sqlmap/Nuclei/wpscan-active/…) — optional candidate sources gated on an existing graph signal, output still passes `run_oracle`; deferred, same treatment as external-scanner ingestion in §9
- **Secrets management** for test-identity credentials — environment-based or a local secrets store, never hardcoded, consistent with §10

---

## 14. Evaluation plan

| Target | Validates |
|---|---|
| **VAmPI** | Baseline BOLA/IDOR/mass assignment/JWT precision-recall — ships with a built-in vulnerable/not-vulnerable toggle purpose-built for measuring false positive/negative rate against ground truth. **Numeric gate: ≥90% precision and ≥80% recall with the toggle on; zero confirmed findings with the toggle off.** |
| **crAPI** | Stateful, multi-step BOLA and business-logic chains, plus an SSRF-relevant flow — validates the graph catches cross-flow object reuse. **Numeric gate: 100% of crAPI's documented multi-step BOLA scenarios (vehicle-location and mechanic-contact chains) reconstructed end-to-end, with zero destructive side effects logged during the run.** |
| **OWASP Juice Shop** | Target-specific API-only evaluation against the pinned image. The strict denominator is the nine keys in `VERIFIED_CHALLENGE_SCOPE`, not all tracker rows. Current deterministic `fire_request` → `run_oracle` → `write_finding` paths cover **6/9 (66.7%)**: the three SQLi auth-bypass keys, `unionSqlInjectionChallenge` and `dbSchemaChallenge` only when their exact user/schema extraction sentinels appear in the successful search response, and `nullByteChallenge`, whose poison-null package-artifact result is labeled `file_upload` as an input-validation finding. `uploadSizeChallenge` and `uploadTypeChallenge` lack persistence/retrieval/execution evidence: `/file-upload` returns empty `204` responses, rejects oversize input with Multer `500`, and has no artifact URL; timing overlap and an invalid `ok.jpg` baseline do not establish a bypass. `localXssChallenge` requires browser-rendered DOM execution and tracker attribution unavailable to the API-only runner. Generic §5 class ratings do not imply target-specific coverage. |
| **PortSwigger Web Security Academy — blind SQLi labs** | Dedicated ground truth for the OOB-first/paired-timing blind SQLi oracle specifically, since Juice Shop doesn't cleanly isolate the blind case. Task 9a runner targets the **Blind SQL injection with time delays** lab by default: timing fallback uses the existing `timing_statistical` family and needs only lab URL/session token/live opt-in; OOB remains dormant until self-hosted interact.sh infrastructure is provisioned. |
| **DVGA** | Dedicated GraphQL ground truth — introspection, batching, resolver BOLA, depth/complexity |
| **PortSwigger Web Security Academy race-condition labs** | Purpose-built ground truth for the single-packet module specifically |
| **Authorized real-world target** | Only after documented precision/recall on all five above, with written scope |

**Consolidated Phase 7 gate (v1.12):** `python -m reachagent.eval` drives every env-gated target gate in one run — VAmPI, crAPI, Juice Shop fresh-container, PortSwigger blind-SQLi, DVGA GraphQL — and emits one composite report + verdict + exit code (`eval/consolidated.py`, `eval/__main__.py`). Live-proof `REACHAGENT_JUICESHOP_EPHEMERAL=1 python -m reachagent.eval --target juiceshop` is **PASSED 6/9 (66.7%) 0% FP** and `python -m reachagent.eval --target vamp` is **PASSED 100% precision/100% recall OFF zero**; `python -m reachagent.eval` composite is **PASSED when only locally-provisionable gates run (vamp+juice PASS, crapi/portswigger/dvga SKIPPED)**. Each target gate is env-gated: an unprovisioned target reports SKIPPED (never blocks); a provisioned-but-errored target reports NOT MEASURABLE (exit 2); a verdict is PASSED/FAILED. Composite = all RAN gates passed → 0; any ran gate failed → 1; any ran gate not-measurable → 2; all-skip → not-measurable. The Juice Shop gate judges the documented **6/9 API-only coverage floor** (not the 75% browser-capable floor — `API_ONLY_COVERAGE_FLOOR = 6/9` vs `COVERAGE_FLOOR = 0.75`, and why `7/9` was reverted `flow ≠ executed` inflated FP `0→14.3%` — see `docs/Phase3-decisions.md` D1-D4); fp-rate ceiling stays ≤10%.

---

## 15. Build roadmap

| Phase | Weeks | Scope | Exit criteria |
|---|---|---|---|
| **1 — Foundation** | 1–3 | Project structure, identity/session management, recon, differential-diff oracle, deterministic verification engine, **Explorer/Validator tools built as MCP tools from the start (§13)** for human-in-the-loop testing via Claude Desktop/Code. Target: VAmPI. | ≥90% precision, ≥80% recall with VAmPI's toggle on; **zero** confirmed findings with the toggle off |
| **2 — Graph + stateful chains** | 4–6 | Live graph (structural layer, NetworkX; migrate to Neo4j MCP once chain queries are the bottleneck), crAPI target, multi-step BOLA, business-logic **4-template invariant library** (single-use reuse, quantity/limit, price tamper, step-order) instantiated from recon-discovered resources | 100% of crAPI's documented multi-step BOLA scenarios reconstructed end-to-end via template match, not hand-coded per-scenario logic; zero destructive side effects logged |
| **3 — Full class coverage** | 7–9 | OOB and paired-trial statistical oracle families (blind SQLi OOB-first + negative-control timing; NoSQLi and LDAP extraction reuse same statistical harness); Playwright taint-tracking shim for DOM XSS (`execution-marker __reachagent_exec` additive `flows+executed → violation`, `flows` alone stays violation, `Footer j/k Tab / filter`, observed via `ReachabilityGraph`); file upload/path traversal. Target: Juice Shop + PortSwigger Academy blind-SQLi labs. | Juice Shop uses a clean pinned target and strict nine-key tracker scope. The historical **≥75% (≥7/9)** floor remains outside API-only Docker mode: the final honest deterministic ceiling is **6/9 (66.7%)**—three SQLi auth-bypass keys, two UNION extraction keys confirmed by exact user/schema sentinels (`admin@juice-sh.op` / `CREATE TABLE \`Users\`` now graph-derived with `fallback` when sparse), and the null-byte input-validation key labeled `file_upload` for tracker scope. Upload size/type still lack persistent retrieval/execution evidence, while DOM-XSS lacks browser attribution. False-positive rate must remain ≤10%; reaching 7/9 requires browser-capable DOM attribution plus distinguishable upload evidence. `1552929→71bb535→80002e6→fb9ad02` closed generic-first: corpus/graph-derived via `payload_chain` `McpCaller` `resolve_entry+mint_fire_kit`, `6 families` held, `reachagent-tui` `3 panes` `Footer` observer shares `scan_target` with headless `reachagent-scan`. Retain the PortSwigger blind-SQLi criterion unchanged—currently SKIPPED (not provisioned) per composite. |
| **4 — GraphQL module** | 10 | Schema introspection + field-suggestion fallback, resolver-level differential testing, batching probes, **complexity-regression methodology for depth/complexity DoS** | All DVGA resolver-level BOLA and batching-bypass challenges confirmed; zero false positives on intentionally-public fields; DoS finding confirmed only via multi-trial regression against baseline, zero false positives under repeated baseline-only trials |
| **5 — Agent system + chain solver** | 11–13 | Coordinator/Explorer/Validator split, scoring-rule prioritization live (§4), `enables`/`derived_credential` mechanism live, cost controls, budget caps, prompt caching | At least one full multi-hop cross-class chain (e.g. the §8 XSS→SSRF example) reconstructed end-to-end on a mixed-vulnerability target; average cost per test path stays within the ~40-tool-call / fixed-$ budget cap |
| **6 — Race-condition module** | 14 | Sequential-replay-first escalation (reuses Phase 2's business-logic anomaly-check oracle), single-packet concurrent delivery only when replay alone finds nothing. Target: PortSwigger labs. Scoped as secondary/lower-priority per §7. | Confirmed exploit reproduced on each assigned PortSwigger Academy race-condition lab, matching that lab's documented intended outcome |
| **7 — Hardening + real-world** | 15–16 | Full evaluation re-run across all five test targets, reporting system, safety hardening, authorized real target with written scope | All Phase 1–6 gates re-passed simultaneously in one consolidated run, before authorization to test a real target |

---

## 16. Realistic limitations

- Will not find every possible vulnerability — strongest against known patterns applied systematically and chains built from them, not novel classes with no existing oracle
- Blind SQLi and DOM-based XSS remain statistically weaker for LLM-driven agents industry-wide; budget extra oracle investment here, don't assume solved
- Race conditions and deserialization exploitation are explicitly partial/weak — see §5 for why, not just that
- Quality is bounded by payload library breadth and oracle design quality, not by model capability alone
- Multi-hop chains built from known-class findings are more reliable than discovering genuinely novel, unprecedented business logic flaws
- Best results require multiple test identities across the real role hierarchy — this is a grey-box, bug-bounty-style tool, not a fully black-box one
- Coverage cost scales roughly with identities × endpoints × parameters; budget caps are load-bearing as target size grows, not optional
- Deliberately conservative: because findings require deterministic confirmation, the system under-reports ambiguous cases rather than over-reports them — a tradeoff, not an oversight

---

## 17. Open questions before writing code

- Test identity provisioning strategy per target (manual seeding vs. self-registration where available)
- Confirmed-chain output format — replay script, Postman collection, or both — and how much of the `enables` chain to surface in the human-readable report vs. keep as raw graph data
- How aggressively the race-condition module should attempt automatic limit identification vs. requiring it flagged per engagement
