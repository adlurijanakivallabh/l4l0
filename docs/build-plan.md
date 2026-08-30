# ReachAgent — Evidence-Driven Build Plan

**Plan date:** 2026-08-27
**Scope:** authorized web/API assessment targets and intentionally vulnerable
laboratories only.
**Rule:** this document is a plan, not an implementation. Every implementation
phase stops after its focused review, test gate, commit, and documentation update.

## 0. Confirmed baseline

### 0.1 Repository facts

These facts were verified from the complete repository history, the locked
architecture plan, source inventory, and current checkout:

- 175 commits; current commit `174bfaf` (`fix gui provider default routing`).
- 144 Python modules under `src/`; 89 Python test files.
- 23 orchestrated detection classes.
- 35 LLM-selectable tool adapters: 29 recon/insertion adapters and 6
  signal-gated claim adapters.
- 6 deterministic oracle families.
- NetworkX is the default graph store; a Neo4j-through-MCP parity backend exists.
- FastAPI/static web GUI is the primary entrypoint.
- MCP server exposes Explorer and Validator capabilities; Coordinator tools remain
  internal to the autonomous loop.
- Last recorded fresh whole-tree run: 1,154 passed, 3 skipped, 5 failures.
  The one local payload-slot regression was fixed, and the four external-service
  startup races passed in focused reruns. No deterministic local failure remains.
- The latest focused GUI gate passed 8 tests. The latest transport-focused gate
  passed 10 tests.
- No source files or project files are deleted by this plan.

### 0.2 Detection inventory

The current orchestrator names these classes:

`sqli`, `sqli_blind`, `nosqli`, `ldap_injection`,
`command_injection`, `xss_reflected`, `xss_stored`, `xss_dom`,
`ssti`, `ssrf`, `path_traversal`, `file_upload`, `jwt_forgery`,
`bola`, `bfla`, `mass_assignment`, `idor`, `business_logic`,
`clickjacking`, `cors_misconfig`, `csrf_missing_protection`,
`graphql`, and `race`.

Coverage is not claimed merely because a string appears in this list. A class is
credited only when its current deterministic evidence path can produce a
`confirmed_violation` verdict and a Validator-gated finding. Current honest
limits remain:

- blind SQLi, blind NoSQLi, LDAP extraction, DOM XSS, CSRF, race conditions,
  and novel business logic are partial or statistically bounded;
- request smuggling, cache poisoning, and generic insecure-deserialization
  exploitation do not yet have a safe generic confirmation path;
- the API-only Juice Shop gate is 6/9, not the historical browser-capable 7/9
  target.

### 0.3 Tool inventory

Recon/fact adapters:

- `nmap`, `masscan`, `rustscan`, `naabu`
- `subfinder`, `amass`, `bbot`, `dnsrecon`, `shuffledns`, `dnsx`, `theHarvester`
- `whatweb`, `httpx`, `katana`
- `gobuster`, `ffuf`, `feroxbuster`, `dirb`
- `waybackurls`, `gau`, `urlfinder`, `wafw00f`
- `testssl`, `sslscan`, `sslyze`, `wpscan`
- `arjun`, `paramspider`, `x8`

Signal-gated claim adapters:

- `sqlmap`, `nuclei`, `nikto`, `dalfox`, `commix`, `jwt-tool`

The first group emits only graph facts. The second group can emit only inert
claims, and every claim must still pass the existing deterministic oracle gate.

### 0.4 Confirmation inventory

The registered mechanisms are:

1. `differential`
2. `execution_confirmation`
3. `oob_callback`
4. `timing_statistical`
5. `structural`
6. `business_rule_invariant`

The invariant is fixed across all phases:

`LLM proposal → allowlist validation → execution evidence →
deterministic oracle → Validator write`.

The LLM never confirms a finding. A tool's own “vulnerable” output is never a
finding. A missing or ambiguous signal is reported as inconclusive or
not-applicable.

## 1. Reference-reading map (licenses recorded before code review)

The repository intentionally uses neutral aliases so reference names do not
appear in project code, comments, docs, or commits.

| Alias | License | Top-level architecture files already read | Role in later phases |
|---|---|---|---|
| **R1** | MIT | Go server entrypoint/router; React/Vite entrypoint and route tree | service lifecycle, provider persistence, GraphQL API, GUI state/layout |
| **R2** | dual: MIT for the agent-origin subtree; research-use-only for the authored core | FastAPI application/server; agent factory; orchestration agent | API/SSE lifecycle, provider selection, agent cloning, handoffs, MCP/session plumbing |
| **R3** | MIT | legacy entrypoint; unified agent, task, tool server, normalized types | backend-neutral agent loop, event normalization, sandbox and MCP process boundaries |
| **R4** | MIT | ReAct agent entrypoint, reasoning layer, standalone engine, local server launcher | iterative observe/think/act loop, working memory, retries, tool summaries, JSONL history |
| **R5** | MIT | Flask server initialization/main; FastMCP client setup/main | large tool catalog, async jobs, cache/recovery, proxy/repeater transport, health endpoints |
| **R6** | Apache-2.0 | scan interface, top-level runner/coordinator, React viewer entrypoint/app | scan preflight, model warm-up, bounded agent coordination, polling viewer, reports |
| **R7** | MIT | vendored payload corpus metadata and machine-readable files | payload breadth and provenance; never a confirmation authority |
| **R8** | MIT | vendored wordlist metadata and machine-readable files | discovery wordlists only; never an exploit verdict |

**Reading rule for every implementation phase:** before editing, enumerate every
file in the selected reference subtree that touches that phase, read it fully
including called helpers, and record the exact files in that phase's decision
document. The aliases above are only the scope map; they are not permission to
skim.

## 2. Current top-level architecture findings

- **R1:** a long-lived service initializes configuration, telemetry, database,
  provider/controller services, subscriptions, and HTTP routing before serving;
  the frontend is a lazy-loaded React route tree with context providers and a
  GraphQL client. This is a useful lifecycle and GUI-state pattern, not a
  detection design.
- **R2:** the API factory owns session state and command execution in
  application state, exposes health/catalog/session/inference routes, and uses
  SSE for both hook-level and token-level live updates. Agent factories clone
  a base agent with a selected model and optional registry/MCP tools.
- **R3:** one task envelope is rendered per backend; one normalized event model
  folds assistant text, tool calls, file changes, usage, and errors; a stdio MCP
  tool server is launched identically for each backend.
- **R4:** the fallback ReAct loop explicitly keeps working memory, a bounded raw
  observation window, a findings log, loop detection, and a persisted session
  file. Tool summaries are fed back into the next model turn.
- **R5:** the server is a large HTTP façade around subprocess tools and an async
  process manager. It adds retries, caches, health/resource metrics, recovery
  suggestions, and a separate MCP client that forwards bounded tool calls.
- **R6:** preflight/model warm-up is separated from the interactive UI; the runner
  coordinates child agents, budget hooks, persistent run state, and a React viewer
  that polls a run, transcript, and vulnerability endpoints.
- No top-level source was treated as a reusable detection oracle. The plan keeps
  all confirmation in ReachAgent's six-family deterministic registry.

## 3. Web research findings (2026-08-27)

The following current primary documentation was checked before planning:

### Asset discovery and enrichment

- Passive URL collection should support multiple sources, URL/field scope,
  source-level rate limits, JSONL output, and bounded run time.
- ASN/range discovery, exposed-host search, DNS permutation generation, DNS
  resolution, wildcard testing, TLS metadata, HTTP probing, and JS-aware
  crawling form a useful enrichment chain.
- Crawlers need explicit host and URL scope plus an out-of-scope policy; modern
  crawlers can extract XHR and form data, not only anchor links.
- Directory fuzzers benefit from per-host calibration. A robust calibration
  compares negative probes by response size, word count, and line count, and
  only installs a filter when the negative probes would otherwise match.
- API route discovery is materially different from file discovery. Schema-derived
  route dictionaries can preserve method, headers, parameters, and example
  values; depth-based baselines help detect virtual routing and wildcard paths.

### API and stateful testing

- OpenAPI/Swagger and GraphQL should be consumed as first-class surface sources.
- Property-based API testing can generate many schema-valid cases, validate status
  and response contracts, and adapt values from prior responses.
- Stateful API fuzzing learns producer/consumer dependencies so later requests use
  identifiers created by earlier requests; this is the right model for deeper
  authorization and business-logic paths.
- GraphQL testing should model fields, argument types, aliases/batches, introspection
  state, depth, and response-time curves rather than only probing `/graphql`.

### Evidence and integrations

- Structured template engines separate requests, matchers, extractors, workflows,
  dynamic values, and output. ReachAgent may borrow this separation only for
  candidate evidence; its own oracle remains authoritative.
- OOB systems require unique per-request correlation and channel-aware evidence.
- Browser MCPs expose accessibility-tree actions and persistent/isolated browser
  contexts; browser automation is not itself a security boundary.
- Current proxy MCPs can send/replay HTTP/1.1 and HTTP/2 messages, inspect/filter
  history, create repeater requests, and poll collaborator interactions. They
  should be treated as transports and evidence sources, not scanners whose
  verdicts are trusted.
- MCP security guidance requires explicit consent, input validation, access
  control, rate limits, output sanitization, timeout handling, audit logging,
  tool-name disambiguation, and audience-bound authorization tokens.
- Large or long-running results should use progress notifications, task handles,
  or resource links instead of flooding the model context.

## 4. Phase plan

### Phase 1 — Recon graph completeness and adaptive enumeration

**Status:** implemented (2026-08-28); focused gate passed.

**Goal:** turn target-type-aware recon into a bounded, LLM-selected evidence
graph with useful inter-tool handoff.

**Read during this phase:** R1 terminal/tool execution and server lifecycle
files; R2 reconnaissance/tool execution modules; R3 task/event/tool-server
files; R4 recon dispatcher, summary, and loop-memory files; R5 HTTP/process
manager and recon endpoint files; R6 input/preflight files; R7/R8 corpus and
wordlist metadata.

**Look for:** output truncation, structured result schemas, timeout/retry
semantics, progress events, rate controls, scope checks, wildcard/depth
calibration, and how one tool's output becomes the next tool's input.

**Build:**

- added scoped, fact-only adapters for event-stream asset discovery, structured DNS
  records, and passive source-attributed URL discovery;
- expanded the catalog with capability/producer/passive/cost metadata so the LLM can
  choose based on the evidence gap rather than a fixed sequence;
- added an adaptive recon decision loop: after each selected adapter, bounded graph
  and audit state is sent back to the LLM, which may add an unrun catalog tool or
  stop; unknown, repeated, signal-gated, and incompatible choices are rejected;
- preserved target-type dispatch, wildcard/depth calibration, Host/Service/Endpoint
  provenance, and per-tool outcome events;
- tightened content-discovery defaults with non-interactive execution, ACL status
  coverage, optional rate/timeout/calibration controls, and purpose-aware wordlist
  candidates;
- kept every subprocess argument-array based, timeout-bounded, optional, scoped,
  read-only-first, and audited. No candidate, oracle verdict, or finding can be
  emitted by this tier.

**Decision record:** `tests/recon/test_recon_adaptive.py` covers the adaptive
selector, new parsers, scope refusals, and observed-state continuation. The
selection callback is enabled by the strict LLM orchestrator; fixture callers
retain deterministic parsing without a provider.

**Focused gate:** recon parser, calibration, target classification, planner
catalog, scope, and event tests only.

**Exit criterion:** every selected adapter produces either validated graph facts,
an explicit audited skip/refusal, or an explicit error; no adapter can write a
candidate or finding.

### Phase 2 — Endpoint, form, and insertion-point mapping

**Status:** implemented (2026-08-28); focused gate passed.

**Goal:** discover the real callable surface and every safe insertion location.

**Read during this phase:** R1 route/API import and browser-flow files; R2 API
session/command and web-agent files; R3 task/tool schemas; R4 parameter and
JS-analysis dispatch; R5 HTTP testing framework and browser-agent endpoints; R6
viewer/run-input and API-spec utilities; all current ReachAgent
`recon/api_discovery.py`, `recon/mapper.py`, and insertion wrappers.

**Look for:** OpenAPI/Swagger import, GraphQL schema recovery, route dictionaries,
HTML form extraction, JSON/form/multipart inference, XHR/fetch extraction,
cookie/header insertion points, and response-shape normalization.

**Build:**

- represent query, path, JSON/body, form, header, cookie, multipart, and GraphQL
  fields as distinct `Parameter` locations with an explicit serialization plan;
- parse OpenAPI/Swagger path-level and operation-level parameters, local schema
  references, request/response examples, header/cookie fields, and body properties;
- crawl bounded same-host HTML pages read-only, extracting links, hidden/CSRF/file
  controls, form methods/enctypes, and script sources; never submit a form;
- mine bounded JavaScript for fetch/XHR/axios routes, query keys, JSON body keys,
  GraphQL fields/arguments, and content types;
- preserve source, confidence, evidence handles, request headers/body examples, and
  response-shape metadata on graph facts; merge repeated observations without loss;
- make Arjun/X8 parameter facts attach to the reported endpoint rather than the
  first endpoint in the graph;
- let the LLM rank endpoint and parameter node ids while graph-backed validation
  rejects unknown ids and incompatible locations; the Coordinator only receives a
  bounded ordering bonus.

**Decision record:** `docs/decisions-endpoint-mapping-phase2.md` records the full
reference read inventory, license posture, technique/gap decisions, web citations,
and the deterministic boundary proof.

**Focused gate:** `tests/recon/test_endpoint_mapping_phase2.py`,
`tests/recon/test_api_discovery.py`, `tests/phase1/test_surface_mapper.py`,
`tests/phase4/test_graphql.py`, and `tests/recon/test_surface_tuning.py`.

**Exit criterion:** a mapped insertion point cannot reach payload firing until it
has a completed benign fingerprint and a concrete location/serialization plan.

### Phase 3 — Identity, authentication, and session binding

**Status: implemented 2026-08-28.** Identity discovery, form/JSON/GraphQL
submission, OIDC metadata discovery, isolated cookie/bearer material, expiry and
refresh, fail-loud authentication events, and secret-free graph/MCP/UI boundaries
are implemented. See `docs/decisions-identity-phase3.md` for the complete read
inventory, design decisions, and deterministic-boundary proof.

**Goal:** make authenticated coverage reliable across multiple identities.

**Read during this phase:** R1 auth/provider/session service files; R2 API auth,
session manager, and agent context files; R3 backend auth/error event files; R4
cookie/bearer handling and session persistence; R5 proxy session/history files; R6
auth preflight/session files; current ReachAgent `identity/login.py`,
`identity/store.py`, and orchestration identity wiring.

**Look for:** login surface detection, form vs JSON vs GraphQL submission,
redirect/cookie/token capture, refresh/expiry, per-role contexts, CAPTCHA/2FA
failure reporting, and secret redaction.

**Build:**

- retain graph-auth POST and password-form detection;
- add OAuth/OIDC discovery, bearer refresh/expiry, cookie jar isolation, and
  GraphQL login mutation handling;
- bind each credential set to a separate identity and session;
- record only token references in the graph and audit metadata;
- make failed authentication a visible blocked phase, never an unauthenticated
  continuation;
- support owner/non-owner role pairs for differential BOLA/BFLA/IDOR checks.

**Focused gate:** `tests/recon/test_identity_phase3.py`,
`tests/phase1/test_login_detection.py`, `tests/phase1/test_identity_store.py`,
`tests/phase1/test_execution_layer.py`, `tests/phase2/test_crapi_recon.py`,
`tests/phase2/test_mapper_ownership.py`, `tests/phase2/test_crapi_bola_gate.py`,
and `tests/phase4/test_graphql.py` (live-container cases are skipped when the
target is not provisioned).

**Exit criterion:** every request after authentication carries exactly the
selected identity's isolated session material, and no secret enters graph,
browser, audit, or model context.

### Phase 4 — LLM planning and adaptive control loop

**Goal:** replace a mostly upfront plan with a bounded, resumable reasoning loop.

**Read during this phase:** R1 controller/provider orchestration; R2 orchestration
agent, handoffs, model factory, and API streaming; R3 `UnifiedAgent`,
`Task`, `Runner`, normalized events; R4 ReAct loop, loop detector, memory
refresh, and watchdog; R6 core runner, coordinator, budget hooks, and session
manager; current ReachAgent `llm/planner.py`, `scan/agentic_loop.py`, and
`scan/orchestrator.py`.

**Look for:** observe→think→act sequencing, context compaction, retries with
error feedback, handoffs/subtasks, budget accounting, cancellation, resume, and
event normalization.

**Build:**

- keep the strict allowlisted plan schema as the admission boundary;
- make each phase emit a compact deterministic state snapshot;
- let the LLM choose continue, skip, revise, or revisit with a bounded budget;
- carry tool outcomes, graph deltas, failed payload context, and auth state into
  the next turn;
- add loop detection, idle timeout, cancellation, and resumable phase state;
- separate model/provider failures from target/tool failures in the event stream;
- never let an LLM response directly alter oracle status or finding state.

**Focused gate:** planner validation, adaptive decisions, compaction, cancellation,
and resume tests.

**Exit criterion:** the loop demonstrably changes its next action from observed
graph/audit state while all execution and confirmation permissions remain fixed.

**Status (2026-08-28): complete.** `scan.agentic_loop` now owns bounded
observe→propose→validate→apply state with compact graph/audit/tool/auth snapshots,
graph deltas and SHA-256 revisions, four scheduling actions, loop/revisit limits,
idle and cancellation guards, and atomic checkpoint resume. The orchestrator emits
snapshot/model-error/cancellation events and applies only phase scheduling and
priority hints; `scan_target` checks cancellation before discovery, selection, and
payload classes. Focused gate: 37 passed (`tests/scan/test_phase4_control.py`,
`tests/scan/test_agentic_loop.py`, `tests/recon/test_llm_planner.py`, and
`tests/recon/test_recon_adaptive.py`). The full suite remains reserved for Phase 10.

### Phase 5 — Payload library, context selection, and mutation

**Goal:** maximize useful payload breadth without losing sink/oracle provenance.

**Read during this phase:** R1 tool argument/terminal and prompt files; R2
web-pentester and payload/tool registry files; R3 shared MCP tool schemas; R4
payload builder, WAF encoder, and response summarizers; R5 HTTP framework
match/replace and fuzzing functions; R7/R8 payload/wordlist files; current
ReachAgent payload library, corpus, resolver, encoding, and payload-chain files.

**Look for:** tagged payload metadata, source locators, dynamic slots, encoding
variants, WAF response classification, retry ordering, and mutation limits.

**Build:**

- retain source/line provenance and dynamic slot validation;
- add context dimensions for content type, method, framework, auth state, and
  parameter location;
- let the LLM rank only existing tagged payload references;
- allow small parent-preserving mutations (encoding, delimiter, casing, wrapper)
  with a strict per-parent limit;
- feed prior outcomes such as reflection, WAF block, timeout, status change, and
  body delta into the next selection;
- add semantic payload checks so a payload cannot be routed to an incompatible
  sink or oracle.

**Focused gate:** corpus ingest, resolver, encoding, mutation, and payload-chain
tests.

**Exit criterion:** every fired payload has a valid library reference, sink,
oracle family, slot kit, and audited attempt number.

**Status (2026-08-28): complete.** Payload entries now carry optional
content-type/method/framework/auth/location context plus parent/mutation metadata;
context filtering remains sink-exact. Bounded URL, double-URL, delimiter, casing,
and wrapper mutations preserve parent tags and are capped at four children per
parent. LLM payload ordering accepts only bucket references and bounded mutation
descriptors, receives prior attempt outcomes, and never supplies raw payload text.
The resolver caches source lines and MCP binds generated variants to one per-fire
slot kit. Focused gate: 153 passed across corpus, resolver, MCP, payload-chain,
mutation, tuning, and flag-gating suites. The full suite remains reserved for
Phase 10.

### Phase 6 — Deterministic evidence and oracle hardening

**Goal:** improve confirmation quality without expanding authority to the LLM.

**Read during this phase:** R1/R2/R3/R4/R5/R6 validator, reporting, and error
paths; current six oracle implementations, registry, Validator, MCP evidence
adapters, and all detector seams.

**Look for:** evidence schemas, baseline/control requirements, matcher/extractor
separation, statistical controls, replay invariants, and false-positive handling.

**Build:**

- keep the six-family registry fixed unless a written architecture decision
  proves a new family is necessary;
- add typed evidence fields inside existing families only when the shape is
  deterministic and independently testable;
- strengthen baseline/control requirements and invalid-evidence errors;
- attach request/response handles, timing samples, body projections, headers, and
  OOB channel metadata without exposing secrets;
- add explicit inconclusive reasons and negative-result audit records;
- verify by AST and runtime tests that no detector constructs a verdict or finding.

**Focused gate:** every oracle family, registry parity, Validator gate, AST boundary,
and negative-result tests.

**Exit criterion:** same evidence always yields the same verdict; only
`confirmed_violation` can create a finding.

**Status (2026-08-29): complete.** The six-family registry remains unchanged.
Each evidence family now carries an optional bounded metadata projection for
opaque request/response handles, body-projection labels, non-sensitive headers,
timing samples, and OOB channel labels. Invalid status, latency, flow, nonce,
body, and secret-bearing metadata fail closed. Verdicts carry deterministic
reasons; inconclusive decisions can be recorded as negative audit entries; raw
bodies, cookies, and authorization values stay server-side. The Validator and
graph store stamp only safe oracle provenance and reject unconfirmed findings.
Focused AST/runtime checks prove six verdict constructors remain confined to the
oracle modules and detector packages construct neither verdicts nor findings.
The Phase 6 focused gate passed 240 tests with two pre-existing environment
skips; no files were deleted. Full-suite validation remains reserved for the
plan's final release gate.

### Phase 7 — Stateful API and property-based exploration

**Goal:** discover deeper producer/consumer paths and contract failures.

**Read during this phase:** R1 GraphQL/API service and task-flow files; R2 API
commands/session state; R3 task/event/MCP interfaces; R4 API fuzz/param tools; R5
HTTP testing framework; R6 API-spec utilities; current GraphQL, business-logic,
ChainSolver, and mapper modules.

**Look for:** schema-derived value generation, producer-consumer dependency graphs,
state-machine transitions, operation ordering, response-derived identifiers,
invalid-input classification, and replayability.

**Build:**

- derive request templates from OpenAPI, GraphQL, and observed traffic;
- learn producer→consumer identifier edges from response JSON and headers;
- generate schema-valid boundary cases and safe negative controls;
- map state transitions without assuming endpoint order;
- feed discovered producer→consumer dependencies into the structural
  `data_dependency` edge (the finding-only `enables` edge remains reserved for
  confirmed chain findings);
- route all generated requests through scope, read-only-first, audit, and
  deterministic confirmation.

**Focused gate:** stateful sequence, producer-consumer, GraphQL, and business-rule
tests.

**Exit criterion:** a deeper sequence is represented as graph evidence and can be
replayed deterministically; no generated sequence bypasses safety gates.

**Status (2026-08-29): complete.** Stateful execution now accepts bounded model
plans containing only graph endpoint/parameter ids and schema-derived selectors.
OpenAPI/Swagger, GraphQL introspection (including field arguments), Postman, and
same-authority observed traffic are materialized as replay templates. Response
JSON and safe identifier headers are harvested into short-lived bindings; only
SHA-256 references and source/evidence metadata are written to the graph's new
`data_dependency` structural edge. Boundary values and negative controls are
deterministic and contain no attack payload text. Every generated request,
including mutating and GraphQL requests, calls `RequestFirer.fire`, so scope,
read-only-first, and audit gates run before network I/O. Probe steps require an
existing differential or business-rule oracle; controls and observations are
never findings, and no stateful module imports or writes `Finding`. The focused
gate passed 17 tests; changed-module Ruff and strict mypy checks passed. No files
were deleted. The whole-tree test suite remains reserved for the plan's final
release gate.

### Phase 8 — Signal-gated external adapters

**Goal:** make optional scanners useful as evidence sources while never trusting
their verdicts.

**Read during this phase:** R1/R2/R3/R4/R5 tool registries and error/recovery
modules; R6 tool/report state; current signal-gated base, six adapters, signal
selector, and reconfirmation seam.

**Look for:** structured output parsing, template/workflow dependencies, timeout
and retry policy, tool health, result normalization, and claim provenance.

**Build:**

- add only adapters whose output can be independently re-fired and confirmed;
- keep `has_signal()` as a hard precondition before spawning;
- parse claims into inert candidates with endpoint, parameter, source, and
  suggested oracle;
- expose tool version, command policy, duration, exit status, and partial-output
  state in audit events;
- add explicit allowlisted template/workflow selectors instead of arbitrary
  command strings;
- send every candidate through the existing Validator oracle bridge.

**Focused gate:** signal gate, parser, missing-binary, timeout, claim-reconfirm, and
AST no-validator-import tests.

**Exit criterion:** an external tool can accelerate discovery but can never create
a finding without independent ReachAgent evidence.

### Phase 9 — Browser and proxy firing transports

**Goal:** make LLM transport selection real, scoped, and observable.

**Read during this phase:** R1 frontend/browser/network providers; R2 SSE/MCP
session handling; R3 tool-server process lifecycle; R4 browser/recon streaming;
R5 HTTP testing framework, repeater, match/replace, and proxy handling; R6 proxy
client/viewer; current `browser/shim.py`, `browser/playwright_driver.py`,
`mcp/server.py`, and `recon/transport_tuning.py`.

**Look for:** persistent vs isolated browser contexts, actual response status,
cookie/session capture, header rewriting, request history, proxy error handling,
MCP tool annotations, progress, and resource-link handling.

**Build:**

- wire `http`, `browser`, and `proxy` selection into actual firing dispatch;
- capture real browser response status, redirects, cookies, and final URL;
- bind browser-captured sessions into the selected IdentityStore identity;
- keep proxy repeater requests behind the same scope/read-only-first/audit gates;
- add per-tool read-only/idempotent/destructive annotations;
- add progress and cancellation for long browser/proxy operations;
- return opaque handles for bodies, headers, and verdicts.

**Focused gate:** browser/form, DOM marker, proxy/header, cookie binding, scope,
MCP registration, and transport-selection tests.

**Exit criterion:** a selected transport changes only how evidence is collected;
the deterministic oracle remains the sole confirmation path.

### Phase 10 — Multi-hop chaining and durable resume

**Goal:** finish chains from real dependencies and survive interruption.

**Read during this phase:** R1 controller/task persistence; R2 session/context
persistence; R3 resume/events; R4 JSON session and finding history; R5 cache/recovery;
R6 run/session manager and report state; current ChainSolver, graph persistence,
Neo4j parity, coordinator support, and GUI state endpoints.

**Look for:** checkpoint atomicity, bounded histories, derived identities, chain
edge semantics, cancellation, recovery, and idempotent re-entry.

**Build:**

- preserve `enables` only for proven data/control dependencies;
- preserve `derived_credential` only when a deterministic finding produced a
  usable session/identity node;
- persist graph facts, solver budgets, audit tail, and phase state atomically;
- never persist token values, fire handles, or verdict handles;
- resume as continue-not-replay: confirmed and inconclusive decisions are not
  replayed; errored work can retry;
- render chain paths from graph edges, not report prose.

**Focused gate:** chain linking, derived identity, persistence round-trip, resume,
recovery, and backend parity tests.

**Exit criterion:** at least one multi-class path is represented as connected graph
evidence and resumes without duplicating findings or leaking secrets.

### Phase 11 — GUI production workspace

**Goal:** provide a polished GUI grounded entirely in real ReachAgent state.

**Read during this phase:** R1 full GUI frontend source and its live-data
providers; R2 API/SSE frontend contract; R3 normalized event model; R4 live log
and session presentation; R5 health/progress dashboards; R6 full viewer frontend
and report components; current GUI HTML/CSS/JS and API slices.

**Look for:** route structure, theme tokens, responsive layout, live updates,
loading/error/empty states, scan history, agent graph rendering, severity cards,
report export, and accessibility.

**Build:**

- keep the current four grounded views:
  1. launch/provider configuration,
  2. live reasoning/tool/audit scan view,
  3. Host→Service→Endpoint→Parameter surface map and findings/chains,
  4. report viewer/export;
- add explicit scan lifecycle states: queued, running, paused, blocked,
  completed, failed, cancelled;
- show the selected plan, rationale, tool status, budgets, retries, and last
  event without exposing secrets;
- use polling or SSE with backoff, heartbeat, stale-data indicators, and bounded
  tails;
- make provider selection/configuration obvious and auto-select only an
  unambiguous saved provider;
- add keyboard navigation, responsive layout, accessible labels, and safe
  markdown rendering;
- keep all displayed counts, findings, chain paths, and reports sourced from the
  real graph/audit state.

**Focused gate:** GUI API slices plus Playwright smoke checks for launch,
provider test, live events, surface, findings, report, export, refresh, and error
states.

**Exit criterion:** a user can observe a running assessment and understand what
the LLM proposed, what actually ran, what the oracle confirmed, and why anything
was skipped.

### Phase 12 — Reporting, evidence export, and operational history

**Goal:** make every result reviewable and reusable.

**Read during this phase:** R1 report/export/analytics; R2 result/session history;
R3 normalized result/usage; R4 findings/report/chains output; R5 analytics and
health endpoints; R6 report writer, SARIF/PDF/viewer; current
`report/renderer.py`, `report/llm_report.py`, GUI exports, and persistence.

**Look for:** deterministic report fields, severity summaries, evidence links,
chain diagrams, machine-readable formats, redaction, and export failure modes.

**Build:**

- keep deterministic tables as the source of truth;
- add evidence index pages that link findings to opaque request/oracle handles;
- add SARIF or equivalent machine-readable export only after schema mapping is
  specified;
- include scope, identity, tool, payload reference, oracle, evidence, timing,
  and chain precondition metadata;
- redact credentials, bearer values, cookies, raw secrets, and sensitive bodies;
- allow report generation to fail independently without changing findings;
- add scan history comparison using persisted graph/audit snapshots.

**Focused gate:** renderer, redaction, export content-disposition, report failure,
and history comparison tests.

**Exit criterion:** exported reports are deterministic, provenance-complete, and
cannot contain an unconfirmed finding.

### Phase 13 — Race and asynchronous behavior

**Goal:** validate concurrency only when sequential evidence is inconclusive.

**Read during this phase:** R1 HTTP/2/server task execution; R2 async command
execution; R3 cancellation/events; R4 race tool dispatch; R5 concurrent process
manager; R6 runner budget/interrupt code; current `race/module.py`,
`business_logic/runner.py`, and timing oracle.

**Look for:** sequential-first policy, barriers, HTTP/2 multiplexing, duplicate
request validation, cancellation, and response correlation.

**Build:**

- keep the sequential replay as the first attempt;
- require a fresh disposable resource for concurrent escalation;
- verify all concurrent requests are identical and state-changing only after
  read-only clearance;
- correlate every response by request label and reject incomplete batches;
- use the existing business-rule oracle; do not add a race-specific finding
  shortcut;
- expose concurrency mode, count, and evidence completeness in the audit log.

**Focused gate:** race delivery, barrier/cancellation, HTTP/2 precondition, and
oracle evidence tests.

**Exit criterion:** concurrency cannot turn an incomplete batch or ambiguous
response into a finding.

### Phase 14 — Full hardening and evaluation

**Goal:** re-run all gates together and establish a releasable baseline.

**Read during this phase:** R1–R6 final lifecycle/error/report paths; current full
source tree, test tree, compose files, CI configuration, and all phase decision
documents.

**Build:**

- run focused gates for every changed phase;
- run the one authorized fresh whole-tree test suite;
- run the VAmPI vulnerable/secure numeric gate;
- run crAPI ownership/chain gate when provisioned;
- run the Juice Shop clean-container gate;
- run GraphQL and blind-SQLi lab gates when provisioned;
- perform a fresh scope/audit/oracle-boundary review;
- run Playwright against the portal and preserve screenshots outside git;
- document every skip, failure, setup issue, and environment dependency.

**Exit criterion:** all provisioned gates pass simultaneously, unprovisioned gates
are honestly marked skipped, no deterministic local failure remains, and the
release report contains the exact test command/results and commit hash.

## 5. Optional post-plan capabilities (proposal checkpoint only)

After Phase 10, reassess these separately instead of silently adding them:

1. **Request-smuggling evidence** — requires a raw-socket or trusted proxy
   evidence shape and a deterministic desynchronization oracle.
2. **Cache-poisoning evidence** — requires cache-key/variant modeling and a
   deterministic cross-request cache persistence oracle.
3. **Insecure-deserialization evidence** — requires language-specific safe
   canaries and structural confirmation without gadget execution.
4. **WebSocket/API event-surface mapping** — requires a bounded handshake/message
   model and identity-aware replay.
5. **Continuous monitoring** — requires diffable graph snapshots, alert policy,
   and a non-destructive scheduler.

These are not part of the current implementation and must not be claimed as
built until each receives its own read, design decision, focused tests, review,
commit, and documentation update.

## 6. Per-phase completion contract

Every implementation phase follows this exact sequence:

1. Restate the invariants and authorization boundary.
2. Inventory and fully read every relevant reference file and every ReachAgent
   caller/helper it touches.
3. Record the reference technique, current gap, and smallest safe design.
4. Implement only that phase.
5. Run only phase-relevant tests.
6. Self-review with Ponytail; fix findings.
7. Check for reference-name leakage in changed code/docs/commit text.
8. Commit the phase.
9. Update this plan and the relevant decision/audit document.
10. Report files read, techniques learned, files changed/deleted, tests, commit
    hash, and remaining weakness.
11. Stop and wait for explicit approval.
