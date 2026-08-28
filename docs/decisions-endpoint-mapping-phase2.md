---
title: Phase 2 endpoint and insertion-point mapping decisions
tags: [reachagent, phase2, surface]
---

# Phase 2 — endpoint, form, and insertion-point mapping

Date: 2026-08-28. Scope: authorized web/API targets and intentionally
vulnerable laboratories. This phase is facts-only. It does not select a
payload, submit a form, call an oracle, or write a finding.

## Invariants and authorization boundary

`LLM proposal/ranking -> graph-backed validation -> read-only observation ->
structural graph fact` is the only new path. The LLM receives bounded endpoint
and parameter summaries and may supply an ordering only. `ScopeGuard` and
`RequestFirer` remain the packet boundary; `run_oracle` and `write_finding`
remain outside this module. POST/PUT/PATCH/DELETE routes are materialized but
never submitted by discovery. A parameter cannot be used by the payload chain
until the existing benign fingerprint and the explicit serialization branch
have completed.

## Licenses recorded before deep reading

The neutral aliases are intentional: reference project names do not appear in
ReachAgent-owned code, comments, documentation, or commits.

| Alias | License | Phase-2 reuse posture |
|---|---|---|
| R1 | MIT | Technique-level reuse; no verbatim code |
| R2 | MIT for the agent-origin subtree; research-use-only for the authored core | Paraphrased ideas only; no proprietary code copied |
| R3 | MIT | Technique-level reuse; no verbatim code |
| R4 | MIT | Technique-level reuse; no verbatim code |
| R5 | MIT | Technique-level reuse; no verbatim code |
| R6 | Apache-2.0 | Technique-level reuse; no verbatim code |

## Full reference read inventory and resulting techniques

### R1 — browser/content route

Read in full: `R1/backend/pkg/tools/args.go`, `R1/backend/pkg/tools/browser.go`.

The browser contract has explicit `markdown`, `html`, and `links` actions. Its
scraper chooses a private/public backend, rejects binary URLs, bounds content,
and runs content and screenshot retrieval concurrently. It returns links as
follow-up inputs, but does not expose DOM controls or API request bodies. This
motivated a separate structural parser rather than treating rendered content
as an endpoint map.

### R2 — web-agent fetch and request analysis

Read in full: `R2/src/agents/web_pentester.py`,
`R2/src/agents/orchestration_agent.py`, `R2/src/agents/selection_agent.py`,
`R2/src/tools/web/fetch_url.py`, `R2/src/tools/web/headers.py`, and
`R2/src/tools/reconnaissance/curl.py`.

The web specialist combines command execution, static fetch, and request/response
analysis. The fetcher pins DNS results, manually validates each redirect, caps
bytes/chars, classifies HTML/JSON/text, and clearly reports JavaScript-only
pages. The request helper keeps method, headers, cookies, query, and body as
separate inputs. ReachAgent adopts the separation and bounded output while
retaining its own scope and read-only gates; it intentionally does not adopt
the helper's unrestricted HTTP path.

### R3 — typed discovery tasks and grounded receipts

Read in full: `R3/unified_agent/task.py`, `R3/unified_agent/types.py`,
`R3/agent/src/agents.py`, `R3/agent/src/plan.py`, and
`R3/agent/src/execution.py`.

Discovery is a distinct task kind from enumeration and exploitation. Tasks copy
an allowlisted target exactly, carry explicit dependencies/basis observations,
and finish only with a contiguous, actionable endpoint/parameter receipt. This
became the design rule for surface evidence: source/confidence/opaque evidence
handles are attached to facts, while a parser result is never a verdict.

### R4 — adaptive recon, forms, and browser JavaScript observation

Read in full: `R4/agent.py` (tool manifest, dispatcher, and observation
formatters), `R4/brain.py` (`analyze_recon`, `analyze_js`, and
`post_recon_hook`), `R4/tools/recon_adapter.py`,
`R4/tools/hai_browser_recon.js`, `R4/tools/zero_day_fuzzer.py`,
`R4/tools/multipart_mutator.py`, and `R4/tools/hai_probe.py`.

The dispatcher exposes separate actions for recon, GET parameter discovery, POST
parameter discovery, API fuzzing, and JavaScript analysis; working memory keeps
a bounded recent observation window. The browser script intercepts both
`fetch` and XHR, records method/URL/body/operation names, and separately tracks
queries and mutations. The browser inspector extracts forms, links, scripts,
storage, and recent network responses. Multipart variants are represented as
explicit content-type/body pairs. ReachAgent adopts these as *evidence shapes*
only: HTML/JS parsing emits graph facts and never trusts scanner text as a
finding.

### R5 — HTTP spider, browser inspector, and API tool wrappers

Read in full: `R5/server.py` (`HTTPTestingFramework`, `BrowserAgent`,
`http_framework_endpoint`, `browser_agent_endpoint`, `api_fuzzer`,
`graphql_scanner`, and `api_schema_analyzer`) and `R5/mcp.py`
(`katana_crawl`, `arjun_parameter_discovery`, `paramspider_mining`,
`x8_parameter_discovery`, `api_fuzzer`, `graphql_scanner`,
`api_schema_analyzer`, `hakrawler_crawl`, `http_framework_test`,
`browser_agent_inspect`, and the repeater/scope/rule wrappers).

The HTTP framework stores bounded request/response history, supports explicit
scope and match/replace rules, and implements a repeater plus per-location
sniper. Its spider is a breadth-first, same-host crawl that extracts links and
all common form controls. The Selenium inspector adds dynamic forms, scripts,
storage, cookies, console errors, and performance-network responses. API schema
analysis preserves method/path/parameters/security metadata, while the MCP
wrappers keep a small JSON contract and forward to a server-side process. These
techniques became ReachAgent's bounded HTML crawl, JS call parser, method-aware
parameter locations, and route replay metadata; no external scanner verdict is
accepted.

### R6 — API-spec admission and run input/viewer boundaries

Read in full: `R6/utils/api_spec.py`, `R6/core/inputs.py`,
`R6/interface/scan_setup.py`, API-target portions of
`R6/interface/utils.py`, and `R6/interface/viewer/transcript.py`.

The spec utility recognizes OpenAPI 3, Swagger 2, and Postman collections,
resolves declared server variables, and returns only absolute base URLs for
scope authorization. Run input stages a spec into a per-run workspace so an
API key stays on the host. The viewer reads bounded JSON projections from disk;
it does not infer or confirm target facts. ReachAgent mirrors the admission
boundary for OpenAPI/Swagger and keeps all request/response bodies secret-free
and bounded.

## Web-standard citations

- OpenAPI defines paths, methods, parameter locations, request bodies, media
  types, and examples: [OpenAPI Specification](https://spec.openapis.org/oas/latest.html).
- HTML form `enctype` distinguishes URL-encoded text from multipart file
  submissions: [MDN `HTMLFormElement.enctype`](https://developer.mozilla.org/en-US/docs/Web/API/HTMLFormElement/enctype).
- GraphQL exposes fields and field arguments through its schema/introspection
  model: [GraphQL specification](https://spec.graphql.org/October2021/).

## Current gap and smallest safe design

Before this phase, API discovery parsed only JSON `paths`, operation-level
parameters, and one GraphQL field layer. HTML forms, hidden/CSRF/file controls,
XHR/fetch calls, JSON/form/multipart serialization, local `$ref` schemas,
response shapes, and parameter-to-endpoint association were absent. Endpoint
ranking excluded parameter ids, and the Arjun/X8 adapters attached results to
the first endpoint rather than the reported route.

The smallest safe design is:

1. Keep `Endpoint`/`Parameter` as the graph schema and add replay/provenance
   attributes rather than new node kinds.
2. Use stdlib `HTMLParser` and bounded regex extraction; do not add a parser
   dependency or execute page JavaScript.
3. Probe specs and same-host pages only with read-only GETs. Materialize POST
   forms and mutation routes without sending them.
4. Normalize each location (`query`, `path`, `json`/legacy `body`, `form`,
   `header`, `cookie`, `multipart`, `graphql`) and reject an incompatible
   serialization at construction time.
5. Validate LLM endpoint and parameter rankings against live graph ids, then
   apply only a bounded Coordinator ordering bonus.

## Deterministic boundary proof

- `recon/surface.py` imports no firer, candidate, validator, oracle, or finding
  module; it only returns immutable `EndpointSpec`/`ParameterSpec` facts.
- `recon/api_discovery.py` writes only Host/Endpoint/Parameter nodes and
  `resolves_to`/`accepts` edges. Its network calls are `RequestFirer.fire` with
  `state_changing=False`.
- `SurfaceMapper` probes authorization only after structure exists and builds
  benign values from recorded examples/serialization. Existing
  `ReadOnlyFirstError`, `ScopeGuard`, and audit behavior remain in force.
- New `explorer.py` branches serialize the mapped location explicitly and still
  require the existing benign fingerprint before payload firing. Unknown
  locations raise instead of silently sending an unmodified request.
- No code path constructs `Finding`, calls `run_oracle`, or calls
  `write_finding`; the focused tests assert this facts-only boundary.

## Files changed/deleted

Changed: graph node/store provenance and replay fields; OpenAPI/GraphQL and
HTML/JavaScript discovery; mapper serialization; insertion-wrapper endpoint
association; surface ranking; Coordinator ranking state; scan event wiring;
Explorer location serialization; focused tests. Added:
`src/reachagent/recon/surface.py` and
`tests/recon/test_endpoint_mapping_phase2.py`.

Deleted: none. No file was unnecessary for this phase.

## Focused validation

- `uv run ruff check src/reachagent tests/recon/test_endpoint_mapping_phase2.py` — passed.
- Focused Phase-2 gate (`test_endpoint_mapping_phase2.py`, API discovery,
  mapper, GraphQL, and surface-ranking tests) — **52 passed, 1 warning**.
- Compatibility gate for Explorer/MCP/persistence/login callers — **66 passed**.

Remaining weakness: JavaScript extraction is intentionally syntactic and
bounded; computed URLs, source maps, and framework-specific runtime routers
still need a browser/MCP-backed enrichment phase. No finding is inferred from
those cases.
