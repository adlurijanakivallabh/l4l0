# Phase 9 decision record — browser and proxy firing transports

Date: 2026-08-30
Status: complete; Phase 10 is not started.
Implementation commit: `874f04e`

## Invariants

- The LLM may choose only `http`, `browser`, or `proxy`; the choice changes
  evidence collection, not interpretation.
- Scope is checked before every network request. Browser routes re-check each
  HTTP(S) request, including redirects and subresources.
- A mutating request is rejected until the same identity has a successful
  read-only clearance. Browser submissions use an audited GET preflight and an
  execution-layer authorization check; proxy requests use `RequestFirer`.
- Raw bodies, response headers, cookie values, and verdict objects stay
  server-side behind `fire-*`, `browser-*`, and `verdict-*` handles. Only
  bounded projections and cookie names cross the MCP boundary.
- Browser/proxy modules do not import an oracle or finding writer. Only
  `run_oracle` constructs evidence and the existing Validator seam can mint a
  verdict or write a finding.

## Licenses recorded before the full read

The six reference checkouts were recorded as neutral aliases: R1 MIT; R2 dual
(MIT for its agent-origin subtree and research-use-only for authored core); R3
MIT; R4 MIT; R5 MIT; R6 Apache-2.0. No checkout name is used in ReachAgent
artifacts.

## ReachAgent files read in full

`browser/shim.py`, `browser/playwright_driver.py`, `execution/firer.py`,
`execution/scope.py`, `execution/audit.py`, `execution/transports.py`,
`identity/store.py`, `tools/explorer.py`, `tools/explorer_context.py`,
`mcp/server.py`, `recon/transport_tuning.py`, and `scan/xss_dom.py` were read
in full, including the called helpers used by the transport paths.

## Full reads and concrete techniques

### R1

Read in full:

- `backend/pkg/tools/browser.go`
- `backend/pkg/tools/browser_test.go`
- `backend/pkg/tools/searchers/proxy_test.go`
- `backend/pkg/server/auth/session.go`
- `backend/pkg/server/response/http.go`
- `frontend/src/providers/flow-provider.tsx`
- `frontend/src/providers/flows-provider.tsx`
- `frontend/src/features/flows/files/use-flow-files-realtime.ts`
- `frontend/src/lib/apollo.ts`
- `frontend/src/lib/axios.ts`

The browser implementation taught bounded content/screenshot handling, private
versus public routing, and explicit error wrapping. Its proxy tests taught
CONNECT interception, header/body preservation, TLS certificate caching, and
idempotent shutdown. The frontend providers taught delaying subscriptions until
initial state exists, cache reconciliation after reconnect, throttling appended
stream chunks, and preserving rendered state during background refetches.

### R2

Read in full:

- `api/streaming.py`
- `sdk/agents/stream_events.py`
- `tools/streaming.py`
- `sdk/agents/mcp/server.py`
- `sdk/agents/mcp/util.py`
- `api/sessions.py`
- `continuous_ops/session_snapshot.py`

The stream path taught high-level SSE event projections, explicit final events,
error events that do not tear down a stream, and cancellation through a running
task. MCP handling taught connect/list/call locks, stale-session cleanup,
reconnect-and-retry, tool-list caching, and separation of text from non-text
resource content. Session code taught per-session locks and bounded snapshots.

### R3

Read in full:

- `unified_agent/tool_server.py`
- `unified_agent/events.py`
- `unified_agent/tools.py`
- `unified_agent/agent.py`

The neutral tool registry and server taught deterministic tool naming, importable
stdio server specs, normalized lifecycle events, bounded event folding, and a
single shared tool surface across backends. ReachAgent retains its own MCP role
boundary rather than copying that registry.

### R4

Read in full:

- `tools/hai_browser_recon.js`
- `tools/recon_adapter.py`
- `mcp/burp-mcp-client/README.md`
- `mcp/caido-mcp-client/README.md`
- `mcp/README.md`

The browser recon script taught interception of both `fetch` and XHR, operation
and variable capture, response cloning, bounded bundle searching, and explicit
dump helpers. The adapter taught nested/flat format normalization, deduplication,
bounded accessors, and idempotent normalization. The proxy integration notes
taught history filtering, repeater modifications, scope-aware traffic, and
server-side credential redaction; ReachAgent keeps all of those behind its own
scope and oracle gates.

### R5

Read in full:

- `MCP client module` lines 1–280 and 5135–5335 (client, MCP wrappers, browser,
  proxy/repeater registrations)
- `HTTP server module` lines 13260–14025 (HTTP framework, match/replace,
  scope, repeater, spider, browser lifecycle, network capture, response
  inspection)
- `HTTP server module` lines 6783–6990 (bounded command execution, output
  readers, progress, timeout, graceful termination)

The HTTP framework taught explicit match/replace locations, request history,
bounded response previews, repeater request specs, browser network-log capture,
real status/cookie/final-URL inspection, and graceful timeout/partial-output
states. Its passive vulnerability list is intentionally not reused as an oracle:
ReachAgent treats those observations as inert evidence and sends them through
the deterministic Validator seam.

### R6

Read in full:

- `tools/proxy/tools.py`
- `tools/proxy/caido_api.py`
- `interface/viewer/server.py`
- `interface/viewer/transcript.py`
- `interface/viewer/frontend/src/components/live/tool-renderers/BrowserRenderer.tsx`
- `interface/viewer/frontend/src/components/live/tool-renderers/ProxyRenderer.tsx`
- `interface/viewer/frontend/src/components/live/tool-renderers/ToolCard.tsx`
- `tests/test_proxy_client.py`
- `docs/tools/browser.mdx`
- `docs/tools/proxy.mdx`
- `tools/agent_browser/README.md`

The proxy client taught a serialized shared client, cursor pagination, sitemap
views, regex/page-bounded request views, raw replay framing repair, and explicit
timeouts. The viewer taught disk-backed live polling, path-traversal-safe asset
resolution, per-process session capabilities, and bounded renderer previews.
The browser/proxy renderers taught compact method/status coloring, truncation,
collapsible code, and separate request/response summaries.

## Gap and design decisions

Before this phase, transport tuning only returned an advisory string, browser
navigation returned no response metadata, the form tool returned a fabricated
status, and proxy-style requests actually used the direct HTTP client. Phase 9
adds:

1. `execution/transports.py`: an allowlisted dispatcher, conservative MCP
   annotations, `TransportControl` cancellation/progress seam, and explicit
   browser preflight/record helpers.
2. `RequestFirer` transport metadata, proxy-client routing, final URL/redirect
   evidence, external-transport authorization, and audited browser outcomes.
3. Browser navigation normalization for status, final URL, redirect chain,
   cookie capture, response headers, bounded page body, and response body length.
   `fire_browser` and `fire_browser_form` bind captured cookies into the selected
   identity's isolated `TokenStore` and return only cookie names plus an opaque
   browser handle.
4. `fire_request` now honors the LLM-selected transport. HTTP and proxy use the
   same `RequestFirer`; browser selection delegates to the browser form path.
   Proxy dispatch fails closed when no configured proxy URL exists and rejects
   model-supplied credential headers.
5. `run_oracle` can consume browser handles for execution, differential, and
   structural evidence without moving raw bodies or headers across MCP.
6. The existing DOM-XSS orchestrator now consumes the typed browser result and
   wraps its Playwright run with the same browser preflight/audit gate instead
   of treating the result as an untyped mapping.

No files were deleted. The pre-existing untracked `docs/payload.json` was not
touched.

## Confirmation-authority proof

Transport choice is data-only. `TransportDispatcher.fire` calls
`RequestFirer.fire`; `prepare_browser` calls `RequestFirer.fire` for clearance
and `authorize_external`; browser route callbacks call `authorize_external`; and
`record_browser` only appends an audit entry. Neither `execution/transports.py`,
`browser/shim.py`, nor `browser/playwright_driver.py` imports `oracles` or
`validator` (Phase 9 AST test proves this). The only new browser-handle path
into confirmation is `mcp.server.run_oracle`, which reconstructs evidence and
then calls `_validator.run_oracle`; `write_finding` still resolves only a
server-minted `verdict_ref` and delegates to `_validator.write_finding`. Thus
HTTP, browser, and proxy transports can change evidence collection only; the
deterministic oracle remains the sole confirmation authority.

## Validation

- `uv run pytest -q tests/phase9/test_transports.py` — 11 passed.
- Related browser/MCP/scope/transport gate — 112 passed:
  `uv run pytest -q tests/phase9/test_transports.py tests/recon/test_identity_phase3.py
  tests/phase3/test_browser_shim.py tests/phase3/test_dom_execution_marker.py
  tests/phase1/test_mcp_server.py tests/recon/test_transport_tuning.py
  tests/phase1/test_execution_layer.py tests/phase3/test_xss_detector.py`.
- Real Chromium DOM integration — 2 passed:
  `uv run pytest -q -m integration tests/phase3/test_browser_integration.py`.
- `uv run ruff check` on changed source/tests — passed.
- Strict mypy on changed source/tests — passed.
- Reference-name scan on changed artifacts — no matches.

The whole-tree pytest run remains reserved for the final release gate, as
specified by the build plan.
