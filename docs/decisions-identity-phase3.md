---
title: Phase 3 identity, authentication, and session binding decisions
---

# Phase 3 — identity, authentication, and session binding

Date: 2026-08-28. Scope: explicitly authorized web/API targets and intentionally
vulnerable laboratories only.

## Invariants and authorization boundary

The only supported runtime is an LLM-driven scan. The model can select and
prioritize surfaces, but it cannot mint a session, decide that credentials
succeeded, call an oracle, or write a finding. A login submission is an explicit
session-bootstrap operation through `RequestFirer`; scope is still checked first,
the operation is restricted to a detected POST login route, and it is audited.
All target-state mutations remain behind the ordinary read-only-first gate.

Passwords, bearer values, cookie values, refresh tokens, and hidden CSRF values
remain process-local. Graph nodes, persistence, audit entries, GUI snapshots,
MCP responses, and model-facing planning context contain only identity names,
opaque `token:<identity>` references, cookie names, auth kind, and expiry.
Authentication failure is a blocked phase; no unauthenticated continuation is
allowed when identities were supplied.

## Licenses recorded before deep reading

| Alias | License | Phase-3 posture |
|---|---|---|
| R1 | MIT | Technique-level reuse only |
| R2 | MIT for the agent-origin subtree; research-use-only for authored core | Paraphrased ideas only |
| R3 | MIT | Technique-level reuse only |
| R4 | MIT | Paraphrased ideas only |
| R5 | MIT | Technique-level reuse only |
| R6 | Apache-2.0 | Technique-level reuse only |

## Full reference reads and concrete techniques

### R1 — signed sessions, middleware, and OAuth callbacks

Read in full:

- `R1/backend/pkg/server/auth/session.go`
- `R1/backend/pkg/server/auth/auth_middleware.go`
- `R1/backend/pkg/server/oauth/client.go`
- `R1/backend/pkg/server/oauth/github.go`
- `R1/backend/pkg/server/oauth/google.go`
- `R1/backend/pkg/server/services/auth.go`
- `R1/backend/pkg/server/router.go`

The implementation derives independent cookie/JWT keys, validates session claims
and expiry before accepting a request, refreshes a cookie near its TTL, and fails
protected routes rather than treating a stale session as anonymous. OAuth uses a
state+nonce handshake, PKCE verifier, code exchange, issuer-specific validation,
and one-time cleanup cookies. The route table makes local JSON login, OAuth start,
and GET/POST callbacks explicit. ReachAgent adopts the state-machine ideas as
per-identity expiry/refresh and fail-closed login errors, without copying key
derivation or provider code.

### R2 — encrypted auth records, session manager, and context boundary

Read in full:

- `R2/api/auth.py`
- `R2/api/sessions.py`
- `R2/api/app.py`
- `R2/api/schemas.py`
- `R2/sdk/agents/run_context.py`
- `R2/util/session.py`
- `R2/continuous_ops/session_snapshot.py`

The API owns a per-installation auth manager, persists records atomically, enforces
TTL lazily, and keeps session state behind an application dependency. Session
objects carry agent/history metadata while the run context is explicitly not sent
to the model. The streaming endpoints preserve state in a per-session manager.
ReachAgent keeps the same separation: `TokenStore` owns private material and
`ExplorerContext` carries only the runtime collaborator; model snapshots expose
bounded facts, never credentials.

### R3 — durable attempts, immutable traces, and typed events

Read in full:

- `R3/backend/audit.py`
- `R3/backend/trace.py`
- `R3/backend/memory.py`
- `R3/unified/events.py`
- `R3/unified/types.py`

The durable state kernel uses revisions, leases, explicit failure kinds, and
atomic transitions. The trace journal flushes each event and stores hashes for
prompt/instruction integrity; typed events distinguish tool calls, results, and
terminal errors. ReachAgent already had an append-only audit stream, so Phase 3
extends it with explicit `auth` events and a blocked terminal state while keeping
all request bodies and headers out of the log.

### R4 — auth header plumbing, CSRF-aware forms, and bounded ReAct memory

Read in full:

- `R4/tools/auth_session.py`
- `R4/tools/_spray_http_form.py`
- `R4/tools/_spray_oauth.py`
- `R4/tools/credential_store.py`
- `R4/memory/schemas.py`
- `R4/agent.py`
- `R4/tests/test_auth_session.py`

The auth-session layer canonicalizes/deduplicates headers, rejects CR/LF, derives
a stable hash for correlation, and masks values in descriptions. Form handling
extracts a CSRF value before submission and identifies redirects/explicit success
signals; OAuth token handling expects structured access-token responses. The
agent keeps a bounded observation window and JSONL trace, but its raw tool args
illustrate why ReachAgent must never put credentials in model-facing events.
ReachAgent reuses the canonical header/hash concept as isolated cookie/bearer
stores, parses forms without submitting during discovery, and returns only opaque
session references.

### R5 — proxy/repeater state and browser inspection

Read in full for the session/history concern:

- `R5/http_mcp.py` client/session/repeater wrappers (lines 147–265 and
  5156–5284)
- `R5/http_server.py` `HTTPTestingFramework` and browser inspection class
  (lines 13281–14035)

The HTTP framework uses a persistent request session, match/replace rules, a
scope setting, repeater/intruder actions, and bounded proxy history. Browser
inspection captures forms, storage, cookies, and network responses. Those outputs
are useful operationally but include secrets in raw history; ReachAgent keeps the
same persistent runtime session idea while withholding bodies, headers, storage,
and cookie values at the MCP/UI boundary.

### R6 — preflight, per-scan lifecycle, and fail-closed viewer auth

Read in full:

- `R6/core/sessions.py`
- `R6/runtime/session_manager.py`
- `R6/interface/viewer/auth.py`
- `R6/interface/scan_setup.py`

The code serializes concurrent session writes, restores state after rewrite
failures, caches one session bundle per run, cleans it up best-effort, and fails
closed when a locally stored viewer token is expired or lacks a usable expiry.
ReachAgent applies those lifecycle principles to token refresh, browser-cookie
merge, and per-identity session graph nodes.

## Current gap and smallest safe design

Before this phase, login detection only probed three fixed paths, returned raw
tokens, handled one cookie, treated every API login as a username/password JSON
body, and never authenticated identities before mapping. `RequestFirer` accepted
static bearer headers only, browser-form MCP returned a cookie value, and graph
examples could retain credential-shaped values.

The smallest safe design was:

1. Keep `IdentityStore` as the sole owner of private material, add structured
   bearer/cookie/mixed material, expiry, in-memory refresh callbacks, and safe
   summaries.
2. Discover login forms from observed graph/root HTML, infer JSON vs form vs
   GraphQL serialization, and probe OAuth/OIDC well-known metadata read-only.
3. Capture all `Set-Cookie` values and structured token responses, bind each
   identity separately, and return only `token:<identity>`.
4. Let `RequestFirer` resolve live identity headers at send time; only an explicit
   internal `authentication=True` POST is allowed for session bootstrap.
5. Authenticate configured identities after cold-start recon and before API/spec
   mapping; emit `auth` events and stop on failure.
6. Redact credential-shaped graph examples and remove cookie values from browser
   MCP responses; support cookie sessions in cross-identity BOLA/GraphQL paths.

## Deterministic boundary proof

No Phase-3 code constructs an `OracleVerdict`, calls `run_oracle`, or writes a
`Finding`. Login only produces private session material and graph-safe session
metadata. Payload firing continues through `RequestFirer` → MCP handles → the
existing deterministic oracle registry → Validator. The LLM receives only event
messages, graph shape, opaque references, and safe error codes.

## Official protocol references

- OpenID Connect Discovery requires a JSON provider document at
  `/.well-known/openid-configuration` and defines `issuer`, authorization, token,
  and userinfo endpoint metadata: [OpenID Connect Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0-20.html).
- OAuth 2.0 defines access-token expiry (`expires_in`) and optional refresh-token
  issuance: [RFC 6749](https://www.rfc-editor.org/rfc/rfc6749).

## Focused verification

`tests/recon/test_identity_phase3.py` covers dynamic HTML, GraphQL, OIDC
discovery, cookie/bearer isolation, expiry/refresh, graph-example redaction,
RequestFirer binding, fail-loud redacted errors, and a hermetic browser-form
response that binds cookies server-side without returning them. Existing identity,
execution, mapper, BOLA, GraphQL, and persistence tests remain green. A real
Chromium run is environment-dependent.
