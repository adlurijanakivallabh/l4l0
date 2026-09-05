---
name: graphql
category: vulnerability
description: GraphQL API security — schema acquisition, resolver-level authorization gaps, batching abuse, and a per-class proof ladder
keywords: [graphql, introspection, resolver, batching, aliasing, federation, apollo, subscription]
---

# GraphQL

GraphQL concentrates an application's entire data graph behind one
endpoint, which means authorization has to be enforced consistently at
every resolver, not once at a route boundary. The most common real gap is
not a dramatic schema leak — it is a child resolver that quietly assumes
its parent already checked authorization, or a second transport
(WebSocket, a persisted-query hash) that never got the same check as the
primary HTTP path.

## Attack Surface

- Queries, mutations, and subscriptions, each potentially reachable over
  more than one transport (HTTP POST/GET, a WebSocket subgraph protocol,
  multipart file-upload requests).
- Persisted or automatic persisted queries (APQ), which move the actual
  operation off the wire and behind a hash — a distinct surface from the
  inline-query path with its own set of gaps.
- Federated architectures (a gateway plus independent subgraphs), where
  the gateway enforcing authorization does not guarantee any individual
  subgraph resolver does the same when reached directly via entity
  resolution.

## Recon

- Acquire the schema: attempt introspection first (cheap, passive); if
  disabled, infer the type graph from field-suggestion errors, "expected
  one of" enum errors, and differing error codes for "unknown field" versus
  "unauthorized field" — the error taxonomy alone often reveals existence.
- Build a principal matrix before testing anything: at least one owned and
  one foreign object ID per sensitive type, across every role you have
  credentials for — this is the same cross-identity evidence pattern
  described in [[access-control]], applied at the resolver level instead
  of the route level.
- Identify whether the target is federated (`_service`, `_entities` in the
  schema) — this determines whether subgraph-level authorization is even a
  separate question worth testing.

## Techniques (start quiet, escalate only as needed)

1. **Schema acquisition.** Introspection query, or inference via error
   taxonomy if disabled — this is passive recon, not yet a test of
   anything.
2. **Field-level authorization sweep via aliasing.** In a single request,
   alias an owned and a foreign object of the same type side by side and
   compare responses — this is the cheapest, highest-signal authorization
   test available in GraphQL specifically because aliasing makes the
   paired comparison a single round trip.
3. **Child-resolver gap probing.** Where a parent object correctly
   enforces access, request a nested field on that same object and check
   whether the child resolver re-validates independently or inherits trust
   from the parent's check — this is a distinct and commonly-missed gap
   from the top-level field test.
4. **Transport-parity check.** Repeat a confirmed-protected operation over
   every transport the schema exposes it on (HTTP, a WebSocket
   subscription, a persisted-query hash) — a gap here is a materially
   different finding from a single-transport bypass, since it means an
   entirely separate, less-observed code path skipped the same check.
5. **Federation entity probing, only once federation is confirmed.**
   Query `_service { sdl }` for schema disclosure, then attempt
   `_entities` materialization directly — gateway-level authorization does
   not imply the subgraph resolver enforces the same check when reached
   this way.
6. **Batching and complexity probing, last and minimally.** Aliased
   batch requests can reveal per-field-vs-per-request authorization
   inconsistencies or bypass a naive per-request rate limit; a fragment
   depth/complexity probe should go only as far as confirming a limit
   exists or is absent — do not run a probe large enough to actually
   degrade the service, since that trades a data point for real
   denial-of-service risk.

## Proof Ladder

- **L1 — schema mapped.** The type graph and sensitive fields/types are
  identified (via introspection or inference), but no authorization test
  has been run against them yet.
- **L2 — authorization gap identified, non-sensitive data.** A paired
  owned-versus-foreign request shows asymmetric behavior, but the exposed
  data is not itself sensitive or is already publicly accessible another
  way.
- **L3 — real unauthorized access to sensitive data.** A paired-request or
  child-resolver test demonstrates genuine access to another principal's
  sensitive data through a specific, identifiable resolver path. This is
  the threshold for a reportable finding.
- **L4 — durable or systemic access.** The gap generalizes across many
  types or fields sharing the same resolver pattern, a federation
  `_entities` path bypasses subgraph authorization entirely, or a
  transport-parity gap exposes an entirely separate unauthenticated route
  to the same sensitive data.

Calibrate severity separately per [[severity-calibration]] — an
unauthenticated `_entities` or transport-parity bypass reaching broad
sensitive data is typically critical; a single child-resolver gap on one
field is usually high rather than critical.

## Validation and False-Positive Discipline

Apply [[closure-discipline]] before recording anything. Class-specific
traps:

- Introspection being enabled is a recon capability, not a finding on its
  own — the finding, if any, is what a subsequent authorization test
  actually reaches through the schema it revealed.
- A resolver returning data that is legitimately public (a product
  catalog, a public profile) looks like an asymmetric result but is not a
  gap — confirm the returned data is actually sensitive and scoped to a
  specific principal before treating an aliased comparison as a finding.
- A custom `@auth`/`@private` directive's presence in the schema is a
  declared intent, not a verified control — confirm the resolver actually
  enforces it rather than assuming the directive name implies enforcement.
- Demonstrating that a rate limit or complexity guard *can* be bypassed is
  not itself an L3 finding without also showing the resulting resource
  exhaustion or data exposure — the bypass is a mechanism, not the impact.

## Impact

Unauthorized cross-principal data access via resolver-level authorization
gaps; full data-graph exposure when federation entity resolution bypasses
subgraph authorization; denial of service via unbounded query complexity
or depth when no cost analyzer is enforced; and CSRF or session exposure
when cookie-authenticated GET-based queries and permissive CORS combine on
a GraphiQL/Playground endpoint.

## Summary

Authorization in GraphQL must be proven per resolver, not inferred from
the schema or from one successful check elsewhere in the same query. The
aliased owned-versus-foreign comparison is the highest-signal single test
available; child-resolver gaps and transport parity are the two places a
real, working top-level check most often turns out not to be universal.
