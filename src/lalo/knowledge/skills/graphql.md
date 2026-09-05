---
name: graphql
class: graphql
summary: GraphQL-specific abuse — introspection, batching/DoS-adjacent, injection via resolvers, authz.
---
# GraphQL Abuse

## Recon
- Try introspection (`{__schema{types{name,fields{name}}}}`) even if the docs
  say it's disabled — many apps leave it on in production.
- Enumerate mutations/queries and their required auth via the schema; diff by identity.
- Field suggestion/error messages sometimes leak schema even with introspection off.

## Techniques
- **Authorization**: exactly the access_control skill's cross-identity method,
  applied per-field/per-mutation (a query can expose object A to identity B).
- **Batching / alias abuse**: send many aliased queries in one request to bypass
  naive per-request rate limiting, or to brute-force (login mutation batched N times).
- **Deeply nested queries**: resource-exhaustion-adjacent — note but do NOT
  actually DoS the target; report the missing depth/complexity limit as a finding
  without exhausting it.
- **Injection via resolvers**: a resolver argument may flow into SQL/NoSQL/shell —
  apply the relevant class's technique through the GraphQL argument.
- **Field-level mass assignment**: a mutation input type may accept privileged
  fields (`role`, `isAdmin`) not shown in the client's UI form.

## Proof ladder
Same ladder as the underlying class being exercised through GraphQL (access
control / injection / etc.) — GraphQL is a transport, not a new proof concept,
except pure schema/introspection exposure which tops out at L2 (info disclosure)
unless it enables a further attack.

## Validation
- Confirm introspection is genuinely reachable in the target environment, not a
  cached/stale schema from docs.
