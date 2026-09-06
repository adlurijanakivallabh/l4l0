---
name: nosql-injection
category: vulnerability
description: NoSQL injection — MongoDB operator/JS injection, blind regex extraction, and non-MongoDB store variants, with a per-class proof ladder
keywords: [nosql injection, mongodb, mongo, operator injection, where injection, redis injection, elasticsearch injection, cypher injection, dynamodb]
---

# NoSQL Injection

NoSQL injection shares SQL injection's root cause — user input controlling
query *structure*, not just a value — but the mechanism differs: instead of
breaking out of string syntax, the attacker submits an **operator object**
(MongoDB's `$ne`/`$gt`/`$regex`) or a structured filter the driver accepts
at face value. MongoDB is the dominant target; Redis, Elasticsearch,
DynamoDB, Cassandra, CouchDB, and Neo4j each have their own distinct
injection surface, and a GraphQL resolver that passes a variable straight
into a backing NoSQL filter is a common cross-cutting vector into any of them.

## Attack Surface

- Any input that reaches a query filter as structured data, not just a
  string: JSON body fields handed to `find`/`findOne`/`aggregate` unchanged,
  and — easy to miss — form fields using bracket notation
  (`username[$ne]=x`), which several server frameworks coerce into an
  operator object (`{username: {$ne: "x"}}`) even though the request never
  looked like JSON at all.
- Login/authentication endpoints (the classic target — an operator object in
  place of a plain string can satisfy the query without knowing a real
  credential), search/filter/admin-lookup APIs, and password-reset or
  token-lookup flows.
- GraphQL resolvers whose input types map directly onto a backing NoSQL
  filter — check `__schema`/`__type` introspection for input types accepting
  an arbitrary object shape.
- Beyond MongoDB: Redis commands built by string concatenation (RESP
  protocol injection via embedded `\r\n`), Elasticsearch `query_string`/
  `simple_query_string` Lucene syntax or Painless scripts built from user
  input, DynamoDB PartiQL, Cassandra CQL built by concatenation instead of
  `session.prepare()`, CouchDB Mango selectors and `_design` view documents,
  and Neo4j Cypher built by string interpolation instead of a `$param`.

## Recon

- Determine input shape and content type first: does the endpoint accept
  raw JSON (an operator object can be submitted directly), or only form-
  encoded/query-string data (try bracket notation, which several popular
  body-parsing middlewares transparently expand into a nested/operator
  object)?
- Send a deliberately malformed operator payload and watch for a store-
  specific error leaking through (`MongoError`, `CastError`, a Cypher/CQL
  parse error, an Elasticsearch mapping exception) — this both fingerprints
  the backing store and confirms raw input is reaching it unvalidated.
- For MongoDB specifically, check whether server-side JavaScript is even
  reachable before investing in `$where`/`$function` payloads — it's
  disabled by default from MongoDB 7.0 onward, but versions 4.4–6.x
  deprecated `$where` while leaving `javascriptEnabled` defaulting to
  `true`, so those are still exploitable unless explicitly hardened.
- Identify whether the code path uses a raw driver call, an ODM in a
  permissive mode (e.g. an object-relational mapper with strict typing
  disabled), or a genuinely parameterized/prepared form — string
  concatenation into a query is the same root cause across every store
  listed above, not just MongoDB.

## Techniques (start quiet, escalate only as needed)

1. **Operator authentication-bypass probe.** Against a login query shaped
   like `db.users.findOne({username, password})`, submit
   `{"username": {"$ne": null}, "password": {"$ne": null}}` (or the
   bracket-notation form-field equivalent) — success against a real account
   with no known credential is immediate, unambiguous proof.
2. **Boolean-blind confirmation.** Where a direct bypass doesn't land,
   compare responses for a predicate that's structurally true
   (`{"$gt": ""}`) versus one that plainly can't match — a real oracle
   response difference confirms the operator is reaching the query engine.
3. **`$regex` blind extraction.** Once an oracle exists, extract a sensitive
   string field (a token, a reset code, a password hash) character by
   character with anchored regex probes (`{"$regex": "^a"}`,
   `{"$regex": "^b"}`, ...); binary-search the character space rather than
   scanning it linearly to cut request volume sharply.
4. **`$where`/`$function` JavaScript injection.** If SSJS is confirmed
   reachable (per the recon check above), a direct `$where` filter can
   return matching documents outright, or — when the response isn't
   reflected — a conditional `sleep()` inside the function body turns it
   into a timing oracle for the same blind-extraction technique.
5. **Aggregation-pipeline pivot.** `$match`/`$project` accept the same
   operator payloads as `find()`; a user-influenceable `$lookup.from` value
   is the highest-impact variant, since it can redirect the join from the
   intended collection into an unrelated one (e.g. `orders` into `users`)
   and exfiltrate cross-tenant data through an endpoint that never looked
   like it touched that collection at all.
6. **Non-MongoDB store variants.** Apply the same underlying idea to
   whatever store is actually in play: Lucene special characters or a raw
   `script.source` field for Elasticsearch, embedded `\r\n` for Redis
   command smuggling, string-built PartiQL/CQL/Cypher for DynamoDB/
   Cassandra/Neo4j, and an operator object inside a Mango `_find` selector
   (or, more seriously, a user-influenced `_design` view function) for
   CouchDB.

## Proof Ladder

- **L1 — operator reaches the query engine.** A malformed or operator-
  shaped payload produces a store-specific error, or a response difference
  between an obviously-true and obviously-false operator predicate — but no
  bypass or extraction has been achieved yet.
- **L2 — non-sensitive confirmation.** A boolean oracle is established and
  reproducible (consistent response/status/timing difference tied
  specifically to the injected predicate), or a single metadata value is
  extracted, without yet reaching authentication or real sensitive data.
- **L3 — authentication bypass or real data extracted.** An operator payload
  grants access to a real account with no valid credential, or a genuine
  sensitive field (token, password hash, PII) is extracted through blind
  regex/timing enumeration. This is the threshold for a reportable finding.
- **L4 — server-side execution or systemic compromise.** Confirmed `$where`/
  `$function`/Painless/APOC JavaScript execution server-side, a `$lookup`
  pivot exfiltrating an entire unrelated collection, or the same operator-
  injection pattern reproduced across multiple independent endpoints
  (not just the one initially tested).

Calibrate severity separately per [[severity-calibration]] — an
authentication bypass or bulk PII extraction is categorically more severe
than a boolean oracle on a non-sensitive field, even though both start from
the identical operator-injection technique.

## Validation and False-Positive Discipline

Apply [[closure-discipline]] before recording anything. Class-specific
traps to check before calling something confirmed:

- A framework or ODM running in strict/typed mode may cast an operator
  object to its string representation (`[object Object]`) before it ever
  reaches the driver — confirm the query actually executed with the
  operator intact (a real behavioral difference tied to the operator's
  semantics), not just that the request was accepted without an error.
- Input sanitization that strips known operator keys (`$ne`, `$gt`, ...)
  before construction is a real, working control if EVERY equivalent
  operator and encoding (bracket notation, `$expr`-wrapped comparisons,
  dotted-key vs. nested-object form) is also blocked — test at least two
  independent operator forms before concluding sanitization is absent
  rather than just one variant being filtered.
- A response difference must be tied to the injected operator specifically:
  rule out that a validation error (rejecting the malformed shape itself,
  not executing it) is what actually produced the differing response.
- `$where`/server-side-JavaScript findings need the actual `javascriptEnabled`
  state confirmed for the specific deployed version — do not assume a
  vulnerable-by-default version from documentation alone when the target's
  own admin/status output can confirm it directly.

## Impact

Authentication bypass granting access to arbitrary or all accounts, bulk
extraction of sensitive fields (tokens, password hashes, PII) via blind
enumeration, cross-collection/cross-tenant data exposure via an aggregation
pivot, and — where server-side scripting is reachable — arbitrary
server-side code execution within the database engine's own sandbox.

## Summary

NoSQL injection is the same "user input controls query structure" failure
as SQL injection, expressed as operator/structure injection instead of
syntax breaking. Enforce strict, typed input validation before it reaches
any query builder, use each store's own parameterized/prepared form
consistently, and never pass a raw client-supplied object into a filter,
selector, or script field unexamined.
