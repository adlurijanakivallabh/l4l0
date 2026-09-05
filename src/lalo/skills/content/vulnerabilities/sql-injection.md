---
name: sql-injection
category: vulnerability
description: SQL injection — union, boolean/time-blind, error-based, out-of-band, and ORM-bypass techniques with a per-class proof ladder
keywords: [sqli, sql injection, sql, union, blind sqli, boolean blind, time blind, injection, database]
---

# SQL Injection

SQL injection stays durable because query construction drifts from the
assumption that every value is bound as a parameter. Treat every string that
reaches a database call as suspect until you can point at the exact
parameterization that protects it — a framework's default is not a
guarantee, per [[closure-discipline]].

## Attack Surface

- Any input that reaches a database call: path/query/body/header/cookie
  parameters, in any encoding (URL, JSON, XML, multipart).
- The identifier/value distinction matters: table and column names need
  quoting or an allowlist, not just escaping the way a literal value would
  be; a query built with `whereRaw`/`orderByRaw`-style raw fragments in an
  ORM is exactly as exposed as hand-written SQL.
- Batch/bulk endpoints, report generators, and export jobs that build a
  filter clause directly from request parameters are frequently missed
  because the "real" endpoint nearby is properly parameterized.
- Beyond classic relational engines, modern surfaces include JSON/JSONB
  operators, full-text search functions, geospatial and window functions,
  and common table expressions — all of which can carry an injectable
  fragment even when the base query looks safe.

## Recon

- Fingerprint the database engine from error text, response timing
  characteristics, or a benign type-coercion probe (e.g. a single quote
  versus a double quote produces different error shapes on different
  engines).
- Map which parameters influence WHERE/ORDER BY/GROUP BY/LIMIT clauses
  versus which only ever reach a value binding — identifier-context
  parameters (sort column names, `include`/`expand`-style projection knobs)
  are worth extra attention since they are more often built by
  concatenation than value parameters are.
- Note whether the application already reveals database errors (stack
  traces, driver messages) — this changes which channel below is quietest.

## Techniques (start quiet, escalate only as needed)

1. **Type/constraint differential** — send a value that would provoke a
   parser or constraint error only if it reaches raw SQL (an unescaped
   quote, a type mismatch) versus a value that should not. A difference in
   status code, body, or error text is your first oracle, and it costs one
   request pair.
2. **Boolean-blind extraction** — pair two requests differing only in a
   predicate's truth value; diff status/body length/response shape. Prefer
   this over timing when the diff is reliable — it produces no server-side
   load and is easy to make quiet.
3. **Time-blind extraction** — only when no observable diff exists. Gate
   the delay inside a subquery (not a bare `SLEEP`/`WAITFOR` clause) so a
   single slow request does not degrade the target, and confirm with a
   control request that should NOT delay before trusting a delayed one.
4. **Error-based extraction** — if the application surfaces database errors
   directly, this is often the fastest channel: force the engine to embed
   extracted data inside its own error message.
5. **UNION-based extraction** — only once you have confirmed column count
   and compatible types; this is the noisiest channel in terms of what it
   reveals in the response, but the cheapest per byte extracted once it
   works.
6. **Out-of-band confirmation** — when in-band channels are filtered or
   silent, use your OAST callback service: craft a payload that causes the
   database to resolve a DNS name or make an HTTP request you control
   (engine-specific: file/network primitives on MySQL, foreign-data or
   COPY-program forms on PostgreSQL, extended stored procedures on MSSQL,
   HTTP/LDAP utility packages on Oracle — check what the target engine
   actually has enabled before assuming a primitive is available). A single
   correlated callback is strong, low-noise evidence of injection with
   engine-level network reach.

Encoding/obfuscation (comment insertion, keyword splitting, alternate
whitespace, numeric-literal tricks, mixed-case/backtick evasion) exists to
get past a filter, not to prove the vulnerability — use the minimum needed
to reach one of the oracles above, not as an end in itself.

## Proof Ladder

- **L1 — oracle identified.** You have a reliable differential (error,
  boolean, or timing) that responds to a syntax change, but have not yet
  extracted anything through it.
- **L2 — non-sensitive extraction.** You have used the oracle to extract
  metadata that proves database-level control (engine version, current
  user, database name) via bit-by-bit or channel-based extraction.
- **L3 — real data or auth bypass.** You extracted actual application data
  (not just metadata) through the injection, or used an injected predicate
  to bypass an authentication or authorization check. This is the threshold
  for a reportable finding.
- **L4 — write primitive or full compromise.** You demonstrated a write
  primitive (row/role modification, file write where the engine allows it),
  command execution via a database extension, or extraction of data at a
  scale that constitutes a full compromise of the dataset.

These levels measure how conclusively you proved the finding — they do not
by themselves set severity; calibrate severity separately per
[[severity-calibration]] (unauthenticated injection reaching real data is
typically high; a confirmed oracle with no extraction achieved is not).

## Validation and False-Positive Discipline

Apply [[closure-discipline]] before recording anything. Class-specific
traps to check before calling something confirmed:

- A generic 500 error is not proof — confirm the error text or timing
  actually correlates with the *injected* fragment, not with malformed
  input in general (test a control value that is malformed but not
  SQL-shaped).
- A consistent response-size difference must be tied to the predicate's
  truth value specifically, not to unrelated template variance — vary only
  the injected fragment between the paired requests.
- An observed delay must disappear when the injected sleep condition is
  made false while everything else about the request stays identical;
  network/CPU jitter alone is not evidence.
- "Uses an ORM" or "uses parameterized queries elsewhere in the codebase" is
  exactly the kind of generic trust [[closure-discipline]] rejects — the
  specific call site matters, not the framework's general reputation.

## Impact

Direct data exfiltration and regulatory exposure, authentication and
authorization bypass via manipulated predicates, server-side file access or
command execution where the engine and privileges allow it, and persistent
impact through modified data, scheduled jobs, or stored procedures.

## Summary

Modern SQL injection succeeds wherever query construction drifts from the
assumption that user input is a bound value. Pick the quietest reliable
oracle, extract metadata before real data, and hold every finding to the
same evidence bar as any other class: a real, reproducible request pair, not
a theory about what the query probably does.
