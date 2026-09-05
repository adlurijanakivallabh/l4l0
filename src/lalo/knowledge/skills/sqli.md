---
name: sqli
class: sqli
summary: Methodology for finding and proving SQL injection.
---
# SQL Injection

1. Fingerprint the parameter: does it reach a query? Reflect a marker, vary type.
2. Error-based: inject a single quote `'` and a balanced `''`; a DB error on the
   first but not the second is a strong signal.
3. Boolean-based: compare `' OR '1'='1` (true) against `' AND '1'='2` (false);
   a stable, reproducible content divergence indicates injection.
4. Time-based (blind): `1 AND SLEEP(5)` / `pg_sleep(5)`; confirm the delay scales.
5. Out-of-band (blind, no visible effect): DNS/HTTP exfil via a stacked query or
   subquery to the OAST domain.

Prove impact non-destructively: read one row (e.g. `version()`), never modify data.
Corroborate across at least two of {error, boolean, time, OOB} before high confidence.
