---
name: web_cache
class: web_cache
summary: Web cache deception and cache poisoning.
---
# Web Cache Deception & Poisoning

## Web cache deception
A cache rule matches on file-extension-looking paths; appending `/nonexistent.css`
to a dynamic, sensitive URL (`/account/settings/nonexistent.css`) can make the
cache store the PERSONAL response under a public, guessable key.
- Confirm: request the crafted URL as victim-ish, then request the SAME crafted
  URL unauthenticated/as another identity — if you get the first response's
  private content back, deception confirmed (a genuine cross-identity proof).

## Cache poisoning
Inject an unkeyed input (header not part of the cache key) that changes the
response, then get that poisoned response cached and served to other users.
- Candidates: `X-Forwarded-Host`, `X-Forwarded-Scheme`, `X-Original-URL`,
  unkeyed query params, `Accept-Language`/`Accept-Encoding` if unkeyed.
- Technique: send a request with a malicious unkeyed header producing a bad
  response (e.g. a poisoned redirect/XSS via reflected header), then re-request
  the same (now cacheable) URL WITHOUT the header — if the poisoned response is
  served, the cache is poisoned for everyone.

## Proof ladder
- L1: cache behavior observed (Age/X-Cache headers present).
- L2: an unkeyed input changes the response.
- L3: the changed response is confirmed CACHED and served on a clean follow-up
  request (deception: to a different identity; poisoning: to a fresh request).
- L4: poisoned response delivers XSS/redirect/credential theft to other real users.

## Validation
- Always re-fetch cleanly (no attacker header, different identity/session) to
  prove the cache — not just your own request — is serving the bad response.
- Be mindful of blast radius: a real poisoning proof affects other real users'
  cached responses; use the minimum reproduction, verify quickly, and note it for
  remediation rather than leaving a poisoned cache live.
