---
name: web-cache-deception
category: vulnerability
description: Web cache deception — tricking a shared cache into storing a private response under a public-looking key, and a per-class proof ladder
keywords: [web cache deception, cache deception, cache poisoning, cache key, static extension, shared cache]
---

# Web Cache Deception

Cache deception is distinct from cache *poisoning*: poisoning injects
attacker-controlled content into a cache that other users then receive;
deception instead tricks the cache into storing a genuine, sensitive,
*per-user* response under a key that a different, unauthenticated user's
request will also match. The vulnerability lives entirely in a mismatch
between how the cache computes its key and how the origin resolves the
path — no injection is needed at all.

## Attack Surface

- Any application sitting behind a shared cache (a CDN, a reverse-proxy
  cache, an API gateway with caching enabled) that also serves
  authenticated, per-user content on paths that look structurally similar
  to static, cacheable resources.
- Frameworks and routers that resolve a path leniently — treating a
  trailing static-looking extension, an extra path segment, or a
  parameter delimiter as ignorable — while the cache in front of them
  keys strictly (or loosely, in the other direction) on the raw path.
- Endpoints returning sensitive per-user data as their *default* response
  (account settings, API tokens, profile pages) are higher-value targets
  than ones requiring specific parameters, since a bare decorated path is
  enough to trigger caching.

## Recon

- Confirm a cache is actually present and identify its behavior before
  attempting anything: response headers like `Age`, `X-Cache`,
  `CF-Cache-Status`, or `Via` indicate a hit/miss and reveal which layer
  is caching.
- Identify what the cache's key is actually composed of — typically the
  path and possibly the query string — versus what the origin server
  normalizes away (trailing extensions, path parameters after `;`,
  duplicate slashes, case).
- Enumerate authenticated, per-user endpoints that return sensitive data
  by default, since these are the payload — the deception technique only
  matters if there is something worth stealing at the end of it.

## Techniques (start quiet, escalate only as needed)

1. **Cache presence and key-composition mapping.** Send the same request
   twice and compare `Age`/`X-Cache` on the second response to confirm a
   cache exists and observe its keying, without touching any sensitive
   endpoint yet.
2. **Path-confusion probe on a low-sensitivity endpoint first.** Append a
   static-looking suffix or path segment (a trailing `.css`/`.js`, a path
   parameter like `;foo.css`, an extra segment the origin router ignores)
   to a non-sensitive authenticated page and check whether the *decorated*
   URL is now cache-hit-eligible — this proves the technique works on this
   target before you point it at anything valuable.
3. **Delimiter and normalization discrepancy sweep, only if the plain
   suffix trick fails.** Try characters the cache and origin are likely to
   treat differently (`?`, `#`, `;`, encoded slashes, double extensions) —
   use the minimum variant that produces a cache hit, not an exhaustive
   sweep once one works.
4. **Confirm storage against the real sensitive endpoint.** Once a
   decorated-path pattern is shown to produce a cache hit on a
   low-sensitivity page, repeat it against the actual sensitive endpoint
   under an authenticated identity — this is the step that turns the
   primitive into a real claim.
5. **Cross-identity retrieval, the actual proof.** From a second, genuinely
   distinct session or an unauthenticated request, fetch the same decorated
   URL and confirm the first identity's sensitive content is returned. This
   is the only step that constitutes real evidence — a single-session test
   proves the caching behavior but not the cross-user exposure.

This class is a distinct mechanism from cache *poisoning* — see
[[http-request-smuggling]] for the closely related but separate technique
of injecting content into a cache via a parser/desync differential rather
than a routing/keying mismatch.

## Proof Ladder

- **L1 — cache and keying behavior mapped.** A cache is confirmed present
  and its key composition is understood, but no deception attempt has been
  made yet.
- **L2 — decorated path cached, non-sensitive content.** A path-confusion
  variant is shown to produce a cache hit, but only against a
  low-sensitivity page used purely to prove the primitive.
- **L3 — sensitive per-user content cached and retrieved cross-identity.**
  A genuinely sensitive, per-user response is stored under a
  deception-crafted key and successfully retrieved by a second, distinct
  identity or an unauthenticated request. This is the threshold for a
  reportable finding.
- **L4 — durable or systemic exposure.** The deception path is reachable
  broadly (not tied to one hard-to-guess URL), affects many users'
  sessions over time, or the cached content itself enables a further
  compromise (a session token or CSRF token that grants further access).

Calibrate severity separately per [[severity-calibration]] — cached
credentials or tokens enabling account takeover are typically critical;
a narrow disclosure of low-sensitivity personal data through a single
guessable path is usually medium to high depending on reachability.

## Validation and False-Positive Discipline

Apply [[closure-discipline]] before recording anything. Class-specific
traps:

- A cache that correctly varies on `Authorization` or the session cookie
  (a properly configured `Vary` header, honored end-to-end) is a real
  control — confirm you tested the actual behavior, not just the presence
  or absence of a `Vary` header claim.
- Content that looks personalized but is actually identical for every
  user (a generic authenticated shell page) is not sensitive — confirm the
  retrieved content genuinely differs per identity before treating cross-
  identity retrieval as a finding.
- A cache-hit indicator on an intermediate layer that turns out to be
  functionally inert (a status header from a component not actually in
  the serving path) is a dead end — confirm the *content*, not just the
  header, changed hands.
- `Cache-Control: private`/`no-store` correctly enforced by the caching
  layer even when the origin's header is technically permissive is the
  control working as designed — confirm the response was actually stored
  and served, not merely eligible in theory.

## Impact

Disclosure of authenticated, per-user data to unauthenticated or
cross-identity requesters; account takeover when the cached content
includes a session token, API key, or CSRF token; and durable, broad
exposure when the deception path is reachable without prior knowledge of
a specific identity's URL.

## Summary

Cache deception needs no injection at all — only a routing/keying mismatch
between the cache and the origin. Prove the caching primitive on a
low-sensitivity page first, then repeat the exact same technique against a
genuinely sensitive endpoint, and only claim the finding once a second,
distinct identity actually receives the first identity's content back.
