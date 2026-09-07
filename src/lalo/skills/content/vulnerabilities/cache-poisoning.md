---
name: cache-poisoning
category: vulnerability
description: Web cache poisoning — injecting a malicious response into a shared cache via unkeyed inputs, cache-key normalization gaps, and fat-GET/param cloaking, and a per-class proof ladder
keywords: [cache poisoning, unkeyed input, x-forwarded-host, cache key, fat get, param cloaking, cdn, shared cache]
---

# Web Cache Poisoning

Cache poisoning is distinct from [[web-cache-deception]]: deception tricks
a cache into storing a genuine *private* response under a *public* key with
no injection at all, while poisoning injects genuinely *attacker-controlled*
content into a cache entry that every subsequent visitor of a *shared*
public URL then receives. The mechanism is an "unkeyed input" — a header,
cookie, or parameter the origin server's response actually varies on, but
that the cache does not include when computing its storage key. Whatever
value that input takes when the cache happens to store its entry is baked
into the cached response for everyone else who requests the same key,
until it expires.

## Attack Surface

- Any application sitting behind a shared cache (a CDN, a reverse-proxy
  cache, a caching API gateway) whose origin reflects a request header,
  cookie, or parameter into the response — a canonical link, a redirect
  target, an asset base URL, an error message, or injected analytics/
  feature-flag markup are all common reflection points.
- `X-Forwarded-Host`, `X-Forwarded-Scheme`, `X-Original-URL`,
  `X-Rewrite-URL`, and similar "trust the edge, told you who you really
  are" headers are the single most common unkeyed-input class: an origin
  that builds absolute URLs, canonical tags, or redirects from
  `X-Forwarded-Host` without validating it against the actual `Host` is
  poisoning-ready by construction if a cache in front of it does not key on
  that header too.
- Query parameters that affect the origin's response but that the cache
  deliberately excludes from its key for a hit-rate reason (tracking
  parameters like `utm_source`, a `debug` flag, an `_escaped_fragment_`
  variant) are an equally common unkeyed-input source, distinct from the
  header case but proven the same way.
- Any endpoint whose cache key is computed from the URL path and a fixed
  set of headers/params while the origin's actual response varies on
  something outside that set is, by definition, poisonable — the specific
  input does not need to be on any well-known list to qualify.

## Recon

- Confirm a shared cache is present and identify its behavior before
  attempting anything: `Age`, `X-Cache`, `CF-Cache-Status`, or `Via`
  headers reveal hit/miss state and which layer is caching — repeat the
  same request twice and diff these headers to establish a baseline.
- Determine the cache's key composition as precisely as recon allows: does
  it key on `Host`, on the full query string, on any request headers at
  all beyond the method and path? Cache documentation (for a known CDN
  product) or observed behavior (does changing a given header/parameter
  change whether a hit occurs) both inform this; treat observed behavior
  as authoritative over documentation.
- Separately enumerate what the *origin's* response actually varies on by
  sending the same cache-key-relevant request with different values of a
  candidate unkeyed input directly to the origin (bypassing the cache with
  a cache-buster) — an input the origin ignores entirely cannot poison
  anything regardless of cache-key gaps.
- Identify high-value response fragments that would matter if poisoned: a
  canonical URL or Open Graph tag reflecting `X-Forwarded-Host` becomes a
  reflected-XSS-via-cache primitive; a redirect target becomes an
  open-redirect served to every subsequent visitor; injected script-src
  or resource-hint URLs become a supply-chain-style injection point.

## Techniques (start quiet, escalate only as needed)

1. **Cache-buster baseline.** Attach a unique, harmless cache-buster
   parameter (one already excluded from the cache key, confirmed by seeing
   it produce a cache miss every time) to every probe below, so each test
   gets a fresh cache entry and does not read back a previous test's
   stored response — this keeps every subsequent step self-contained and
   avoids false negatives from reading a stale, unrelated cached value.
2. **Unkeyed-header reflection probe, cache-buster'd, self-contained.**
   Send a request with a distinctive marker value in a candidate unkeyed
   header (`X-Forwarded-Host: distinctive-marker.example`,
   `X-Forwarded-Scheme`, `X-Original-URL`) and check the *direct* response
   (not yet a second, cache-served request) for the marker appearing in
   the body or response headers — this confirms the origin reflects the
   input at all, before touching the cache's storage behavior.
3. **Cache-key gap confirmation, once reflection is confirmed.** Repeat the
   same request (same cache-buster'd path/params, same marker header),
   then issue a second, plain request with no special header to the same
   cache-buster'd key from a fresh client context, and check whether the
   marker value is served back — this is the step that proves the *cache*,
   not just the origin, is the vulnerable component, since it shows the
   header was excluded from the key while still affecting the stored body.
4. **Normalization-discrepancy sweep, only if the direct header probe is
   inconclusive.** Try encoding and casing variants the cache and origin
   are likely to normalize differently (a duplicate header, an
   unusual-but-valid header casing, a port suffix on `X-Forwarded-Host`,
   URL-encoded characters in the path) — use the minimum variant that
   produces a reflection, not an exhaustive sweep once one works.
5. **Fat-GET and parameter-cloaking variants, for parameter-based unkeyed
   inputs.** Move a candidate parameter into the request body of a `GET`
   request some frameworks still parse ("fat GET"), or append it after a
   fragment/cloaking delimiter (`?realparam=x#&cachebuster=y`,
   `;paramname=x`) that the cache's key parser stops at but the origin's
   own parser does not — this targets applications that specifically
   exclude query-string parsing edge cases from the cache key while the
   origin still honors them.
6. **Confirm delivery to an uninvolved third party, the actual proof.**
   From a second, genuinely distinct client (a different session, a clean
   browser profile, or literally a different network path) with no special
   headers set, request the exact poisoned cache-buster'd URL and confirm
   the injected marker is served back — a single-session round-trip proves
   the caching primitive but not that an uninvolved victim actually
   receives poisoned content.

## Proof Ladder

- **L1 — reflection and cache presence both confirmed, independently.** The
  origin is shown to reflect a candidate unkeyed input directly, and a
  shared cache is confirmed present with an established key-composition
  baseline, but no poisoned entry has actually been stored and re-served
  yet.
- **L2 — cache-key gap confirmed on a fresh, self-contained entry.** A
  cache-buster'd request with the marker header produces a stored entry
  that a *second* plain request to the same key then receives — this
  proves the mechanism works, but only within a single test's controlled
  round-trip.
- **L3 — poisoned content delivered to an uninvolved third-party request.**
  A distinct client, session, or network path with no special headers
  receives the injected marker from the shared cache, reproducible on a
  second independent attempt. This is the threshold for a reportable
  finding.
- **L4 — durable or systemic exploitation.** The poisoned response includes
  executable content (a script-injecting reflected value landing in an
  unescaped sink) or an open-redirect/credential-harvesting target, the
  poisoning is reachable on a widely-hit URL (a homepage, a shared static
  asset, a commonly-linked path) rather than an obscure cache-buster'd one,
  or the entry's TTL keeps it live and affecting new visitors for an
  extended window.

Calibrate severity separately per [[severity-calibration]] — a poisoned
entry that delivers persistent, cache-wide script execution or credential
harvesting on a high-traffic path is typically critical; a narrow
poisoning limited to a low-traffic or hard-to-reach cache key with
non-executable content is usually medium to high depending on reach and
TTL.

## Validation and False-Positive Discipline

Apply [[closure-discipline]] before recording anything. Class-specific
traps:

- A cache that correctly includes the candidate input in its key (proven by
  observing a cache *miss* whenever that input's value changes) has no gap
  to exploit — confirm you actually varied the input and observed the
  cache's real hit/miss behavior, not merely that the input appears in the
  origin's response.
- An origin that reflects an input directly but a cache never actually
  stores that specific response (a `Cache-Control: private`/`no-store`
  correctly honored by the caching layer, or a cache configuration that
  only caches static file extensions) means the reflection is real but
  inert for this specific cache — confirm actual storage, not just
  eligibility, before treating reflection alone as a finding.
- A single self-triggered round-trip (L2) is not proof of impact on real
  users — you must show a second, genuinely independent request retrieves
  the poisoned content before this rises above a primitive demonstration.
- Reflection into a context that is already escaped or encoded correctly by
  the origin (a value placed inside a properly `htmlspecialchars`'d
  attribute, a URL component correctly percent-encoded) is not itself
  exploitable even if cache-key gaps exist — confirm the reflected value
  actually lands somewhere unescaped or otherwise dangerous before claiming
  more than a benign content-injection primitive.
- Distinguish this class from a parser/desync-based cache poisoning
  reachable via [[http-request-smuggling]] — that route poisons via
  connection-level request confusion rather than an unkeyed-input/cache-key
  mismatch, and needs its own desync-specific proof, not this skill's
  header-reflection technique.

## Impact

Persistent, cache-wide cross-site scripting or content injection served to
every visitor of a poisoned URL without any per-victim action required;
open-redirect delivery at scale; cache-wide denial of service when the
injected content breaks page rendering or triggers client-side errors; and,
when the injected content itself references attacker-controlled resources
(a script-src, a resource hint), a supply-chain-style compromise of every
page load that hits the poisoned entry until it expires or is purged.

## Summary

Cache poisoning always reduces to the same question: does the origin's
response depend on something the cache's key does not? Confirm origin
reflection and cache presence independently and cheaply first, prove the
key gap with a self-contained cache-buster'd round-trip, and only claim the
finding once a genuinely separate, uninvolved request actually receives the
poisoned content back — reach and TTL, not just the mechanism, are what
decide how severe it is.
