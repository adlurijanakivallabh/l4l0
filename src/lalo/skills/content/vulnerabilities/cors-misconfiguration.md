---
name: cors-misconfiguration
category: vulnerability
description: CORS misconfiguration — reflected-origin ACAO, null-origin acceptance, subdomain-wildcard trust, and credential-leaking combinations, and a per-class proof ladder
keywords: [cors, cross-origin resource sharing, acao, access-control-allow-origin, null origin, credentials wildcard, preflight]
---

# CORS Misconfiguration

Cross-Origin Resource Sharing exists to relax the browser's same-origin
policy on purpose, for a named set of trusted origins. The vulnerability is
never CORS being present — it is the server computing which origins to
trust so permissively that the "trusted set" collapses to "anyone who
asks." Every technique below is really the same question asked a different
way: does the server's `Access-Control-Allow-Origin` decision actually
depend on a real allow-list, or does it just echo whatever the browser
sent?

## Attack Surface

- Any API or endpoint that returns `Access-Control-Allow-Origin` (ACAO) at
  all — this is opt-in behavior, so its presence already means someone
  decided cross-origin reads were sometimes appropriate; the question is
  whether the decision logic behind it is sound.
- Endpoints that also return `Access-Control-Allow-Credentials: true` are
  categorically higher value: this header is what turns a cross-origin read
  into a read *of the victim's own authenticated session* (cookies sent,
  `Authorization` headers usable via `fetch` with `credentials: "include"`).
- Multi-tenant or multi-subdomain applications, where the CORS policy is
  commonly implemented as "allow anything under `*.example.com`" — a
  pattern that is only as safe as every subdomain in that set, including
  ones the security team does not control (a dead subdomain, a customer
  demo instance, a marketing microsite on a CMS).
- Internal APIs exposed to a browser-based frontend, where a wide-open CORS
  policy was added purely to unblock local development and never narrowed
  for production.

## Recon

- Fetch the target endpoint once with no `Origin` header, once with a
  clearly foreign `Origin` (an attacker-controlled domain you actually
  control, not just a guess), and once with `Origin: null`, and diff the
  three `Access-Control-Allow-Origin`/`Access-Control-Allow-Credentials`
  response pairs — this single triple tells you which of the patterns below
  is in play before you touch anything else.
- Read the policy logic's intent from its own behavior: does ACAO ever
  differ per request, or is it a static value baked into every response
  regardless of what `Origin` was sent? A static, non-reflective ACAO of a
  specific trusted domain is not a finding; a value that changes to match
  whatever `Origin` you sent is the signal to keep going.
- Note whether `Vary: Origin` is present when ACAO is dynamic — its absence
  is a caching hazard on top of any CORS issue (a cache serving one origin's
  permissive CORS response to a different origin), not itself the primary
  finding, but worth recording alongside one.
- Identify what a successful cross-origin read would actually expose:
  session-bound data, an API token, CSRF tokens, or account details are the
  payload that makes any of the following techniques worth pursuing at all.

## Techniques (start quiet, escalate only as needed)

1. **Origin reflection probe.** Send the request with an arbitrary,
   clearly-external `Origin` header and check whether the response's ACAO
   echoes that exact value back rather than a fixed, expected origin. This
   is the cheapest and most common misconfiguration — a server that
   reflects `Origin` unconditionally has no allow-list at all, it merely
   has the *appearance* of one.
2. **Null-origin acceptance, if reflection alone did not trigger.** Send
   `Origin: null` (which a browser sends from a sandboxed iframe, a
   `file://` page, or certain redirect chains — all attacker-reachable
   contexts) and check whether the server treats it as trusted. Servers
   that special-case `null` as an allowed value are usually doing so to
   accommodate local file testing that was never removed.
3. **Subdomain-wildcard trust boundary probing, only when the policy is
   clearly matching on a domain suffix.** If the reflected/allowed origin
   pattern suggests a suffix or wildcard match (`*.example.com`, or logic
   that checks `origin.endswith("example.com")` without a delimiter), test
   with a domain that satisfies the naive check but is not actually a
   subdomain (`evilexample.com`, `example.com.attacker.net`), and
   separately identify any real, attacker-registerable or forgotten
   subdomain that the suffix match would legitimately admit.
4. **Credentials-plus-permissive-origin confirmation.** Once a permissive
   ACAO pattern is established, check specifically whether
   `Access-Control-Allow-Credentials: true` accompanies it — this is the
   step that turns "cross-origin read of public data" into "cross-origin
   read of the victim's own session," and is the detail that decides
   whether this is worth a full proof-of-concept at all.
5. **Preflight bypass and method/header scope check, once a permissive
   result is confirmed.** Confirm whether the permissive policy also covers
   non-simple requests (custom headers, `PUT`/`DELETE`, `application/json`
   bodies) via the `OPTIONS` preflight response's
   `Access-Control-Allow-Methods`/`-Headers`, or whether the vulnerable
   response only reaches simple `GET`/`POST` requests that skip preflight
   entirely — this determines how much of the API is actually reachable
   from a hostile page, not just whether the header itself is broken.
6. **End-to-end cross-origin proof, the actual evidence.** From a page
   hosted on a domain you control (not a browser dev-tools `fetch` call
   from the target's own origin, which proves nothing about cross-origin
   behavior), issue an authenticated `fetch` with `credentials: "include"`
   against the vulnerable endpoint while a victim session cookie is present
   in that browser, and confirm the response body — containing real
   session-bound data — is readable by your page's JavaScript.

## Proof Ladder

- **L1 — permissive ACAO pattern identified.** Origin reflection, null-origin
  acceptance, or a naive subdomain-suffix match is observed in the response
  headers, but no actual cross-origin read has been attempted from a
  browser context yet.
- **L2 — cross-origin read demonstrated, non-sensitive data.** A real
  cross-origin `fetch` from an attacker-controlled origin successfully
  reads a response, but the data returned is not session-bound or
  otherwise sensitive (a public endpoint that happened to have a broken
  CORS policy anyway).
- **L3 — cross-origin read of authenticated, session-bound data
  confirmed.** The same technique against an authenticated endpoint, with
  `Access-Control-Allow-Credentials: true` present and a real victim
  session cookie sent, returns genuinely sensitive per-user data readable
  by the attacker's page. This is the threshold for a reportable finding.
- **L4 — durable or systemic account compromise.** The exposed data
  includes credentials, an API key, or a token sufficient to fully
  authenticate as the victim elsewhere, or the misconfiguration is present
  broadly across the API surface rather than one isolated endpoint.

Calibrate severity separately per [[severity-calibration]] — cross-origin
theft of a session token or credential enabling full account takeover is
typically critical; a narrow read of non-sensitive personalized data (a
display name, a non-secret preference) through a broken CORS policy is
usually medium.

## Validation and False-Positive Discipline

Apply [[closure-discipline]] before recording anything. Class-specific
traps:

- ACAO reflecting the request's `Origin` is not automatically dangerous —
  confirm what data the endpoint actually returns and whether
  `Access-Control-Allow-Credentials` is present; a fully public, unauthenticated
  GET endpoint with reflected ACAO and no credentials flag exposes nothing
  a direct unauthenticated request would not already expose.
- A wildcard `Access-Control-Allow-Origin: *` is explicitly forbidden by
  browsers from ever being combined with `Access-Control-Allow-Credentials:
  true` — if you observe both, confirm you actually captured the real
  response headers and are not misreading a reflected-origin value as a
  literal `*`.
- A real, intentional allow-list of specific partner domains is the control
  working correctly, even if the list is long — confirm you tested an
  origin genuinely outside that list, not a variant that happens to satisfy
  a substring match you assumed rather than observed.
- `Origin: null` acceptance is only exploitable if you can actually make a
  browser send it from a context you control (a sandboxed iframe without
  `allow-same-origin`, a crafted redirect, a local file context reachable by
  the victim) — confirm a real delivery path exists before treating null-origin
  acceptance alone as a finding.
- A CORS policy that is permissive but the endpoint requires a
  request-specific, unpredictable token the attacker cannot obtain
  cross-origin (a fresh CSRF token minted per session and validated
  server-side independent of CORS) may still be `ruled_out` for account
  takeover specifically — confirm what the endpoint actually validates
  before assuming permissive CORS alone completes the chain.

## Impact

Cross-origin theft of session-bound data, API tokens, and CSRF tokens
leading to full account takeover; exposure of internal API responses to
attacker-hosted pages when combined with credentialed requests; and, when
chained with a CSRF token read, downstream state-changing requests forged
against the victim's authenticated session.

## Summary

A broken CORS policy is a broken trust decision, not a broken header
syntax — the server's actual allow-list logic (or lack of one) is the
thing under test. Establish which pattern is in play with a small,
self-contained origin-reflection triple first, then only escalate to a
real cross-origin browser proof once credentials and genuinely sensitive
data are both confirmed to be in scope.
