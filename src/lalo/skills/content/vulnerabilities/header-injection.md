---
name: header-injection
category: vulnerability
description: HTTP header injection — CRLF response splitting, Host-header confusion, forwarding-header trust, and cache poisoning, with a per-class proof ladder
keywords: [header injection, crlf injection, response splitting, host header attack, x-forwarded-for, cache poisoning]
---

# HTTP Header Injection

Header injection turns user input into protocol-level control, because a
header value that isn't normalized (no CR/LF stripping, no escaping) lets
the attacker terminate the current header and start writing new ones. The
bug itself usually lives in a middle layer that copies a request value
into a response header, or a proxy that trusts a forwarded header past the
boundary it controls — impact depends entirely on which downstream
component (a cache, a browser, an authorization check) consumes the
result.

## Attack Surface

- Any value echoed into a response header: `Set-Cookie`, `Location`,
  `Content-Type`, `Content-Disposition`, or a custom `X-*` field built by
  concatenating user input without CR/LF stripping.
- Request headers that get re-emitted somewhere: `Referer` in an error
  page, `User-Agent` in a correlation ID, `X-Forwarded-Host` echoed back
  into a canonical link.
- The `X-Forwarded-*`/`Forwarded`/`X-Real-IP` family specifically — these
  are informational by protocol design, and any application trusting them
  past the boundary it actually controls (its own reverse proxy) is
  exploitable by a caller who can reach the app directly or through an
  untrusted intermediate hop.
- High-value flows where a forged `Host` shapes a link the server later
  sends: password-reset and account-recovery emails, OAuth `redirect_uri`
  construction, canonical-URL generation.

## Recon

- Enumerate every response header that varies with input by flipping
  query/body/cookie values and diffing `Set-Cookie`, `Location`,
  `Content-Type`, `Content-Disposition`, `ETag`, and any custom `X-*`
  header — for each one that moves, identify whether the source is
  genuinely user-controlled or server-derived.
- Determine precedence between `Host` and `X-Forwarded-Host` by sending
  both with different values and observing which one wins in redirects,
  generated links, or logged output.
- Check whether the deployment sits behind a CDN/reverse proxy that
  already strips CR/LF and forwarding headers before the application ever
  sees them — this closes most of the class if genuinely enforced at that
  boundary, per [[closure-discipline]].
- Identify whether a CDN/cache sits in front of the response and, if so,
  whether its cache key includes every header that influences the
  response body — an unkeyed input that changes content is the
  precondition for cache poisoning.

## Techniques (start quiet, escalate only as needed)

1. **CR/LF normalization probe.** Inject `%0d%0a` (and, if that's
   filtered, double-encoding `%250d%250a`, bare `%0a`, or the tab
   character `%09` which RFC 7230 technically permits in field values)
   into the identified varying header source, and check whether a second
   header actually lands in the raw response — not just whether the
   request was accepted.
2. **Host-header confusion.** Send a legitimate password-reset or
   link-generating request with a forged `Host` (or `X-Forwarded-Host`,
   testing precedence both ways) and confirm whether the generated link
   in the response or the actual delivered email points at the forged
   host — this is usually the single fastest, highest-value test in this
   class.
3. **Forwarding-header trust probe.** Spoof `X-Forwarded-For`,
   `X-Real-IP`, or `True-Client-IP` against any endpoint gated by an IP
   allowlist or per-IP rate limit, and confirm whether the spoofed value
   changes the authorization or throttling decision.
4. **Cache-key/response-content split.** Find an input that changes the
   response body but is NOT part of the cache key, then confirm from a
   second, unrelated session that the poisoned response is actually
   served back — see [[web-cache-deception]] for the closely related
   deception variant of this same underlying gap.
5. **Cookie manipulation.** Where a cookie value or attribute is
   influenced by input, test widening scope (`Domain=.example.com`,
   `Path=/`), forcing persistence or expiry (`Max-Age`), and same-name
   cookie shadowing (cookie tossing) from a sibling subdomain.
6. **Method-override probing.** Where `X-HTTP-Method-Override` (or an
   equivalent) is honored, confirm whether it's consulted BEFORE or after
   method-based authorization — reaching a state-changing handler this way
   from a non-browser caller bypasses a check gated only on the original
   HTTP verb.

## Proof Ladder

- **L1 — normalization gap identified.** An unnormalized value is
  confirmed reaching a header sink (via a benign marker), but no second
  header, cache effect, or trust decision has been changed yet.
- **L2 — protocol effect confirmed.** A real second header lands (CRLF
  confirmed live, not just accepted), or a spoofed forwarding header is
  shown changing a logged value — but not yet a security-relevant
  decision or a cross-session effect.
- **L3 — security decision or cross-session effect proven.** A forged
  `Host`/forwarding header actually changes an authorization or
  rate-limit outcome, a generated link in a real delivered artifact
  (email, redirect) points at the attacker's host, or a poisoned cached
  response is confirmed served to a genuinely separate session. This is
  the threshold for a reportable finding.
- **L4 — account takeover or systemic cache compromise.** The Host/
  forwarding-header confusion is chained into full account takeover (a
  captured password-reset token delivered to an attacker-controlled
  host), or the cache-poisoning primitive is shown affecting a public,
  shared cache entry reachable by arbitrary future visitors.

Calibrate severity separately per [[severity-calibration]] — CRLF
confirmed-but-stripped-downstream is a much lower severity than the same
primitive chained into an account-takeover-capable Host-header attack.

## Validation and False-Positive Discipline

Apply [[closure-discipline]] before recording anything. Class-specific
traps to check before calling something confirmed:

- CRLF that is accepted by the application but stripped by an OUTER proxy
  before reaching any real client or cache is not exploitable — confirm
  the injected header actually reaches the final consumer, not just that
  the app-layer call accepted the string.
- A forwarding header (`X-Forwarded-*`) reflected only into logs, with no
  authorization, rate-limiting, or trust decision made from it, is not a
  security boundary — do not report the reflection alone.
- Cache poisoning requires a genuinely UNKEYED input — confirm the
  specific input that changes the response body is not also part of the
  cache key, and confirm the poisoned response reaches a second,
  independent request/session, not just the same one that sent it.
- Method-override headers reachable only from a browser (which triggers a
  CORS preflight for a non-safelisted header) are not a CSRF primitive on
  their own — this technique is most useful from server-to-server or
  non-browser callers; state which caller type your proof used.

## Impact

Cross-user cache poisoning (defacement, stored XSS, or authenticated
content served to anonymous visitors), account takeover via Host-confused
password-reset or OAuth flows, authorization or rate-limit bypass on
endpoints trusting forwarding headers, and session fixation or hijack via
cookie manipulation.

## Summary

Header injection is a normalization failure somewhere on the request →
response path. Audit every header whose value moves with input, and treat
every `Host`/`X-Forwarded-*` trust decision as a security boundary that
needs explicit justification, not an assumed-safe convention.
