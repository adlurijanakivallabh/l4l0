---
name: csrf
category: vulnerability
description: Cross-site request forgery — SameSite/token/Origin bypass, content-type games, and login/OAuth chaining, with a per-class proof ladder
keywords: [csrf, cross-site request forgery, samesite, anti-csrf token, origin check, referer check, xsrf]
---

# Cross-Site Request Forgery (CSRF)

CSRF abuses ambient authority — a cookie or HTTP-auth credential the browser
attaches automatically — to make a victim's browser issue a state-changing
request the victim never intended. It is eliminated only when a state change
requires a secret the attacker cannot supply, verified consistently across
every method, content type, and transport a request can arrive through — not
by CORS, which controls whether a cross-origin caller can *read* a response,
never whether it may *cause* one.

## Attack Surface

- Any state-changing action reachable from a session the browser attaches
  automatically: cookie-based sessions and HTTP auth are exposed; bearer
  tokens sent only via an `Authorization` header the page must set explicitly
  are not, unless the app *also* accepts them via cookie as a fallback.
- High-value targets specifically: credential/profile changes (email,
  password, phone, MFA enable/disable), payment and money movement, API-key
  or SSH-key generation, OAuth connect/disconnect, account deletion, and
  admin/staff/impersonation actions — prioritize these over low-sensitivity
  toggles.
- Non-REST transports carry the same risk and are easy to miss: GraphQL
  mutations reachable via GET or a persisted query, and WebSocket handshakes
  — browsers attach cookies to both.
- A state change hidden behind what looks like a read (a "confirm" GET link,
  a webhook/back-office endpoint meant for staff) is exactly the shape that
  slips past a review focused only on POST/PUT/DELETE routes.

## Recon

- Inspect the session cookie's own attributes first: `HttpOnly`, `Secure`,
  and `SameSite` (`Strict`/`Lax`/`None`). `Lax` (the modern default) still
  sends the cookie on a top-level cross-site *navigation* (a plain link or
  auto-submitting GET form), just not on cross-site XHR/fetch or a
  non-top-level POST — this is the single most common source of a false
  "SameSite protects it" assumption.
- Locate any anti-CSRF token (hidden form field, meta tag, custom header) and
  check whether the server actually verifies `Origin`/`Referer` on state
  changes at all, independent of the token — many implementations have a
  token that LOOKS present but is never actually checked server-side.
- Confirm which methods perform state changes — GET/HEAD "read" endpoints
  that quietly also change state are a direct SameSite=Lax bypass.
- Note which content types the endpoint accepts. `application/x-www-form-
  urlencoded`, `multipart/form-data`, and `text/plain` are all "simple"
  requests a browser sends without a CORS preflight; if the server parses
  JSON out of any of these (or a framework treats `data[foo]=bar`-style form
  keys as equivalent to nested JSON), a JSON-only endpoint is not actually
  CSRF-safe just because it "requires JSON."

## Techniques (start quiet, escalate only as needed)

1. **Token/header removal.** Resubmit the legitimate request with the
   anti-CSRF token or custom header stripped entirely. If the server accepts
   it, there is no real enforcement regardless of what the client sends.
2. **Cross-session token reuse.** Reuse a token captured from one session
   (or one page load) in a request under a different session — a token not
   actually bound to the session/user proves nothing even when present.
3. **Origin/Referer bypass.** Send the request with a missing, null (an
   iframe sandboxed without `allow-same-origin`, or an `about:blank`/`data:`
   navigation both produce a null `Origin`), or cross-origin value for
   `Origin`/`Referer` — some frameworks incorrectly accept a null value.
4. **Content-type switching.** If the endpoint expects JSON, retry the exact
   same state change as `application/x-www-form-urlencoded`,
   `multipart/form-data`, or `text/plain` — a preflightless request that
   still reaches the same handler defeats a CORS-only defense outright.
5. **Top-level GET navigation.** For a GET-triggerable state change, an
   auto-navigating link (no script required) is the cleanest, quietest
   proof — it works even against `SameSite=Lax`, since that setting only
   restricts cross-site GET at the *iframe/subresource* level, not top-level
   navigation.
6. **Login/logout chaining.** Force-logout (clearing session state and any
   session-bound token) then force-login as an attacker-controlled account —
   a victim's subsequent actions land under the attacker's identity, turning
   a "just a logout" CSRF into full account-binding.

## Proof Ladder

- **L1 — defense gap identified.** A missing/removable token, an unchecked
  `Origin`/`Referer`, or a state-changing GET is confirmed structurally, but
  no actual cross-origin trigger has been built yet.
- **L2 — cross-origin request delivered.** A real cross-origin page (or
  auto-submitting form) successfully reaches the vulnerable endpoint and the
  server processes it as authenticated — but the state change itself has not
  yet been observed to take effect.
- **L3 — state change proven under the victim's identity.** The action
  actually occurred (a real before/after state diff for the SAME account),
  driven entirely by a cross-origin trigger with no client-side credential
  ever supplied by the attacker's page. This is the threshold for a
  reportable finding.
- **L4 — high-value or chained compromise.** The forged action changes
  credentials/authorization (password, email, MFA, role) or is chained with
  another primitive (login CSRF to bind a victim to an attacker account,
  CSRF+IDOR to act on another user's resource once references are known,
  CSRF+open-redirect to widen an OAuth-flow abuse).

Calibrate severity separately per [[severity-calibration]] — CSRF on a
low-sensitivity preference toggle is a different severity story than CSRF on
password change or a funds transfer, even at the same proof level.

## Validation and False-Positive Discipline

Apply [[closure-discipline]] before recording anything. Class-specific
traps to check before calling something confirmed:

- Demonstrate the state change with a real cross-origin page requiring no
  interaction beyond a visit (or, honestly, one plain click) — a same-origin
  test, or one requiring the victim to already be authenticated to an
  attacker-controlled tool, proves nothing about cross-site forgery.
- A token or `Origin` check that exists is not the same as one that is
  *enforced*: prove enforcement by showing the exact condition it fails
  under (missing token accepted, null Origin accepted, method override
  bypassing a check applied only to the original verb) — do not assume
  absence of a visible token field means absence of protection, since
  `SameSite=Strict` with no HTTP-auth fallback can make an endpoint
  genuinely un-forgeable with no token at all.
- An operation that is idempotent and non-sensitive (a public "like" button,
  a UI theme toggle) reproduced via forged request is a real finding of
  *missing defense*, but its severity is not comparable to a credential or
  financial action — do not inflate a low-impact toggle to a high-severity
  finding just because the forgery itself succeeded.
- Permissive CORS (`Access-Control-Allow-Origin: *` or a reflected origin
  with credentials) is a *different* vulnerability (cross-origin data
  exfiltration) from CSRF — do not conflate the two or treat one as proof of
  the other; a tightly-scoped CORS policy does not by itself defend against
  CSRF, and a broken CORS policy does not by itself confirm a CSRF gap.

## Impact

Unauthorized account-state changes (email/password/MFA/role), financial
operations performed under the victim's identity, session/account binding
via login CSRF, durable authorization changes (permission or key rotation),
and — when chained with IDOR, open redirect, or an OAuth mix-up — broader
compromise than the single forged action alone would suggest.

## Summary

CSRF is eliminated only when a state change requires a secret the attacker
cannot supply and the server verifies the caller's origin — consistently,
across every method, content type, and transport the endpoint accepts, not
just the one the frontend happens to use by default.
