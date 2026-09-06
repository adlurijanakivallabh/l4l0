---
name: open-redirect
category: vulnerability
description: Open redirect — parser-differential and allowlist-bypass techniques for phishing, OAuth token theft, and redirect-following SSRF, with a per-class proof ladder
keywords: [open redirect, unvalidated redirect, oauth redirect_uri, ssrf chaining, url parser confusion]
---

# Open Redirect

An open redirect is dangerous specifically because of what it's chained
into, not the redirect itself: phishing (a link on a trusted domain that
lands the victim on an attacker page), OAuth/OIDC code or token theft (an
authorization code delivered to a `redirect_uri` that itself bounces
off-domain), and SSRF pivoting (a server-side fetcher that follows a 3xx
from an allowlisted host into an internal target). Almost every real-world
bypass is a **parser differential**: the validator's URL parsing disagrees
with the browser's (or the fetching library's) actual navigation behavior.

## Attack Surface

- Server-driven redirects (HTTP 3xx `Location`) and client-driven ones
  (`window.location`/`location.assign`/`location.replace`, meta refresh,
  SPA router `push`/`replace` calls fed directly from a query parameter).
- OAuth/OIDC/SAML flows: `redirect_uri`, `post_logout_redirect_uri`
  (frequently validated more loosely than the primary `redirect_uri`),
  `RelayState`, `returnTo`/`continue`/`next`.
- High-value surfaces specifically: login/logout, password reset, SSO
  entry points, payment gateways, email/invite links, unsubscribe links,
  and any dedicated `/out` or `/r` link-redirector endpoint.
- Server-side fetchers that follow redirects on the application's behalf —
  link unfurlers, webhook validators, PDF/screenshot renderers — turn an
  open redirect on an allowlisted host into an SSRF pivot with no separate
  vulnerability of their own required.

## Recon

- Enumerate every parameter shaped like a redirect target across the app:
  `redirect`, `url`, `next`, `return_to`, `returnUrl`, `continue`, `goto`,
  `target`, `callback`, `dest`, `back`, `to`, `r`, `u` — and the OAuth-
  specific `redirect_uri`/`post_logout_redirect_uri`/`RelayState`/`state`.
- For each candidate, determine what actually validates it: a substring/
  regex "contains" check, a wildcard subdomain match, an exact-origin
  allowlist, or nothing at all — each has a distinct, well-known bypass
  shape (below).
- Check whether validation happens only on the FIRST hop of a redirect
  chain — a trusted-domain redirector that itself accepts an unvalidated
  second-hop target is a very common gap.
- Identify any server-side component that follows redirects on the
  application's behalf (link preview, webhook delivery, screenshot
  service) — this is what turns the finding into SSRF, not just phishing.

## Techniques (start quiet, escalate only as needed)

1. **Parser-differential probes.** Compare how the validator parses a URL
   against how a real browser navigates it: userinfo confusion
   (`https://trusted.com@evil.com` — many parsers read the host as
   `trusted.com`), backslash/slash confusion (`https://trusted.com\evil.com`,
   `///evil.com`, `/\evil.com`), and encoded whitespace/control characters
   before the scheme (`http%09://evil.com`).
2. **Allowlist evasion.** Against a substring-contains check, append the
   trusted domain as a subdomain of the attacker's own
   (`https://trusted.com.evil.com`); against a `*.trusted.com` wildcard,
   register `attacker.trusted.com.evil.net` (the wildcard match is on a
   substring position, not a suffix boundary) or use Unicode/IDN
   look-alikes and a full-width dot (`trusted.com。evil.com`).
3. **Scheme and encoding smuggling.** Try non-HTTP(S) schemes the
   validator may not anticipate (`data:`, `javascript:`, `file:`), mixed
   case (`hTtPs://`), and double URL-encoding (`%2f%2fevil.com`,
   `%252f%252fevil.com`) against a validator that decodes only once.
4. **Multi-hop chaining.** Where the first hop lands on a legitimate
   trusted redirector, feed that redirector an unvalidated second-hop
   target — proving the allowlist is enforced only at the entry point.
5. **OAuth/OIDC redirect_uri abuse.** Combine an open redirect ON a
   registered trusted domain with an OAuth flow's `redirect_uri` — the
   identity provider delivers the authorization code to the trusted host,
   which then bounces it to the attacker; `post_logout_redirect_uri` is
   worth checking separately, since it is frequently validated less
   strictly than the sign-in flow's own `redirect_uri`.
6. **SSRF-via-redirect-following.** Point a server-side fetcher (link
   unfurler, webhook validator, screenshot renderer) at an allowlisted
   host's open-redirect endpoint with an internal target as the redirect
   destination (a cloud metadata address, `localhost`, an internal-only
   hostname) — confirm the internal fetch actually occurred via an OAST
   callback or a timing/response difference, per [[ssrf]].

## Proof Ladder

- **L1 — bypass constructed.** A crafted URL is confirmed to defeat the
  stated validator (accepted where a plain external URL would be
  rejected), but no actual navigation or fetch to the external target has
  been observed yet.
- **L2 — navigation confirmed.** A real browser (or the actual server-side
  fetcher) is shown navigating/fetching to the attacker-controlled
  destination — full address-bar or fetch-log capture, not just an
  accepted parameter.
- **L3 — credential or code delivery proven.** An OAuth authorization
  code, session token, or `RelayState` value is actually captured at the
  attacker-controlled endpoint via the redirect chain, or a phishing chain
  is demonstrated end-to-end against a real trusted-domain link. This is
  the threshold for a reportable finding.
- **L4 — SSRF pivot or systemic bypass.** The redirect is chained into a
  confirmed internal-network fetch (cloud metadata, internal service) per
  [[ssrf]]'s own proof ladder, or the same allowlist-bypass technique is
  reproduced across multiple independent redirect surfaces in the
  application.

Calibrate severity separately per [[severity-calibration]] — a redirect on
an unauthenticated marketing link is a different severity story than one
sitting inside an OAuth `redirect_uri` or chainable into SSRF.

## Validation and False-Positive Discipline

Apply [[closure-discipline]] before recording anything. Class-specific
traps to check before calling something confirmed:

- A redirect restricted to relative, same-origin paths with real
  normalization (no scheme, no protocol-relative `//`, no traversal
  sequences surviving decode) is not vulnerable — confirm the validator
  actually rejects an absolute or protocol-relative value, not just that
  no example happened to use one.
- An OAuth `redirect_uri` validated by an EXACT, pre-registered match
  (not a prefix/suffix check) closes this class entirely for that flow —
  distinguish exact-match validation from a "starts with" or "contains"
  check before concluding a bypass exists.
- A parser-differential payload must be shown reaching REAL navigation or
  a real fetch, not just surviving server-side validation — a value that
  passes the check but that no client (browser or fetcher) would actually
  interpret as pointing off-domain proves nothing.
- Compare the validator's behavior against actual browser navigation for
  every bypass class attempted — a difference between what the server
  accepts and what a browser resolves is the entire mechanism; without
  that gap demonstrated, there is no finding.

## Impact

Credential and session-token theft via phishing, OAuth/OIDC authorization-
code or `RelayState` interception, internal-network exposure when a
server-side fetcher follows the redirect (SSRF), and erosion of user trust
in the trusted domain's own links and brand.

## Summary

A redirect is safe only when its final destination is constrained AFTER
full canonicalization, using a single consistent URL parser, against an
exact-origin allowlist — not a substring/wildcard check — and re-validated
at every hop of a chain, not just the first.
