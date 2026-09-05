---
name: xss
category: vulnerability
description: Reflected, stored, and DOM-based cross-site scripting — context classification, sink mapping, and a per-class proof ladder
keywords: [xss, cross-site scripting, dom xss, stored xss, reflected xss, script injection, csp]
---

# Cross-Site Scripting

XSS persists because output context, parser behavior, and framework
auto-escaping each have edges. The question is never "does this reflect" —
it is "does this reflect *unescaped for its exact context*."

## Attack Surface

- **Types**: reflected (in the immediate response), stored (persisted and
  served to other users later — check whether it reaches an admin or
  higher-privilege viewer, which changes both impact and how you prove it),
  and DOM-based (a client-side source reaches a client-side sink with no
  server round trip involved in the vulnerable step itself).
- **Contexts**, each with different encoding requirements: HTML body text,
  an HTML attribute value (quoted or unquoted), a URL or `javascript:`-style
  scheme, a JavaScript string literal, CSS, and SVG/MathML (which execute
  script via handlers like `onload`, not just `<script>` tags).
- **Client-side sinks** worth checking explicitly:
  `innerHTML`/`outerHTML`/`insertAdjacentHTML`, `document.write`, a
  framework's raw-HTML escape hatch (React's `dangerouslySetInnerHTML`,
  Vue's `v-html`, Svelte's `{@html}`, Angular's `$sce` trust APIs), and
  string-built `setTimeout`/`setInterval`/`eval`/`Function` calls.
- **Client-side sources** feeding those sinks: `location.hash`/`search`,
  `document.referrer`, `postMessage` payloads, WebSocket messages, and
  local/session storage — a DOM XSS often has no server involvement in the
  vulnerable step at all, so testing only server responses will miss it.
- Defenses to identify before testing: Content-Security-Policy (nonces,
  hashes, or an allowlist — note whether `unsafe-inline`, `data:`, or
  wildcards are present), Trusted Types, and a sanitizer library's actual
  configuration (strict mode vs. default).

## Recon

- For each candidate input, trace it from source to sink rather than
  guessing at payloads — the sink's context (HTML text vs. attribute vs.
  script vs. URL) determines which encoding would actually be correct, and
  therefore which payload shape would actually execute if it is missing.
- Check whether the value round-trips through more than one render path
  (server-side render vs. client-side hydration vs. an API response
  consumed by a separate front end) — a value safely escaped on one path is
  not necessarily safe on all of them.
- For stored candidates, identify who else will view the stored value —
  same-privilege users, a moderation/admin panel, or an automated system —
  since the viewer determines both impact and how you will prove execution
  reached them.

## Techniques (start quiet, escalate only as needed)

1. **Context classification first.** Reflect a unique, inert marker string
   and observe exactly how it comes back (raw, HTML-entity-encoded,
   attribute-encoded, JS-string-escaped, or stripped). This one request
   tells you which encoding is missing, if any — before spending payloads.
2. **Minimal context-correct probe.** Craft the smallest payload that would
   actually execute given the classified context — an unquoted-attribute
   event handler needs a very different string than an HTML-text-context
   tag. A minimal, targeted probe is also easier to defend as unambiguous
   evidence than a large canonical payload string.
3. **Alternate tags/handlers when the obvious one is filtered.** If
   `<script>` is stripped or blocked, other elements execute via event
   handlers or `onload`/`onerror`-style attributes — this is a filter-shape
   question, not a different vulnerability.
4. **Parser-differential and mutation cases.** Some markup that looks inert
   to a naive filter is repaired by the browser's HTML parser into something
   executable (malformed tags, `<noscript>` boundary tricks). Worth checking
   specifically when a sanitizer looks otherwise correctly configured.
5. **CSP/Trusted-Types bypass, only once a policy is actually present.**
   Check the policy for what it actually restricts before assuming it is a
   dead end: missing nonces/hashes, `unsafe-inline`, allowed `data:`/`blob:`
   schemes, or a JSONP/script-gadget endpoint on an allowed origin are all
   real bypass paths — record the exact policy gap you used.

Do not stop at a bare alert/marker execution — demonstrate a step toward
real impact (reading a cookie or storage value the same-origin policy would
otherwise protect, making an authenticated request as the victim, modifying
the DOM in an observable way) before calling this confirmed.

## Proof Ladder

- **L1 — reflection identified.** Your marker reflects without the
  encoding its context requires, but you have not yet produced an
  executing payload.
- **L2 — execution in a low-value context.** A payload executes (an alert
  or console log equivalent) but only in a context that requires unusual
  victim interaction or has no path to real impact yet (e.g. an isolated
  test page you control, not the real application flow).
- **L3 — execution in the real application with a real victim path.** The
  payload executes in the actual application, reachable via a realistic
  victim action (visiting a link, viewing stored content), and you have
  demonstrated a concrete effect beyond a bare alert — reading a real
  cookie/token/storage value, or performing an action as the victim. This
  is the threshold for a reportable finding.
- **L4 — full session/account compromise.** You demonstrated end-to-end
  session or credential exfiltration, or an authenticated action taken as
  the victim with material impact (not just proof the channel exists).

Severity is calibrated separately per [[severity-calibration]] — a
self-triggered or interaction-heavy finding is rarely more than medium even
at L3/L4; an unauthenticated stored payload reaching every visitor is a
different severity story even at the same proof level.

## Validation and False-Positive Discipline

Apply [[closure-discipline]] before recording anything. Class-specific
traps:

- Reflection that is correctly encoded *for its actual context* is not a
  finding — confirm you tested the real context the browser will parse, not
  an assumed one (an attribute-context payload tested as if it were an
  HTML-text payload will look "blocked" when it was never applicable).
- A CSP header being present is not proof of safety by itself — check
  whether it actually blocks the specific payload's mechanism (inline
  script vs. an allowed external origin vs. `javascript:` URLs are
  independent policy dimensions).
- A sanitizer library being present is not proof of safety — confirm its
  actual configuration (strict mode, allowed tags/attributes/URI schemes)
  rather than assuming a default.
- Execution that only occurs on a page you crafted yourself, not on any
  real page/flow the application actually serves, is not yet a finding —
  it is a starting point for finding the real reachable path.

## Impact

Session or credential theft, account takeover via token exfiltration,
cross-site request forgery chaining onto a state-changing action, DOM
manipulation for phishing overlays, and persistence via a registered
service worker or re-injected storage value.

## Summary

Context and sink decide whether a reflection is exploitable — classify
before crafting a payload. Prove impact beyond a bare execution marker, and
verify every claimed defense (CSP, sanitizer, framework escaping) by its
actual configuration, never by its presence alone.
