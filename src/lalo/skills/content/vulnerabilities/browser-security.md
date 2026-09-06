---
name: browser-security
category: vulnerability
description: Browser-internals security — postMessage/window-relationship abuse, client-side path traversal, XS-Leaks, and service-worker/cache poisoning, with a per-class proof ladder
keywords: [postmessage, xs-leaks, cross-window messaging, client-side path traversal, service worker security, browsing context]
---

# Browser Security (Browser-Internals Exploitation)

Some client-side impact depends on browser behavior that goes well beyond
a basic HTML/script injection: window and frame relationships, message
passing between origins, navigation and history state, and what a service
worker or Cache API entry can persist for later reuse. Use the browser
tool itself (not just the HTTP firer) to observe and reproduce these,
since a raw HTTP client cannot model window/worker/cache semantics at all.

## Attack Surface

- `postMessage` senders and listeners across windows/iframes/popups —
  message schema, origin checks, and source checks each need independent
  verification.
- Client-side routers and SPA navigation that interpolate a path/query/hash
  value into a subsequent `fetch`/XHR call, distinct from a server-side
  path-traversal sink.
- Cross-origin timing and state oracles (XS-Leaks) that need no ability to
  read a cross-origin response body at all — load/error events, cache
  state, and navigation timing are enough.
- Service workers and the Cache API, which can persist attacker-influenced
  content for reuse by a completely different later page load.

## Recon

- For every `postMessage` listener found in source or via runtime
  instrumentation, record its expected message schema and which
  properties it checks: `event.origin`, `event.source`, and any
  application-level schema/token check — a listener missing any of these
  is a candidate.
- Map the browsing-context graph for the flow under test: opener/parent/
  child relationships, named window/frame targets, and whether COOP or
  `noopener` isolates them — a security check on `event.origin` is
  meaningful only once this graph is understood, since an attacker may
  still hold a live reference to a context they don't own.
- For a client-side router suspected of path traversal, trace the FULL
  pipeline: URL → router parser → route/query/hash accessor → app
  interpolation → the actual `fetch`/XHR call — instrument `fetch`/XHR at
  runtime to capture the real final URL, since encoding/decoding can
  differ at each hop.
- Check whether a service worker is registered for the origin, its scope,
  and whether its fetch handler ever serves or caches a response whose
  content an unprivileged script context could have influenced.

## Techniques (start quiet, escalate only as needed)

1. **postMessage origin/source bypass.** Send a message from a page at a
   different origin (or, if the listener checks `event.source` instead of
   `event.origin`, from within a nested/opened context sharing the
   assumed identity) and confirm whether a listener missing a proper
   origin+source+schema check accepts it and triggers a real action.
2. **Client-side path-traversal probe.** Feed `%2F`, `%5C`, `%2E%2E`, and
   double-encoded variants independently into the path, query, and hash
   portions of a client-routed URL, and instrument the actual outbound
   `fetch`/XHR call to see where and how each form decodes — a
   traversal-shaped value reaching the final request is the primitive;
   the sink determines impact (CSRF-like state change, XSS via an
   HTML-rendering response, or SSRF if it reaches a server-side fetch).
3. **XS-Leak oracle construction.** Build a paired-control test comparing
   an authenticated-true vs. authenticated-false (or owned vs. foreign)
   resource load using only observable, non-body signals — `onload`/
   `onerror` firing, timing, or cache hit/miss — and confirm the
   difference is reproducible across repeated trials, not noise.
4. **Service-worker/cache poisoning.** From a constrained script context
   (a worker, an iframe with limited privileges) that can still write to
   a shared Cache API entry, write a poisoned response and confirm a
   LATER, separate page load (or the service worker's own fetch handler)
   actually consumes and serves that poisoned entry.
5. **Window-name/reference collision.** Where a `window.open()` target
   name or an iframe name is predictable, check whether an unrelated page
   can create or reuse a context under that same name within the same
   browsing-context group, and whether that gives it a usable reference to
   the original page's window object.

## Proof Ladder

- **L1 — missing check identified.** A `postMessage` listener, router
  decode path, or service-worker fetch handler is confirmed to be missing
  a specific check (origin, source, schema, or cache-key scoping), but no
  actual cross-context message or traversal has been delivered yet.
- **L2 — delivery confirmed.** A crafted message, traversal-shaped URL, or
  cache write is shown reaching the vulnerable listener/handler in a real
  browser session — but the resulting action or oracle has not yet been
  observed to have real effect.
- **L3 — concrete effect proven.** The listener performs a real,
  attacker-influenced action (a state change, a data leak into the
  attacker's page); the traversal reaches a genuine sink (a
  state-changing API call, an HTML-rendered response, a server-side
  fetch); or the XS-Leak oracle reliably distinguishes true from false
  across repeated trials with quantified separation. This is the
  threshold for a reportable finding.
- **L4 — cross-origin data exfiltration or persistent compromise.** Actual
  sensitive data crosses the origin boundary via the message/oracle/cache
  primitive, or a poisoned service-worker/cache entry is shown persisting
  and affecting a genuinely later, independent page load.

Calibrate severity separately per [[severity-calibration]] — an XS-Leak
that only confirms account existence is a different severity story than
one that exfiltrates actual sensitive field values.

## Validation and False-Positive Discipline

Apply [[closure-discipline]] before recording anything. Class-specific
traps to check before calling something confirmed:

- A message that reaches a listener but is rejected by a real schema,
  origin, or source check before any action fires is not a finding —
  confirm the check is actually absent or bypassable, not merely that a
  message arrived.
- A router that decodes traversal characters but whose decoded value never
  actually reaches a `fetch`/XHR or DOM sink proves nothing — trace the
  value all the way to a real sink before reporting.
- Distinguish unstable network behavior from a genuine oracle: repeat an
  XS-Leak trial enough times, with both true and false controls, to show
  the separation is real and not noise.
- A named-window collision blocked by COOP, `noopener`, or genuine origin
  scoping closes this specific vector — confirm which of these is actually
  in effect before claiming the collision is exploitable.

## Impact

Cross-origin data exfiltration and session/state manipulation via
`postMessage` abuse, client-side traversal escalating to CSRF-like state
changes, stored XSS, or SSRF depending on the reached sink, account/session
existence and content leakage via XS-Leak oracles, and persistent
compromise via a poisoned service-worker cache affecting future page loads.

## Summary

Browser exploitation is state-machine exploitation: model origins, context
relationships, navigation, and worker/cache state as one system, then prove
each transition with real browser evidence rather than reasoning about it
from source alone — many of these primitives simply cannot be confirmed
with an HTTP client.
