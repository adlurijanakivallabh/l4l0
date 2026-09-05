---
name: http-request-smuggling
category: vulnerability
description: HTTP request smuggling / desync — CL.TE, TE.CL, H2-downgrade parser differentials, and a per-class proof ladder
keywords: [request smuggling, desync, http smuggling, cl.te, te.cl, h2.cl, h2.te, transfer-encoding, content-length]
---

# HTTP Request Smuggling / Desync

Smuggling exploits a disagreement between a front-end proxy and a back-end
server about where one request ends and the next begins. Once the two
systems parse `Content-Length` and `Transfer-Encoding` differently, a
prefix hidden in one request gets prepended to whatever the *next* client
sends on the same back-end connection — turning a parser bug into
cross-user impact.

## Attack Surface

- Any topology with a front-end and a back-end that parse HTTP
  independently: a CDN or load balancer in front of an origin, a reverse
  proxy chain, an API gateway forwarding to microservices, or a WAF that
  terminates and re-forwards.
- HTTP/2-to-HTTP/1.1 downgrades are a distinct and increasingly common
  surface (H2.CL / H2.TE) — the ambiguity does not exist in HTTP/2's own
  framing, only in what the downgrade step injects for the back-end.
- Connection reuse is the precondition for all of it — a proxy that closes
  the back-end connection after every request has no desync surface
  regardless of parser behavior.

## Recon

- Map the proxy chain first: identify the front-end (CDN, load balancer,
  WAF) and the back-end (application server) before crafting anything —
  the specific pairing determines which differential is even possible.
- Check whether the connection to the back-end is pooled/reused; a
  desync with no connection reuse has no victim request to poison.
- Note whether the front-end is HTTP/2 while the back-end is HTTP/1.1 —
  this is worth testing independently of classic CL/TE probes, since it is
  a materially different (and currently under-tested) mechanism.

## Techniques (start quiet, escalate only as needed)

1. **Timing-based probe, self-contained.** Send a request with a
   deliberately incomplete chunked body against a matching `Content-Length`
   (or vice versa) and observe whether the back-end times out waiting for
   bytes that will never arrive. This confirms a differential exists
   without ever touching another user's traffic.
2. **Transfer-Encoding obfuscation, only if the plain probe is
   inconclusive.** Try minimal header variants (a non-standard `TE` value,
   a duplicate `Transfer-Encoding` header, injected whitespace before the
   value) — use the smallest variant that produces a differential, not an
   exhaustive sweep once one works.
3. **Differential-response confirmation.** Send two requests in rapid
   sequence and check whether the second receives a response that belongs
   to neither request as sent — a marker string in the smuggled prefix
   rules out ordinary timing noise.
4. **Controlled bypass demonstration, once desync is confirmed.** Smuggle
   a request to a restricted path and confirm the back-end processes it as
   if it originated from the trusted front-end — this is the first
   technique with real security impact, and should be attempted only after
   the differential itself is independently established.
5. **Cross-user capture, the most invasive technique, last.** Poison the
   back-end socket so a subsequent, genuinely different user's request is
   captured into a response you control. This affects real traffic from
   real users — treat it as a last-resort proof step, run only against a
   low-traffic window, and stop the moment capture is demonstrated once.
6. **H2.CL / H2.TE variants.** Repeat the equivalent probes over an
   HTTP/2 front-end connection where the target supports HTTP/2 — inject
   `content-length` or `transfer-encoding` as a regular header (never a
   pseudo-header) and observe the same differentials as the HTTP/1.1 case.

## Proof Ladder

- **L1 — timing differential observed.** A malformed CL/TE probe produces
  an unexplained delay, suggesting a parser disagreement, but the exact
  mechanism (which side reads which header) is not yet confirmed.
- **L2 — desync confirmed, no control bypassed.** A differential-response
  test with a marker string proves the back-end socket was actually
  poisoned, independent of timing noise, but nothing of value was reached
  yet.
- **L3 — a security control bypassed or cross-user data captured.** A
  smuggled prefix reached a restricted endpoint the front-end would have
  blocked, or a real (not self-generated) user's request content appeared
  in a response you control. This is the threshold for a reportable
  finding.
- **L4 — durable or systemic impact.** The bypass generalizes across many
  endpoints or the entire front-end's access-control layer, or the
  technique chains into cache poisoning affecting every user of a cached
  resource, not a single captured request.

Calibrate severity separately per [[severity-calibration]] — a confirmed
cross-user session/credential capture is typically critical; a bypass
limited to one non-sensitive restricted endpoint is usually high rather
than critical.

## Validation and False-Positive Discipline

Apply [[closure-discipline]] before recording anything. Class-specific
traps:

- Ordinary network or backend processing latency, unrelated to any parser
  disagreement, produces the same symptom as a CL.TE timing probe — always
  confirm with a differential-response test before treating a delay alone
  as desync.
- A server or proxy that closes the connection after every request has no
  socket to poison — confirm connection reuse is actually happening before
  investing further, regardless of how convincing a timing result looks.
- A WAF or proxy that normalizes conflicting `Content-Length`/
  `Transfer-Encoding` headers before forwarding removes the ambiguity
  entirely — a probe that produces no effect here is the control working,
  not an inconclusive test.
- Full end-to-end HTTP/2 with no downgrade to HTTP/1.1 anywhere in the
  chain has no H2.CL/H2.TE surface — confirm the downgrade actually
  happens before attempting these variants.

## Impact

Authentication and access-control bypass by smuggling a request past
front-end enforcement; cross-user session or credential capture; cache
poisoning that serves attacker-controlled content to every subsequent
visitor of a cached resource; and internal-service access bypassing
IP-based restrictions enforced only at the front-end.

## Summary

Smuggling is a parser-agreement failure, not an input-validation failure —
prove the differential first with a self-contained timing or
marker-response test, and only escalate to a real bypass or capture attempt
once the underlying desync is independently confirmed. The capture
technique touches real user traffic; reserve it for the minimum needed to
prove impact once, not as a routine step.
