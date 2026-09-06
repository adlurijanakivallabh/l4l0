---
name: ssrf
category: vulnerability
description: Server-side request forgery — cloud metadata, internal service discovery, redirect/DNS-rebinding bypass, and a per-class proof ladder
keywords: [ssrf, server side request forgery, metadata, imds, internal network, blind ssrf]
---

# Server-Side Request Forgery

Any feature that fetches remote content on the server's behalf can become a
tunnel into networks the attacker cannot otherwise reach — cloud metadata
services, internal admin panels, and service meshes. The server's network
position is the whole point of exploiting it.

## Attack Surface

- Direct URL-shaped parameters: `url=`/`link=`/`fetch=`/`webhook=`/
  `avatar=`/`image=` and anything that clearly names a remote resource.
- Indirect sources that still cause a server-side fetch: link-preview
  generators, PDF/image renderers, import/export jobs, webhook signature
  verifiers that fetch the target first, and calendar/feed importers.
- Anything that resolves a URL found inside a document it parses (an SSRF
  via a document format, not a direct parameter) — office documents,
  SVG/XML with external entity or stylesheet references, and PDF
  generators are common carriers.
- Non-HTTP schemes some fetchers still honor if not explicitly restricted:
  `file://`, `gopher://`, `dict://`, and language-specific wrappers — these
  turn a "fetch a URL" feature into a raw-protocol client.

## Recon

- Identify what the fetcher actually validates: a hostname allowlist
  checked before resolution is a fundamentally different (weaker)
  guarantee than one enforced on the resolved IP at connection time — the
  same distinction this project's own outbound firer closes by resolving
  once and dialing that exact pinned address (see how `pin_for_connect`
  is used in the execution layer) — an SSRF finding is exactly what that
  design exists to prevent *for L4L0's own traffic*; here you are checking
  whether the *target* has the equivalent protection.
- Check whether the fetcher follows redirects, and if so, whether it
  re-validates the destination on every hop or only checks the
  originally-supplied URL.
- Note the cloud/orchestration environment if visible from other
  reconnaissance (response headers, error messages, technology
  fingerprints) — this narrows which metadata endpoint shape to try first
  rather than guessing across every cloud provider blindly.

## Techniques (start quiet, escalate only as needed)

1. **Out-of-band confirmation first.** Point the fetcher at your own
   OAST callback host/domain. A single correlated DNS or HTTP hit is
   unambiguous, low-noise proof that a server-initiated request occurred —
   establish this before anything else, since it also tells you whether
   the fetch happens at all (versus being entirely client-side, which would
   make this whole class inapplicable).
2. **Semi-blind differential baseline, when OOB is unavailable or blocked.**
   Compare the response (status, error class, and timing) across three
   requests: a known-dead internal address, a known-fast external host,
   and the actual internal target — a real difference between the three
   (not just between two) is a strong signal the server genuinely
   attempted the internal connection, even with no direct response
   content to read.
3. **Internal addressing.** Once egress is confirmed, pivot to loopback and
   private-range addresses (including less obvious encodings — decimal,
   hex, or octal IP forms, and IPv6/IPv4-mapped variants a naive filter
   may not normalize) to test whether the fetcher's allowlist, if any,
   actually blocks internal destinations or only blocks the literal
   `localhost` string.
4. **Cloud metadata, if the environment suggests a cloud deployment.**
   Each major provider's instance-metadata service lives at a
   well-known link-local address or hostname and returns credentials or
   instance identity data with no authentication beyond network reachability
   (some require a specific header or a short-lived token fetched in a
   prior request — check whether your fetcher can be made to set headers,
   since that gates whether the newer, harder-to-reach metadata API
   versions are in scope at all).
5. **Redirect abuse.** If the fetcher validates only the initially-supplied
   URL, host a redirect that passes validation and points to an internal
   target on the next hop — and test whether a protocol switch survives the
   redirect too, not just a host change.
6. **Protocol abuse, only once HTTP-level access is exhausted.** Where a
   non-HTTP scheme is honored, speaking a raw text protocol (to a cache, a
   message broker, or an internal admin API) can escalate a read primitive
   into a write or execution primitive — this is a deliberate escalation
   step, not a default first move, since it has a materially larger blast
   radius on the internal service than a read-only metadata fetch does.

## Proof Ladder

- **L1 — egress suspected.** A behavioral difference (timing, error class,
  response shape) suggests the server made an outbound request, but you
  have no direct confirmation.
- **L2 — egress confirmed, non-sensitive target.** An OAST callback
  correlated to your request proves the server made an outbound request
  you controlled the destination of, but you have not yet reached anything
  sensitive.
- **L3 — internal or metadata resource reached.** You retrieved content
  from an internal-only service, an admin interface, or a metadata endpoint
  that a direct external client could not reach. This is the threshold for
  a reportable finding.
- **L4 — credential or control-plane compromise.** You extracted live
  cloud credentials, control-plane tokens, or used the SSRF as a stepping
  stone to a write/execution primitive against an internal service.

Calibrate severity separately per [[severity-calibration]] — reaching a
harmless internal health-check endpoint is a different severity than
extracting live cloud credentials, even though both can clear L3.

## Validation and False-Positive Discipline

Apply [[closure-discipline]] before recording anything. Class-specific
traps:

- An OAST callback whose source address matches your own testing machine,
  not the target server, means a client-side fetch made the request (a
  browser preview, a client-side library) — not the backend. Confirm the
  callback's source IP before trusting it as server-side evidence.
- A strict allowlist that pins DNS resolution and refuses to follow
  redirects is a real control, not a false claim of one — confirm by
  testing an actual bypass attempt (an encoding variant, a redirect) fails
  consistently, not by reading the allowlist's intent.
- Uniform errors across every target and protocol you tried usually mean
  egress is genuinely blocked, not that you have not found the right
  payload yet — but confirm this against a known-working comparison
  request before closing the candidate as ruled out.
- A fetcher that only ever hits a mock/simulator with canned responses is
  not exhibiting real network reach — verify you are observing genuine
  egress, not a sandboxed preview feature.

## Impact

Cloud credential disclosure leading to control-plane or storage access,
reach into internal admin panels and data stores never intended to be
externally exposed, lateral movement into orchestration/service-mesh
control surfaces, and — where the reached internal service itself accepts
unauthenticated write or execution primitives — remote code execution one
hop removed from the original request.

## Summary

SSRF turns the server's own network position into the attacker's. Confirm
egress out-of-band before anything else, prefer the quietest internal target
that still proves real impact, and never assume an allowlist works — test
it.
