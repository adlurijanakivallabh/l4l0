---
name: ssrf
class: ssrf
summary: Find, exploit, and prove SSRF (blind via OAST, internal reach, metadata).
---
# Server-Side Request Forgery

The server makes an attacker-influenced request. Prove it reaches an
attacker-controlled or internal destination.

## Attack surface
- Any feature that fetches a URL: webhooks, "import from URL", PDF/HTML render,
  image proxy, link preview/unfurl, SSO metadata, file-from-URL, SSRF-in-XML(XXE).
- Indirect: a hostname/host header/`Forwarded` reflected into a downstream fetch.

## Recon
- Find URL-ish params (url, uri, dest, callback, image, feed, webhook, next).
- Note allow-list/scheme filters to bypass.

## Techniques (escalate)
1. **Blind confirm (do this first)**: point the param at your OAST HTTP URL and
   DNS name; poll the OAST server for the callback (proves the server fetched it).
2. **Internal reach**: `http://127.0.0.1:<port>/`, `http://localhost/`, internal
   hostnames, other in-scope hosts; compare responses/timing to infer reachability.
3. **Cloud metadata** (if in scope): `http://169.254.169.254/latest/meta-data/`,
   `metadata.google.internal` (header `Metadata-Flavor: Google`) — reading IAM
   creds/instance data demonstrates critical impact.
4. **Filter bypass**: alternate IP encodings (decimal/octal/hex, `[::]`,
   `0.0.0.0`), DNS-rebinding, `@`/`#` tricks, redirect-to-internal, URL-concat.
- gopher/dict/file schemes where the client allows (internal protocol smuggling).

## Proof ladder
- L1: param accepts a URL. L2: differential timing/response suggests fetch.
- L3: OOB callback fired (server truly fetched attacker URL) OR distinct
  internal-service response returned.
- L4: read cloud metadata/IAM creds, or reached a sensitive internal service.

## Validation / false positives
- A client-side fetch (browser) is not SSRF — the *server* must make the request
  (OOB callback source IP = server, not you).
- Distinguish "connection refused/timeout to internal" (still evidence of reach
  attempt) from an actual returned internal response.
- L4G0 note: L4L0's own firer denies metadata by default; SSRF here is the
  *target* proxying to metadata, evidenced via OAST/returned content.
