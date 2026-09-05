---
name: request_smuggling
class: request_smuggling
summary: HTTP request smuggling/desync (CL.TE, TE.CL, TE.TE, H2 downgrade).
---
# HTTP Request Smuggling / Desync

Front-end and back-end disagree on where one request ends and the next begins —
lets you smuggle a second, attacker-controlled request into another user's
connection/queue, or bypass front-end security controls.

## Recon
- Identify a front-end/back-end chain (CDN/proxy + origin) — smuggling needs two
  HTTP parsers in the path (common with reverse proxies, CDNs, load balancers).
- Send a request with BOTH `Content-Length` and `Transfer-Encoding: chunked`.

## Techniques
- **CL.TE**: front-end uses Content-Length, back-end uses Transfer-Encoding —
  smuggle a request body chunk the back-end treats as the start of the next request.
- **TE.CL**: reverse — front-end uses TE, back-end uses CL.
- **TE.TE**: both use TE, but the header is obfuscated (`Transfer-Encoding: xchunked`,
  space/tab variants, duplicate headers) so one parser ignores it.
- **HTTP/2 downgrade smuggling**: H2 request smuggled into an H1 back-end via
  CRLF injection in a pseudo-header or a request-line desync.
- Confirm with a timing-based probe first (send an ambiguous request, observe the
  next request on the same connection times out/hangs = smuggled), then escalate
  to response-queue poisoning to steal another user's response or bypass auth
  front-end checks.

## Proof ladder
- L1: front-end/back-end disagreement suspected (differing CL/TE handling).
- L2: timing-based confirmation (a probe causes an observable desync/hang).
- L3: demonstrated smuggled request reaches the back-end as a separate request
  (response-queue poisoning captures a planted marker).
- L4: bypassed a front-end security control, or captured another user's response
  (session/credential theft).

## Validation
- This class needs care: a false confirmation from timing alone is common —
  require BOTH a timing signal AND a captured/observed smuggled effect.
- Never smuggle destructive payloads into another real user's session — this
  class's proof must stay non-destructive and low-volume.
