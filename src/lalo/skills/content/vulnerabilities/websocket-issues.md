---
name: websocket-issues
category: vulnerability
description: WebSocket-specific issues — missing origin validation on the handshake, message-level injection, and authorization that doesn't survive the connection's own lifetime
keywords: [websocket, ws, wss, origin, cross-site websocket hijacking, cswh, message injection, per-message authorization, handshake, socket.io]
---

# WebSocket Issues

A WebSocket connection is authenticated (if at all) once, at handshake
time, and then stays open for an arbitrary duration carrying an arbitrary
number of subsequent messages. Both properties create gaps that don't
exist on a stateless HTTP request: the handshake itself can be forged
cross-site the way a cookie-authenticated GET can, and a check that ran
once at connect time is not the same as a check that runs on every message
sent afterward. The `ws_fire` tool connects, sends one message, and
returns whatever arrives, which is the primitive every technique below
builds on.

## Attack Surface

- The handshake itself — an HTTP `Upgrade: websocket` request, which
  carries the browser's ambient cookies exactly like any other
  same-origin request, but which the server may authenticate purely on
  those cookies with no equivalent of a CSRF token.
- Every distinct message type the application-level protocol defines over
  the socket (a chat message, a subscription request, an RPC call framed
  as JSON) — each is a separate potential injection or authorization
  point, not one undifferentiated "the socket is authenticated" surface.
- The connection's own lifetime: how long it stays open, what state
  (identity, permissions, tenant) it was bound to at handshake time, and
  whether that binding is ever re-verified.
- Any message that is rendered, executed, or stored by another connected
  client (a chat/broadcast relay), which turns message-level injection
  into a stored or reflected client-side issue on a different victim's
  connection.

## Recon

- Identify the handshake's authentication mechanism first: a cookie sent
  automatically by the browser, a token in the URL query string, or a
  token sent as the first application-level message after connect — each
  has a different cross-site forgery risk profile.
- Capture the handshake request in full and note whether an `Origin`
  header is present, and whether the server's response differs at all
  based on its value — the only way to know if `Origin` is actually
  checked is to vary it and compare, not to assume from the framework's
  defaults.
- Enumerate the application-level message protocol: connect, send one of
  each observed message type via `ws_fire`, and record which ones
  produce a response, an error, or a broadcast to note as attack surface.
- Note whether the same logical action (e.g. "send a chat message") is
  also reachable over a parallel HTTP/REST endpoint — a check present on
  one transport and absent on the other is the transport-parity gap
  described for GraphQL in [[graphql]], and the same principle applies
  here.

## Techniques (start quiet, escalate only as needed)

1. **Origin validation probing (cross-site WebSocket hijacking).** Perform
   the handshake with a forged, out-of-origin `Origin` header (or omit it
   entirely, since some servers only check its presence, not its value)
   and confirm whether the connection is still accepted and still
   authenticated as the ambient-cookie principal. A server that accepts
   any `Origin` — or accepts a missing one — on a cookie-authenticated
   handshake is vulnerable to cross-site WebSocket hijacking: a page on
   any other origin can open the socket as the victim and read whatever
   it streams back, with no CORS-equivalent protection, since the
   same-origin policy's CORS check has no WebSocket analogue.
2. **Message-level injection.** Treat every field of every message type
   the same way you would treat an HTTP body field the framework doesn't
   already validate — a WebSocket message is application data the server
   wrote its own parsing/handling for, and it is common for that handling
   to trust the message body more than an equivalent REST endpoint would,
   precisely because "it came over the authenticated socket." Test for
   the same injection classes ([[sql-injection]], [[command-injection]],
   [[nosql-injection]]) using the message body as the injection point,
   fired via `ws_fire`.
3. **Missing per-message authorization.** Establish a connection as a
   low-privilege identity, then send a message requesting an action or
   object scoped to a different principal or a higher-privilege operation
   — the same paired owned-versus-foreign comparison [[access-control]]
   and [[graphql]] both use, applied per message rather than per HTTP
   request. A connection authenticated once at handshake time is a common
   place for a developer to assume "this socket is already trusted" and
   skip the per-action check a REST equivalent would have.
4. **Broadcast/relay poisoning.** Where a message from one client is
   relayed to others (chat, a live dashboard, a collaborative document),
   send a message containing markup or a payload that a receiving client
   might render unsafely — this is [[xss]]'s own proof standard applied
   to a WebSocket-delivered payload landing in another user's browser,
   not a new technique, and needs the same DOM-sink confirmation before
   it counts as proven.
5. **Reconnection and session-fixation probing.** Where the client
   reconnects automatically (a dropped connection, a token refresh),
   confirm the reconnected socket re-validates the current identity/
   permissions rather than reusing whatever was true when the original
   connection first authenticated — a permission revoked mid-session
   should not survive a silent reconnect if it wouldn't survive a fresh
   HTTP request.

## Proof Ladder

- **L1 — surface mapped.** The handshake mechanism and the application
  message protocol are enumerated, but no origin, injection, or
  authorization test has been run yet.
- **L2 — anomaly observed.** A forged-origin handshake is accepted, or a
  message produces an unexpected response, but no unauthorized data or
  action has been confirmed yet.
- **L3 — confirmed cross-origin hijack, injection, or authorization
  bypass.** Either: a forged-origin page is shown to establish an
  authenticated socket and receive real victim-scoped data; a message-body
  injection is confirmed via the same proof standard its underlying class
  requires (a real SQL error/data leak, a real executed command); or a
  per-message authorization bypass is confirmed to return or affect
  another principal's real data. This is the threshold for a reportable
  finding.
- **L4 — systemic or broadcast-scale exploitation.** The origin bypass
  works against the production origin with no other precondition, the
  injection reaches a shared/persistent sink affecting other users, or the
  authorization bypass generalizes across many message types sharing the
  same missing-check pattern.

Calibrate severity separately per [[severity-calibration]] — a confirmed
cross-site WebSocket hijack against an authenticated session is typically
high to critical depending on what the socket streams; a single missing
per-message check on a low-sensitivity action is usually medium.

## Validation and False-Positive Discipline

Apply [[closure-discipline]] before recording anything. Class-specific
traps:

- A missing `Origin` header check is not itself proof of hijackability —
  confirm the handshake is ALSO authenticated by ambient browser state
  (a cookie), since a handshake authenticated by an explicit token the
  attacker page cannot read carries no such risk regardless of `Origin`
  handling.
- A socket accepting a forged `Origin` in a test client is not the same as
  a browser actually being willing to send that connection cross-site —
  confirm the finding with an actual cross-origin page context (or state
  plainly that you tested the server-side check only, if a real browser
  cross-origin repro wasn't performed) rather than implying a full browser
  PoC that wasn't run.
- A message rejected with a generic error is not evidence either way for
  injection — confirm via the same class-specific proof (a timing
  differential, a real data leak, a boolean-based differential) the
  underlying vulnerability class already requires, never a bare error
  string.
- The absence of a visible re-authentication prompt on reconnect does not
  by itself mean permissions were not re-checked server-side — confirm
  against the actual server-enforced permission, not the client's own UI
  state.

## Impact

Cross-site WebSocket hijacking exposing another authenticated user's live
data stream to an attacker-controlled page; injection vulnerabilities
reached via a message body the server trusts more than an equivalent HTTP
field; and authorization bypass from a per-message check the developer
assumed the handshake already covered.

## Summary

Two properties make WebSocket issues distinct from their HTTP equivalents:
the handshake can be forged cross-site with no CORS-equivalent defense,
and a check enforced once at connect time is not the same as a check
enforced on every subsequent message. Use `ws_fire` to probe both
directly, and hold every downstream finding (injection, authorization,
stored payload) to the exact same proof standard its own vulnerability
class already requires.
