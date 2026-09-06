---
name: session-replay-and-mitm
category: vulnerability
description: Network-layer session and protocol replay — captured-credential reuse, TCP sequence prediction, and on-path (ARP/DNS spoofing) positioning, with a per-class proof ladder
keywords: [replay attack, session replay, tcp hijacking, arp spoofing, dns spoofing, mitm, anti-replay, sequence prediction]
---

# Session and Protocol Replay (Network-Layer)

Distinct from the request-level replay covered inside [[jwt]] and other
web-application skills, this class covers replay and on-path attacks at
the network/transport layer — reusing a captured authentication sequence
verbatim, predicting a weak TCP sequence number to hijack an established
connection, or gaining an on-path position via ARP/DNS spoofing in the
first place. This applies to raw network services and infrastructure
targets, not just HTTP APIs.

## Attack Surface

- Any protocol whose authentication or session-establishment sequence can
  be captured off the wire and reused verbatim: HTTP cookies, OAuth/JWT
  bearer tokens, Kerberos tickets, NTLM challenge/response, and SAML
  assertions all share the same underlying weakness if the receiving side
  never checks freshness.
- TCP sessions on a segment where the attacker can observe or influence
  traffic — sequence-number predictability turns into connection hijacking
  without needing to see every packet.
- Local-segment address resolution (ARP) and DNS resolution, both of which
  are trusted-by-default in most deployments — spoofing either is the
  usual way to GET an on-path position in the first place, before any
  higher-layer replay or manipulation becomes possible.
- API request/response pairs captured via any proxy or packet capture
  during earlier recon — a full captured request replayed later against a
  still-valid session is often enough on its own, no manipulation
  required.

## Recon

- Determine what's actually available to capture: is the target segment
  switched (ARP spoofing needed to see other hosts' traffic) or shared, and
  is transport-layer encryption (TLS) actually terminated where you can
  observe it, or genuinely end-to-end?
- For any captured authentication exchange, identify what — if anything —
  makes it single-use: a nonce, a timestamp with server-side freshness
  enforcement, a sequence number bound to the specific TCP connection, or
  nothing at all.
- Sample a short run of TCP handshakes from the target and check whether
  initial sequence numbers show any exploitable pattern (a small or
  predictable increment) rather than assuming modern stacks are always
  safe — this varies meaningfully by embedded/legacy device stacks.
- Identify authentication-protocol specifics in play (Kerberos ticket
  lifetime and replay-cache configuration, NTLM's own challenge freshness,
  SAML assertion `NotOnOrAfter`/`InResponseTo` binding) before assuming any
  one class's replay defenses are absent.

## Techniques (start quiet, escalate only as needed)

1. **Direct capture-and-reuse.** Replay a captured authentication
   sequence or full API request verbatim, unmodified, against the live
   target and confirm whether it's accepted — the simplest, least
   destructive test and the one to try before any packet manipulation.
2. **On-path positioning (only where required and in-scope).** Where
   observing traffic between two hosts is actually necessary and
   authorized for the engagement, use ARP cache poisoning to establish
   the on-path position, or DNS response spoofing where DNS resolution
   itself is the trust boundary being tested — treat this as a
   prerequisite step, not the finding itself.
3. **TCP sequence prediction and hijacking.** From a sample of observed
   sequence numbers, test whether the increment pattern is predictable
   enough to inject a packet into an established connection without
   being on-path for the whole session — a genuinely predictable sequence
   is itself often the reportable weakness, independent of what's injected.
4. **Cross-context session/token replay.** Reuse a captured session
   artifact in a different context than it was issued for (a different
   source IP, device, or client) to test whether the server binds the
   session to anything beyond the bare token value — per [[jwt]] for the
   JWT-specific variant of this same test.
5. **Rate/volume replay for a distinct outcome.** Replay the same
   authenticated request repeatedly to test whether server-side
   idempotency or rate-limiting behaves correctly under replay — a
   duplicate side effect (a payment processed twice, an action repeated)
   is a distinct, often higher-impact finding from mere authentication
   replay.

## Proof Ladder

- **L1 — replay accepted structurally.** A captured sequence or request is
  confirmed accepted by the target on direct replay, but no distinct
  session, privileged action, or on-path position has yet resulted.
- **L2 — on-path position or hijack primitive confirmed.** ARP/DNS
  spoofing is shown successfully redirecting traffic, or a predicted TCP
  sequence number is confirmed accepted by the target — a real primitive,
  not yet a captured session or executed action.
- **L3 — session or authenticated action reproduced.** The replayed
  artifact produces a genuine authenticated session or executes a real
  action under the original party's identity, independently confirmed
  (not just an accepting status code). This is the threshold for a
  reportable finding.
- **L4 — durable compromise or systemic protocol weakness.** The replay
  or hijack is chained into sustained session control, a duplicated
  financial/state-changing side effect, or the underlying weakness
  (predictable sequence numbers, unauthenticated ARP/DNS) is shown
  affecting the whole segment or protocol implementation, not one
  isolated exchange.

Calibrate severity separately per [[severity-calibration]] — replay
producing a duplicated financial transaction or full session takeover is
categorically more severe than a replay that only demonstrates a missing
nonce with no further consequence proven.

## Validation and False-Positive Discipline

Apply [[closure-discipline]] before recording anything. Class-specific
traps to check before calling something confirmed:

- A replayed request that fails specifically because the ORIGINAL session
  or token had already naturally expired is not proof either way — retest
  with a fresh, still-valid capture before concluding replay protection is
  absent.
- TLS termination between the attacker's vantage point and the actual
  authentication exchange defeats capture entirely — confirm you actually
  captured plaintext (or a genuinely broken/downgraded TLS session), not
  an assumption that "the network is switched, so I can see it."
- A short-lived token or ticket that expires before your replay attempt
  can execute closes this specific instance — confirm the artifact was
  still valid at replay time, and separately assess whether the lifetime
  itself is long enough to matter in practice.
- Sequence-number predictability observed from a small sample can be
  coincidental — confirm the pattern holds across a larger, freshly
  captured sample before reporting it as a systemic weakness.

## Impact

Session and account takeover via captured-credential reuse, TCP
connection hijacking enabling data injection or manipulation on an
established session, on-path traffic interception and manipulation via
ARP/DNS spoofing, and duplicated state-changing or financial side effects
from unprotected request replay.

## Summary

Freshness, not secrecy, is what defeats replay: a nonce, a short-lived
token with real server-side expiry enforcement, and sequence numbers or
session bindings an attacker cannot predict or reuse across context. Test
direct capture-and-reuse first — it's the cheapest, most conclusive proof
— before escalating to on-path positioning or packet-level manipulation.
