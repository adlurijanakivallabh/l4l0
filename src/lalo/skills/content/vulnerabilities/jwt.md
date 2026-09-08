---
name: jwt
category: vulnerability
description: JWT/OIDC token forgery, weak-secret cracking, algorithm confusion, header manipulation, and claim validation gaps with a per-class proof ladder
keywords: [jwt, json web token, oidc, oauth, algorithm confusion, alg none, token forgery, weak secret, hmac crack]
---

# JWT and OIDC

A JWT is only as trustworthy as the verification path that checks it —
signature, issuer, audience, key, and context all have to bind correctly on
*every* acceptance path. This project's own `jwt` tool's `decode`/
`crack_secret`/`alg_none`/`with_claim` ops give you the decode/crack/tamper
primitives (the last three are pure - they never decide anything is
vulnerable, only produce or check a candidate); this skill is the
methodology for what to try and how to prove it matters.

## Attack Surface

- Any service accepting a JWT for authentication or authorization: web/API
  gateways, first-party services, and microservices that verify tokens
  independently of each other.
- The distinction between access tokens, ID tokens, and refresh tokens
  matters — a service that checks only the signature and not the token's
  intended type/audience can be tricked into accepting the wrong one.
- Key distribution and rotation endpoints (a JWKS-style key-set URL, a
  well-known configuration document) are part of the attack surface, not
  just the token verification code itself.

## Recon

- Capture tokens for at least two roles/identities and decode both header
  and payload (`jwt_decode`) to see the real algorithm, key identifier, and
  claim set actually in use — do not assume a spec-typical shape without
  checking.
- Identify every service that independently verifies this token type —
  audience/issuer enforcement is frequently inconsistent across services
  even when they trust the same identity provider.
- Note whether the header carries a key-selection hint (a key ID, an
  embedded key, or a URL pointing to a key set) — each is its own
  potential manipulation surface, distinct from the signature algorithm
  itself.

## Techniques (start quiet, escalate only as needed)

1. **Weak or guessable signing secret (check this first for any HS256/384/512
   token).** A symmetric secret that's a default, a common word, or drawn
   from the target's own visible strings (its name, its framework, a value
   seen in source/config/error output) is, in practice, the single most
   common way a JWT-using target actually gets fully compromised — more
   common than algorithm confusion. Use `jwt`'s own `crack_secret` op with a
   SMALL, curated candidate list: a dozen or so likely defaults (the
   target's own name/framework/environment terms, plus generic ones like
   `secret`, `changeme`, `dev`) — build the list from what you already know
   about this specific target, don't reach for an entire wordlist file.
   `crack_secret` enforces a hard cap and refuses an oversized list for
   exactly this reason: loading a whole wordlist file into memory via
   `run_command` instead (rather than a short, targeted list through this
   op) is a real way to exhaust the container's own memory budget, not a
   hypothetical risk — a live run did exactly this once. If a short,
   targeted list finds nothing, that is real signal the secret is NOT
   trivially weak; move on to other techniques rather than escalating to a
   massive wordlist attempt of marginal value.
2. **Algorithm-confusion and none-algorithm probes.** If the algorithm is
   not strictly pinned server-side, test whether an asymmetric-to-symmetric
   algorithm swap (using a public key as a symmetric secret) or an
   unsigned (`alg: none`) token is accepted — `jwt_alg_none` produces the
   candidate token; whether it is accepted is what you are testing.
3. **Claim manipulation on an otherwise-valid signature path.** Where you
   cannot forge a valid signature, test whether a claim change survives
   anyway — a service that decodes but does not fully re-verify, or one
   using a still-valid stale token structure — via `jwt_with_claim`.
4. **Header-driven key-selection abuse.** If the header carries a key
   identifier or an embedded/remote key reference, test whether the
   service actually restricts which keys or sources it will trust, or
   whether it can be steered to a key you control.
5. **Cross-context and cross-service replay.** Try the same token against
   every service that accepts tokens from the same issuer — a token
   correctly scoped for one audience being silently accepted by another is
   a distinct, often-missed finding from any single-service test.
6. **Type confusion between token kinds.** If both access and ID tokens
   exist, test whether a service that expects one will accept the other —
   this is a common gap when a service verifies signature and expiry but
   not the token's declared type.
7. **Refresh-token reuse.** If refresh tokens are in scope, test whether a
   previously-used refresh token is still accepted (no rotation
   enforcement) — this is a durable-access finding distinct from anything
   about the access token itself.
8. **OIDC identity binding to a mutable claim ("nOAuth"-style account
   takeover).** Applies wherever the target lets an operator or user
   register or link an arbitrary external OIDC tenant as a trusted
   identity provider (a "bring your own IdP" / social-login SSO model).
   Check which claim the relying party actually uses to look up or
   provision the local account on login: `email` and `preferred_username`
   are values the ATTACKER fully controls inside a tenant they administer,
   while `sub` is scoped to that specific issuer and tenant and is not. To
   test: register a self-service tenant on the same IdP family the target
   trusts, issue yourself an ID token whose `sub` is attacker-chosen but
   whose `email`/`preferred_username` is set to a known victim's real
   address, and present that token at the target's SSO callback. The
   finding is confirmed when this authenticates you AS the victim's
   existing account — an established session, the victim's own private
   data visible — purely because the mutable claim matched, not because
   you merely created a new account under that address. Before calling it
   confirmed, rule out a relying party that keys the account on the
   immutable `issuer + sub` pair instead, or that requires a separate
   email-ownership verification step (a confirmation link, an OTP) before
   granting the session — either one defeats this specific variant even
   though the claim itself is still technically attacker-controlled.

## Proof Ladder

- **L1 — verification gap suspected.** Decoding reveals a header or claim
  shape (an unpinned algorithm, an unchecked audience) that suggests a
  gap, but no tampered token has actually been accepted yet.
- **L2 — tampered token accepted, low-value claim.** A forged or
  claim-modified token is accepted by at least one verification path, but
  the modified claim does not yet grant meaningfully different access.
- **L3 — tampered token grants real unauthorized access.** A forged or
  manipulated token is accepted and grants access to a resource or action
  the original token's real claims would not have permitted. This is the
  threshold for a reportable finding.
- **L4 — durable or systemic compromise.** The forgery generalizes across
  every service that trusts the issuer (not just one), or you demonstrated
  minting tokens for an arbitrary identity using a key you control.

Calibrate severity separately per [[severity-calibration]] — full
authentication bypass or trivially forgeable authentication (an unsigned
token accepted, a signature never actually checked) is typically critical;
a narrower claim-manipulation gap on one internal service is usually high
rather than critical.

## Validation and False-Positive Discipline

Apply [[closure-discipline]] before recording anything. Class-specific
traps:

- A service rejecting your tampered token because of strict audience or
  issuer enforcement is a real control working correctly, not a finding —
  confirm exactly what got rejected and why before moving to a different
  service or technique.
- Key pinning to a specific, verified key set is a real control — confirm
  by actually attempting a key-source manipulation rather than assuming it
  is absent.
- A short-lived token with real rotation and revocation on logout being
  "still valid" for a brief window is expected behavior, not a finding, un-
  less the window itself is unreasonably long for the stated design.
- An ID token being rejected by an API that correctly requires an access
  token is the control working, not a gap — confirm the actual acceptance,
  not just that a request was sent.

## Impact

Account takeover and durable session persistence, privilege escalation via
accepted claim manipulation, cross-service or cross-tenant access when
audience/issuer binding is missing, and the ability to mint tokens for
arbitrary identities when a key-selection gap is fully exploited.

## Summary

Every acceptance path has to bind signature, algorithm, issuer, audience,
and key together — not just check that *a* signature validates against
*some* key. Test claim manipulation and cross-service replay as
seriously as algorithm confusion; the more common real-world gap is
inconsistent verification across services, not a single dramatic
signature bypass.
