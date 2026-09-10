---
name: oauth-oidc
category: vulnerability
description: OAuth 2.0/OIDC protocol-level security — redirect_uri validation gaps, PKCE/state omission, token-endpoint confusion, and a per-class proof ladder
keywords: [oauth, oauth2, oidc, openid connect, pkce, redirect_uri, authorization code, implicit flow]
---

# OAuth 2.0 / OIDC

OAuth/OIDC's security rests almost entirely on a handful of parameters
being validated exactly, not approximately — `redirect_uri`, `state`,
and PKCE's `code_verifier`/`code_challenge` pair. This skill covers the
protocol-level gaps in how a relying party or authorization server
validates them, distinct from [[jwt]] (which covers the TOKEN itself
once issued) and the "nOAuth" mutable-claim account-takeover technique
already covered in [[jwt]]'s own OIDC section.

## Attack Surface

- The authorization endpoint's `redirect_uri` validation — exact match
  vs. prefix match vs. no validation at all.
- Presence and validation of `state` (CSRF protection for the
  authorization flow) and PKCE (`code_challenge`/`code_verifier`,
  protection against authorization-code interception).
- The token endpoint's handling of `grant_type`/`client_id`/
  `client_secret` — confusion between a public client (SPA/mobile,
  should never hold a secret) and a confidential client's flow.
- Any custom-built authorization server (vs. a well-known managed IdP)
  is higher-risk by default — the well-known providers have had these
  exact gaps hardened over years of public research.

## Recon

- Identify the flow in use (authorization code, authorization code +
  PKCE, implicit — the latter deprecated and itself a finding if still
  in use for a new integration) and whether the client is public or
  confidential.
- Test the actual `redirect_uri` validation directly rather than reading
  documentation about it: register/observe the expected value, then try
  a subdomain variation, a path-suffix addition, a different scheme, and
  an open-redirect-shaped value on the SAME registered host (a redirect
  endpoint on the legitimate host that itself forwards elsewhere).
- Check whether `state` is present, unique per request, and actually
  verified on callback (vs. merely echoed back and ignored) — a present-
  but-unchecked `state` parameter is functionally the same gap as a
  missing one.

## Techniques

1. **`redirect_uri` validation-strength probe.** Attempt each variation
   from Recon in turn; a successful authorization-code delivery to an
   attacker-controlled or attacker-reachable URI (an open redirect on
   the legitimate host counts, since it forwards the code onward) is the
   core exploitation primitive this class is built around.
2. **CSRF-via-missing/unchecked-`state` probe.** Initiate an
   authorization flow as the attacker, capture the resulting
   authorization code/callback URL, and have the victim's browser follow
   it (a standard CSRF delivery) — if the relying party accepts it and
   links the attacker's OAuth identity to the victim's existing session,
   this is a full account-linking/takeover primitive, not merely a CSRF
   nuisance.
3. **PKCE downgrade/omission check.** For a public client, confirm PKCE
   is actually REQUIRED by the authorization server (not merely
   supported) — attempt the authorization code exchange without a
   `code_verifier` and confirm it is rejected; if accepted, an
   intercepted authorization code (via the `redirect_uri` primitive
   above, a referrer leak, or a malicious app on the same device) can be
   exchanged by the attacker directly.
4. **Client confusion / token-endpoint parameter-pollution check.**
   Attempt to exchange a code intended for a public client using a
   confidential client's endpoint behavior (or vice versa), and check
   whether supplying an unexpected `client_id`/multiple `client_id`
   values in the token request produces confused-deputy behavior.

## Proof Ladder

- **L1** — a validation gap identified (loose `redirect_uri` matching,
  missing `state`, PKCE not enforced) but not yet demonstrated end-to-end.
- **L2** — a single hop of the gap demonstrated in isolation (an
  authorization code successfully delivered to a variant redirect URI;
  an authorization request accepted with no `state`) without yet
  completing a full account-impact chain.
- **L3** — the gap chained to a concrete, observed account-level effect:
  an authorization code intercepted and exchanged by the attacker, or a
  victim's account linked to an attacker-controlled OAuth identity via
  CSRF — reportable.
- **L4** — full account takeover: the attacker gains an authenticated
  session as the victim through the chained gap, reproducible on a
  second run.

## Validation and False-Positive Discipline

Apply [[closure-discipline]]. `redirect_uri` confirmed validated by
EXACT string match against a pre-registered allowlist (not merely
"starts with" or "same host") closes the redirect-uri primitive
entirely — confirm the actual match algorithm by testing variations
directly, never by reading a client registration UI's stated value
alone. `state` confirmed cryptographically random, unique per request,
and actually verified against the session on callback is the control
working correctly.

## Impact

Full account takeover via a chained redirect_uri/state/PKCE gap;
authorization-code theft and replay; cross-account linking via CSRF on
the authorization callback.

## Summary

Test `redirect_uri`/`state`/PKCE validation directly with real variation
attempts — documentation or a registration UI's stated policy is not
evidence of the actual server-side validation strength. A chain across
more than one of these three usually produces the highest-severity,
clearest-to-reproduce finding in this class.
