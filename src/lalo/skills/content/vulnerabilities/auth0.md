---
name: auth0
category: vulnerability
description: Auth0-specific attack surface — Rule/Action misconfiguration, tenant/connection confusion, and a per-class proof ladder
keywords: [auth0, identity provider, rules, actions, tenant]
---

# Auth0

Auth0-specific gaps center on custom Rules/Actions (arbitrary JavaScript
a tenant admin writes to run during login) and connection/tenant
configuration — an escalation surface [[oauth-oidc]]'s generic protocol
methodology doesn't cover.

## Attack Surface

- Custom Rules/Actions running arbitrary tenant-authored JavaScript
  during the login pipeline — a bug here (an insecure API call, a
  hardcoded credential, an injection into a downstream call) is a
  tenant-specific vulnerability layered on top of Auth0's own platform
  security.
- Multiple connections (database, social, enterprise) on one tenant —
  an account-linking Rule that links identities by email without
  verifying the email is actually verified on the incoming connection
  is the same mutable-claim account-takeover shape [[jwt]] already
  documents for generic OIDC, specific to how Auth0 exposes it.
- Auth0's Management API credentials (a machine-to-machine application)
  with overly broad scopes, if leaked, allow full tenant administration.

## Recon

- Where source or configuration access exists, read every Rule/Action's
  actual code for a hardcoded secret, an unvalidated external call, or
  an account-linking decision based on an unverified claim.
- Enumerate the tenant's configured connections and check whether any
  social/enterprise connection's `email_verified` claim is actually
  checked before an account-linking Rule uses email as the linking key.

## Techniques

1. **Unverified-email account linking**, the Auth0-specific instance of
   the mutable-claim takeover technique in [[jwt]] — register via a
   connection that allows an unverified or attacker-chosen email and
   confirm whether a linking Rule grants access to an existing account
   sharing that email.
2. **Rule/Action code-injection or logic-bug exploitation** — direct
   source review of any accessible custom Rule/Action code, applying
   [[source-aware-review]]'s methodology.

## Proof Ladder

Follow [[oauth-oidc]]'s ladder for the protocol-level portion of any
finding; a confirmed Rule/Action code vulnerability follows whatever
class its actual bug shape belongs to (e.g. [[command-injection]] if the
Rule shells out unsafely).

## Validation and False-Positive Discipline

Apply [[closure-discipline]]. An account-linking Rule that explicitly
checks `email_verified === true` before linking closes the unverified-
email path — confirm this check exists in the actual Rule code, not from
the connection's general description.

## Impact

Account takeover via unverified-email account linking; arbitrary
compromise via a vulnerable custom Rule/Action; full tenant compromise
via leaked Management API credentials.

## Summary

Read the tenant's actual Rules/Actions code and connection configuration
directly — this is where Auth0-specific risk concentrates, on top of
whatever the underlying OAuth/OIDC protocol-level checks in
[[oauth-oidc]] already cover.
