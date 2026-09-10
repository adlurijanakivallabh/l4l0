---
name: infrastructure-lifecycle-trust
category: methodology
description: Infrastructure-lifecycle trust gaps — dangling DNS records, decommissioned-but-still-trusted resources, and stale CI/CD deployment artifacts
keywords: [dangling dns, subdomain takeover lifecycle, decommissioned infrastructure, stale deployment, orphaned resource]
---

# Infrastructure Lifecycle Trust

Infrastructure that was once legitimately provisioned and later
decommissioned — without cleaning up every reference to it — is a
recurring, high-value gap distinct from [[subdomain-takeover]]'s own
narrower CNAME-to-deprovisioned-service technique: this is about the
broader lifecycle (a DNS record, a firewall allowlist entry, a CI/CD
deployment target, a trust relationship) outliving the resource it once
pointed to.

## Attack Surface

- A DNS record (not only a CNAME — an A record, an MX record, an NS
  delegation) pointing to an IP/service that has since been released
  back to a cloud provider's shared pool, reachable by re-claiming that
  same resource.
- A firewall/security-group rule or an allowlist entry still trusting an
  IP range or identity that was reassigned after the original resource
  was decommissioned.
- A CI/CD pipeline still configured to deploy to, or pull secrets from,
  an environment/target that no longer serves its original purpose but
  is still reachable and still holds valid credentials.
- An old, still-resolving staging/demo subdomain running a stale,
  unpatched version of the application, discovered via
  [[asset-discovery]], that shares authentication/session infrastructure
  with production.

## Recon

- For every discovered ([[asset-discovery]]) host/record, check whether
  it appears to serve its ORIGINAL purpose or something inconsistent
  with it (a "staging" or "demo"-named host serving a default cloud-
  provider landing page, or nothing at all) — this mismatch is the core
  signal for this whole class.
- Where CI/CD configuration is accessible (a `.github/workflows`,
  `.gitlab-ci.yml`, or equivalent file, or a build history the target
  exposes), check deployment targets and referenced secrets/environments
  against what actually still exists.

## Techniques

1. **Dangling-record reclamation check**, generalizing
   [[subdomain-takeover]]'s technique beyond CNAME-to-SaaS: for a record
   resolving to a cloud-provider-owned IP/resource, attempt to determine
   (via the provider's own documented resource-claiming mechanism, never
   by actually claiming a resource you do not control unless the
   engagement scope explicitly authorizes it) whether that specific
   resource is currently unclaimed and re-claimable.
2. **Stale-staging-environment probe.** Test a discovered
   staging/demo/legacy host for a known vulnerability already patched in
   production, and separately check whether it shares session cookies,
   an auth token signing key, or a database with production — if so, a
   compromise there escalates directly to production impact.
3. **CI/CD stale-target check.** Where visible, confirm whether a
   pipeline's configured deployment target or referenced secret is for a
   resource that still exists and is still under the operator's control.

## Proof Ladder

- **L1** — a lifecycle mismatch identified (a record/config referencing
  something that looks decommissioned) but not yet confirmed exploitable.
- **L2** — the referenced resource confirmed to no longer be under the
  expected owner's control (via a documented, non-destructive check),
  but no actual reclamation/exploitation attempted.
- **L3** — the gap demonstrated with a benign proof (a claimed resource
  serving a benign marker page reachable via the dangling record; a
  stale staging environment's shared-credential exposure confirmed)
  within the authorized engagement scope — reportable.
- **L4** — the gap chained to production impact (a shared signing key or
  session mechanism between a compromised stale environment and
  production, confirmed).

## Validation and False-Positive Discipline

Apply [[closure-discipline]]. Never actually claim/register a
third-party resource (a cloud IP, a SaaS subdomain slug) unless the
engagement's own scope explicitly authorizes that specific action — most
engagements do not, and the correct default is to demonstrate
reclaimability via documentation/provider-tooling evidence rather than
performing the claim. A record confirmed to still point to a resource
genuinely under the operator's own control (even if the resource's
PURPOSE looks outdated) is not a dangling-record finding.

## Impact

Full subdomain/service takeover via a reclaimable dangling record;
production compromise via a stale staging environment sharing
credentials or signing keys with production; unauthorized deployment or
secret exposure via a stale CI/CD target.

## Summary

Look for the mismatch between what a record/config still claims and what
actually exists today — this is the core signal. Never perform an actual
third-party resource claim without explicit engagement authorization;
demonstrate reclaimability through documented evidence instead.
