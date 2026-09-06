---
name: subdomain-takeover
category: vulnerability
description: Subdomain takeover — dangling CNAME/NS records and unclaimed cloud resources on a trusted subdomain, with a per-class proof ladder
keywords: [subdomain takeover, dangling dns, dangling cname, ns takeover, unclaimed bucket]
---

# Subdomain Takeover

A subdomain takeover happens when DNS for a trusted subdomain still points
at a third-party resource (a CNAME to a cloud host, an NS delegation to an
external nameserver) that no one owns anymore — whoever claims that
resource next now serves content, and sometimes receives mail, from a
domain the victim organization's own users and systems trust by name.

## Attack Surface

- Dangling CNAME/A/ALIAS records pointing at hosting, storage, serverless,
  or CDN providers whose resource (bucket, app, site, distribution) has
  since been deleted or renamed.
- Orphaned NS delegations — a child zone delegated to nameservers on a
  domain that has since expired, handing full control of every hostname
  under that delegation to whoever registers the expired domain.
- Decommissioned SaaS integrations still referenced by a CNAME (a support
  desk, a docs site, a marketing/forms tool) long after the integration
  itself was torn down.
- MX records pointing at a decommissioned mail provider — a takeover here
  can mean receiving mail for the subdomain, not just serving web content.

## Recon

- Build the subdomain inventory first — certificate-transparency logs,
  passive DNS, and any known asset list — then resolve every record type
  (A/AAAA/CNAME/NS/MX/TXT) and follow CNAME chains to their final external
  endpoint.
- Classify each external CNAME target by provider (a hosting/storage/CDN
  domain suffix is the strongest signal) and probe it over HTTP/HTTPS,
  capturing status, body, and any provider-specific "unclaimed resource"
  error text.
- For an NS delegation, check whether the domain the child zone is
  delegated to is itself still registered and actively resolving — an
  NS delegation to an expired domain is the highest-impact variant, since
  registering that domain grants authoritative control over every host
  under the delegated subzone.
- Before assuming a fingerprint means "claimable," confirm the provider's
  CURRENT behavior — many providers have since added ownership/TXT
  verification that closes what used to be a takeover; an old fingerprint
  match is a lead, not proof.

## Techniques (start quiet, escalate only as needed)

1. **Fingerprint match.** Request the subdomain over HTTP/HTTPS and match
   the response against a known "unclaimed resource" signature for the
   CNAME's provider (an explicit "no such app," "no such bucket," or
   "unknown domain" message, or a service-specific 404 shape) — this is
   the L1 signal, not yet proof of current claimability.
2. **Claimability confirmation.** Without actually claiming it yet,
   determine from the provider's own current documentation or observed
   behavior whether the specific resource name is still available to
   register and whether the provider requires a separate domain-ownership
   proof (TXT record, file) before binding a custom domain to it — this
   distinguishes a genuinely exploitable gap from a provider that has since
   added verification.
3. **Resource claim (only within engagement authorization for this exact
   step).** Create the matching resource — the exact bucket name, app
   name, or site — with the exact name the dangling record requires.
4. **Control verification.** Serve a minimal, unique marker at the
   now-claimed subdomain and fetch it over HTTPS at the real subdomain URL
   to prove genuine control, not just that the underlying provider
   resource exists.
5. **Trust-chain escalation.** Check whether the taken-over subdomain is
   referenced anywhere that extends trust further: an OAuth `redirect_uri`
   allowlist entry, a CSP `script-src`/`frame-ancestors` allowance, or a
   cookie `Domain` scope shared with the parent — each turns a standalone
   takeover into cookie theft, CSP bypass, or OAuth token interception.

## Proof Ladder

- **L1 — fingerprint match.** An "unclaimed resource" response is observed
  for a dangling record, but current claimability has not been separately
  confirmed against the provider's present-day behavior.
- **L2 — claimability confirmed, not yet claimed.** The specific resource
  name is verified as currently available to register, with no ownership
  verification the attacker couldn't satisfy — but the takeover step
  itself has not been executed.
- **L3 — control demonstrated.** The resource was actually claimed (within
  authorization) and a unique marker is served and independently verified
  at the real subdomain over HTTPS. This is the threshold for a reportable
  finding.
- **L4 — trust-chain impact proven.** The taken-over subdomain is shown
  actually granting further access — accepted as an OAuth `redirect_uri`,
  trusted by a CSP directive, or in the `Domain` scope of a live session
  cookie from the parent site — with that downstream impact independently
  confirmed.

Calibrate severity separately per [[severity-calibration]] — an unclaimed
NS delegation controlling an entire subzone is categorically more severe
than an isolated dangling CNAME to a single forgotten marketing tool.

## Validation and False-Positive Discipline

Apply [[closure-discipline]] before recording anything. Class-specific
traps to check before calling something confirmed:

- An "unknown domain" response does not by itself prove claimability —
  many providers now require a TXT record or other ownership proof before
  binding a custom domain to a newly created resource; confirm the
  provider's CURRENT enforcement, not a historical assumption, before
  reporting above Low.
- A provider-branded default page for a resource that IS still owned by
  the organization (just not yet configured with a custom domain) is not
  a takeover — confirm the resource is actually absent/deletable, not
  merely unconfigured.
- Do not actually register an expired parent domain or claim a production
  resource as "proof" beyond what the engagement's authorization and this
  proof ladder's L3 step require — a claim performed outside authorized
  scope is a serious overstep, not evidence.
- Severity above Low always needs current-state confirmation, not a stale
  fingerprint database entry — provider behavior in this class changes
  frequently and a fingerprint that was exploitable a year ago may not be
  today.

## Impact

Content injection (phishing, malware delivery, brand-trust abuse) served
from a trusted subdomain, cookie and CORS pivot when the parent site scopes
session cookies or CORS to the whole domain, OAuth/SSO redirect abuse via
a whitelisted `redirect_uri`, and mail interception when an MX record
points at the taken-over resource.

## Summary

Subdomain safety is DNS lifecycle safety: any record pointing at an
external resource must be owned and verified for as long as the record
exists — remove the record the moment the resource is decommissioned, or
verify ownership continuously; there is no safe middle state.
