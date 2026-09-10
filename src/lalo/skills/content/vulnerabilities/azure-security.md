---
name: azure-security
category: vulnerability
description: Azure-specific attack surface — IMDS/managed-identity token theft, Storage/Key Vault/Entra ID specifics beyond the generic cloud-IAM skills, and a per-class proof ladder
keywords: [azure, entra id, azure ad, managed identity, key vault, blob storage, arm]
---

# Azure-Specific Security

Azure-specific mechanisms and gotchas; apply alongside
[[cloud-iam-privilege-escalation]] and
[[cloud-iam-storage-misconfiguration]] for the general methodology.

## Attack Surface

- Azure Instance Metadata Service (IMDS) and managed-identity token
  endpoints reachable via SSRF on any compute resource (VM, App Service,
  Function, Container Instance).
- Storage account access keys vs. Shared Access Signatures (SAS) vs.
  Entra ID (Azure AD) RBAC — three independent access paths to the same
  blob/queue/table data, each with its own misconfiguration surface.
- Entra ID app registrations with overly broad API permissions (especially
  an application-type Graph API permission granted admin consent, which
  acts account-wide rather than delegated to a signed-in user).
- ARM/Bicep template outputs or deployment logs leaking a provisioning-
  time secret.

## Recon

- From an SSRF foothold, probe
  `http://169.254.169.254/metadata/identity/oauth2/token` with the
  required `Metadata: true` header — confirm whether a managed identity
  is attached to the compromised resource at all (many are not) before
  assuming this path is live.
- Enumerate a storage account's actual access paths independently: check
  for a still-enabled account key (older, broader-scoped, harder to
  rotate selectively), any long-lived or overly-permissive SAS token
  embedded in client-side code or a config file, and the RBAC role
  assignments on the account/container.
- For Entra ID, distinguish delegated permissions (scoped to what the
  signed-in user could already do) from application permissions with
  admin consent (scoped to everything the permission allows, account-
  wide) — the latter on an app registration reachable via a compromised
  client secret or certificate is a full-tenant-scope finding.

## Techniques

1. **Managed-identity token theft via SSRF**, per Recon — once a token is
   retrieved, confirm its actual resource/scope via a trial call (e.g. to
   Azure Resource Manager or Microsoft Graph) rather than assuming
   account-wide access from the token's mere presence.
2. **Storage access-path downgrade check.** If Entra ID RBAC on a
   container looks properly scoped, still check whether a legacy account
   key or a broad SAS token provides an independent, more permissive path
   to the same data — a properly configured RBAC role does not close this
   class if either bypass path is still live.
3. **App-registration admin-consent overreach.** Confirm an application
   permission with admin consent is actually necessary for the app's
   stated function — a Mail.ReadWrite or Directory.ReadWrite.All granted
   to an app that only needs to read a single calendar is a real,
   reportable overreach even before any exploitation.

## Proof Ladder

Follow [[cloud-iam-privilege-escalation]]'s own proof ladder for
escalation impact, and [[cloud-iam-storage-misconfiguration]]'s for a
storage-access finding.

## Validation and False-Positive Discipline

Apply [[closure-discipline]]. A resource with NO managed identity
attached means the IMDS token-theft path is simply not applicable there —
confirm this explicitly (a 400/404 from the identity endpoint) rather
than reporting IMDS reachability alone as a finding; IMDS being network-
reachable is expected and not itself a vulnerability without a live
identity behind it. Delegated (not application) Graph permissions scoped
tightly to what the app's own UI actually exercises is the control
working as designed.

## Impact

Tenant-wide compromise via an over-consented app registration or a stolen
managed-identity token with broad resource scope; data exposure via a
legacy storage account key or an overly permissive SAS token bypassing
otherwise-correct RBAC.

## Summary

Always confirm a managed identity is actually attached before assuming
IMDS token theft is live, and always check for a legacy-key or SAS-token
bypass path independently of RBAC — a correctly scoped RBAC role does not
close this class if either older path still works.
