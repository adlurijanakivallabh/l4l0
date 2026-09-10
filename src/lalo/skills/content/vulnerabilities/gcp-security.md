---
name: gcp-security
category: vulnerability
description: GCP-specific attack surface — metadata-service token theft, service-account/IAM binding specifics beyond the generic cloud-IAM skills, and a per-class proof ladder
keywords: [gcp, google cloud, service account, iam, gcs, cloud functions, workload identity]
---

# GCP-Specific Security

GCP-specific mechanisms and gotchas; apply alongside
[[cloud-iam-privilege-escalation]] and
[[cloud-iam-storage-misconfiguration]] for the general methodology.

## Attack Surface

- GCE/Cloud Run/Cloud Functions metadata service reachable via SSRF,
  exposing the attached service account's OAuth2 access token.
- Overly broad IAM role bindings at the project/folder/organization level
  (especially a legacy Editor/Owner role, or a custom role that
  over-grants beyond a resource-specific predefined role).
- GCS bucket IAM (uniform bucket-level access) vs. legacy ACLs — a bucket
  with uniform access enabled is governed entirely by IAM, but one
  without it can have a permissive object ACL independent of the bucket's
  own IAM policy.
- Workload Identity Federation trust configurations allowing an external
  (non-Google) identity provider to impersonate a GCP service account.

## Recon

- From an SSRF foothold, probe
  `http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token`
  with the required `Metadata-Flavor: Google` header — confirm the
  attached service account's actual scope via
  `.../service-accounts/default/scopes` before assuming broad access.
- Enumerate the effective IAM policy at every level (project, folder,
  organization) via `gcloud projects get-iam-policy` — a binding granted
  at a HIGHER level (folder/org) than the resource you're testing is easy
  to miss if you only check the resource's own policy.
- For a GCS bucket, check whether uniform bucket-level access is enabled;
  if not, check for a legacy `allUsers`/`allAuthenticatedUsers` ACL grant
  independently of the bucket's IAM policy.

## Techniques

1. **Metadata-service token theft via SSRF**, per Recon — confirm the
   token's actual scope via a trial call to the relevant API rather than
   assuming project-wide access from the token's mere presence.
2. **Legacy Editor/Owner role check.** A service account or user still
   holding the legacy `roles/editor` or `roles/owner` (rather than a
   scoped predefined or custom role) is itself a reportable overreach
   given these broadly imply near-total project control — confirm via
   the IAM policy, then demonstrate concrete impact from that scope.
3. **Workload Identity Federation trust overreach.** An overly broad
   `attribute-condition` (or none at all) on a workload identity pool
   provider lets ANY token from the trusted external IdP impersonate the
   bound service account, not just the intended workload — confirm the
   condition actually restricts to the expected subject/repository/
   environment.
4. **GCS ACL bypass check.** With uniform bucket-level access disabled,
   confirm whether a legacy object or bucket ACL grants broader access
   than the bucket's own IAM policy suggests.

## Proof Ladder

Follow [[cloud-iam-privilege-escalation]]'s own proof ladder for
escalation impact, and [[cloud-iam-storage-misconfiguration]]'s for a
storage-access finding.

## Validation and False-Positive Discipline

Apply [[closure-discipline]]. A metadata-service token whose scopes are
narrowly restricted (e.g. only `logging.write`) is the control working
correctly even though the endpoint itself is reachable — confirm the
actual scope via the token, not just that the endpoint answered. Uniform
bucket-level access being enabled closes the legacy-ACL bypass path
entirely for that bucket — verify this setting explicitly before testing
for an ACL bypass that cannot exist once it's on.

## Impact

Project-wide compromise via a legacy Editor/Owner role or an
over-permissioned service account token stolen via SSRF; external-identity
impersonation of a GCP service account via an under-restricted Workload
Identity Federation trust condition; data exposure via a legacy GCS ACL
bypassing an otherwise-correct IAM policy.

## Summary

Always confirm a stolen metadata-service token's actual scope before
assuming project-wide access, and always check for a legacy Editor/Owner
role or a legacy ACL bypass independently of an otherwise-correct-looking
IAM policy or uniform-bucket-access setting.
