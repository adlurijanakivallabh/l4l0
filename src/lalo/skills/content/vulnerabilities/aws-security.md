---
name: aws-security
category: vulnerability
description: AWS-specific attack surface — IMDS credential theft, S3/Lambda/IAM specifics beyond the generic cloud-IAM skills, and a per-class proof ladder
keywords: [aws, s3, iam, lambda, ec2, imds, sts, cloudtrail, kms]
---

# AWS-Specific Security

This skill covers AWS-specific mechanisms and gotchas; the generic
cross-provider privilege-escalation and storage-misconfiguration
methodology lives in [[cloud-iam-privilege-escalation]] and
[[cloud-iam-storage-misconfiguration]] — apply both together rather than
duplicating that reasoning here.

## Attack Surface

- EC2/ECS/Lambda instance metadata (IMDS) reachable via an SSRF primitive
  on any service running in the account.
- S3 bucket policies, ACLs, and pre-signed URLs; overly broad
  `sts:AssumeRole` trust policies; Lambda execution-role over-privilege;
  Cognito identity-pool unauthenticated-role grants.
- CloudTrail/GuardDuty logging gaps that would hide exploitation.

## Recon

- From any SSRF foothold, probe `http://169.254.169.254/latest/meta-data/`
  (IMDSv1) and confirm whether IMDSv2's session-token requirement (a
  `PUT` for a token before any `GET`) is actually enforced — IMDSv1 being
  reachable at all from an SSRF primitive is itself a real, reportable
  finding on modern AWS given IMDSv2 has been the recommended default for
  years.
- Enumerate the current role's effective permissions via `aws sts
  get-caller-identity` then `aws iam simulate-principal-policy` (or, more
  reliably against opaque policies, direct trial calls) rather than
  trusting the account's own IAM policy documents at face value — an
  explicit `Deny` elsewhere, or an SCP at the organization level, can
  silently narrow what a policy document alone suggests is allowed.
- Check S3 bucket policy AND the separate "Block Public Access" account/
  bucket-level settings independently — a bucket policy allowing public
  read is still blocked if Block Public Access is on, and vice versa a
  restrictive-looking policy can be overridden by a permissive ACL if
  Block Public Access is off.

## Techniques

1. **IMDS credential theft via SSRF**, per Recon above — once temporary
   credentials are retrieved from `iam/security-credentials/<role>`,
   confirm their actual scope via `sts get-caller-identity` and a handful
   of read-only trial calls before assuming account-wide access.
2. **Lambda execution-role over-privilege.** A function with an
   overly-broad execution role (common: `s3:*` on `*` instead of the
   specific bucket the function needs) reachable via any code-execution
   primitive in that function (a deserialization bug, an injected
   environment-variable read) inherits that role's full scope.
3. **S3 pre-signed URL scope check.** Confirm a pre-signed URL is scoped
   to the specific object/method/expiry it claims — a URL generated with
   an overly broad prefix or excessive expiry is a durable-access finding
   distinct from the bucket policy itself.
4. **Cross-account trust-policy overreach.** A role's trust policy
   granting `sts:AssumeRole` to `"*"` or an overly broad external
   account/condition is a durable privilege-escalation path — confirm by
   attempting the assume-role from outside the expected trusted
   principal.

## Proof Ladder

Follow [[cloud-iam-privilege-escalation]]'s own proof ladder — this skill
supplies AWS-specific techniques to reach each of its stated levels, not
a separate ladder.

## Validation and False-Positive Discipline

Apply [[closure-discipline]]. IMDSv2 enforcement (a required session
token) confirmed present is the control working correctly, not a finding
— confirm this explicitly with a token-less `GET` attempt rather than
assuming from account-level configuration alone, since enforcement can be
set per-instance. A `Deny` further up the SCP hierarchy that blocks an
otherwise-broad-looking IAM policy from ever taking effect is a real
control — verify with an actual trial call before reporting the policy
document's stated permissions as exploitable.

## Impact

Full account compromise via a role with excessive trust or execution
permissions; data exposure via a misconfigured S3 bucket or an
over-scoped pre-signed URL; lateral movement across AWS accounts via an
overly broad cross-account trust policy.

## Summary

IMDS credential theft from any SSRF foothold is the single most common
and most impactful AWS-specific path — always check IMDSv2 enforcement
explicitly. Beyond that, this skill supplies AWS-specific mechanisms;
[[cloud-iam-privilege-escalation]] supplies the general escalation
methodology they feed into.
