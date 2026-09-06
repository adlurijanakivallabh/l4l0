---
name: cloud-iam-storage-misconfiguration
category: vulnerability
description: Cloud IAM privilege misconfiguration and storage exposure — public buckets, leaked credentials, over-permissive roles, privilege-escalation paths, with a per-class proof ladder
keywords: [cloud, iam, aws, azure, gcp, s3, blob storage, privilege escalation, misconfiguration, leaked credentials, resource policy]
---

# Cloud IAM and Storage Misconfiguration

Cloud environments turn a single leaked credential or a single overly-broad
role into the whole account. The attack surface here is rarely a code bug —
it is almost always a configuration decision (a public bucket, a wildcard
policy, a role bound more broadly than intended) that the platform itself
would have prevented by default. Recon here is often cheaper than in any
other class: unauthenticated checks alone frequently confirm exposure.

## Attack Surface

- Object storage (S3 buckets, Azure Blob containers, GCS buckets) with
  public list/read/write permissions, or a resource policy granting access
  wider than intended (a wildcard principal, an overly broad condition).
- IAM identities (users, roles, service accounts) with wildcard actions or
  resources in their policy, or a policy that grants an action which itself
  enables further privilege escalation (creating/attaching new policies,
  passing a role to a service that will execute with it).
- Leaked long-lived credentials: committed to a public repository, embedded
  in a client-side bundle, or disclosed via the SSRF-to-metadata path
  covered in [[ssrf]] — this skill picks up from "I have a credential," not
  how it was obtained.
- Resource/trust policies granting cross-account access, or a trust
  relationship wider than the intended partner account.
- Serverless function configurations with secrets in plaintext environment
  variables, or an execution role broader than the function's own code
  needs.

## Recon

- Check public accessibility with **no credentials first** — an
  unauthenticated list/read attempt against a discovered bucket or object
  URL is the cheapest possible test and needs no account access at all.
- Once any credential is obtained, the very first call is always an
  identity check (the platform's own "who am I" API) — never assume a
  credential's scope from where you found it or what its name implies.
  A key named `readonly-service` is a claim, not a fact.
- Run a cloud security-posture scanner (this project's runtime arsenal
  ships ScoutSuite and Prowler for exactly this) against any obtained
  credentials, read-only — it enumerates policy misconfigurations across
  the whole account far faster than manual API-by-API review, and its
  output is a real inventory to verify against, not the finding itself.
- For AWS specifically, enumerate privilege-escalation paths with Pacu
  (also in the arsenal) — it names the *specific* escalation technique a
  given credential's policy permits (e.g. `iam:PassRole` combined with
  `lambda:CreateFunction`), which is far more actionable than a raw policy
  JSON dump.
- Note the naming convention of any confirmed-exposed resource — cloud
  storage names are frequently predictable from the organization's own
  domain or product names, which narrows further enumeration.

## Techniques (start quiet, escalate only as needed)

1. **Unauthenticated storage checks first.** List and attempt to read one
   object from any discovered bucket/container with no credentials at all
   — this alone often reaches a reportable finding with zero further
   escalation needed.
2. **Identity confirmation for any obtained credential.** Call the
   platform's own identity/whoami API before anything else — this is the
   single highest-value, lowest-risk call available and tells you exactly
   what you are working with, not what you assumed.
3. **Posture scanning across the whole account.** Run the scanner
   read-only, then verify its most severe findings by hand against the
   actual policy documents — a scanner finding is a lead, not proof.
4. **Privilege-escalation path testing.** Where a scanner or manual review
   identifies a plausible escalation chain, execute only the steps needed
   to prove it — stop at the point where you have demonstrably gained
   broader access, and prove that gain with the least invasive action
   available (a benign read using the newly-escalated identity), never a
   destructive or persistence-creating action.
5. **Cross-account/trust boundary testing.** Where a resource or trust
   policy appears to grant cross-account access, confirm the boundary
   actually crosses with a single benign read from the other side, not by
   reading the policy text alone.
6. **Metadata-service credential harvesting.** If SSRF reaches an
   instance-metadata endpoint, that is [[ssrf]]'s own proof ladder, not
   this skill's — cross-reference rather than duplicating the technique;
   this skill starts once you already hold the harvested credential.

## Proof Ladder

- **L1 — exposed footprint identified.** A cloud resource (a bucket name,
  an IAM identity) is confirmed to exist and belong to the target, but no
  unauthorized access has been confirmed yet.
- **L2 — unauthenticated or low-privilege access confirmed.** A public
  object was read without credentials, or an obtained credential's
  identity was confirmed via a real API call — real access, but not yet
  shown to reach anything sensitive or to grant escalation.
- **L3 — meaningful data or privilege gain confirmed.** A bounded, specific
  piece of sensitive data was read, or a privilege-escalation path was
  executed and the resulting broader access was proven with a benign
  action. This is the threshold for a reportable finding.
- **L4 — account or organization-wide compromise path.** The escalation
  reaches an administrator-equivalent identity, spans multiple accounts
  via a trust relationship, or the exposure covers bulk sensitive data
  rather than a single bounded object.

Calibrate severity separately per [[severity-calibration]] — a public
bucket holding a single stale log file is a different severity from one
holding customer data or deployment credentials, even though both clear L1.

## Validation and False-Positive Discipline

Apply [[closure-discipline]] before recording anything. Class-specific
traps:

- An `AccessDenied` response is not the same as the resource not existing
  — confirm which one you are actually seeing before drawing a conclusion
  about exposure.
- Public *listing* of a bucket's contents and public *read* of individual
  objects are separate permissions — test the exact operation your claimed
  severity depends on, never infer one from the other.
- A policy document showing a broad-looking permission is not proof of
  actual capability until you exercise the exact allowed action via a real
  API call — a console/CLI dump of policy JSON is a lead, not evidence.
- A scanner's own severity rating is its heuristic, not your confidence
  score — verify the specific finding against the real policy and, where
  possible, a real API call before reporting it at that severity.
- Confirm the resource actually belongs to the engagement's declared scope
  before pursuing further — cloud naming conventions produce false
  positives across unrelated organizations more often than other classes.

## Impact

Full cloud account or organization compromise via a chained
privilege-escalation path, bulk data exfiltration from exposed storage,
lateral movement into production infrastructure via harvested service
credentials, and persistent access via a newly-created or modified IAM
identity.

## Summary

Cloud IAM misconfiguration chains cheap, often unauthenticated recon
(public listings, leaked keys) into privilege-escalation paths a posture
scanner can name precisely. Confirm identity before assuming scope, prove
escalation with the least invasive action that demonstrates real access,
and never take a destructive or persistence-creating action to prove a
point that a benign read already proves.
