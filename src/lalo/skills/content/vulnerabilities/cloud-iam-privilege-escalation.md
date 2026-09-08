---
name: cloud-iam-privilege-escalation
category: vulnerability
description: Chaining individually-minor IAM permissions into privilege escalation once you already hold a starting identity — distinct from initial cloud misconfiguration/exposure recon
keywords: [iam, privilege escalation, passrole, policy attachment, escalation chain, service impersonation, access control matrix, aws, azure, gcp]
---

# Cloud IAM Privilege Escalation

[[cloud-iam-storage-misconfiguration]] covers how a starting cloud
identity or exposed resource is typically found — a public bucket, a
leaked key, a misconfigured trust policy. This skill picks up from "I
already hold a starting identity," the same way [[cloud-iam-storage-misconfiguration]]
itself picks up from "I have a credential" without covering how it was
obtained. The specific technique here is different from broad
misconfiguration hunting: almost no single permission looks dangerous in
isolation, and escalation comes from *chaining* two or more individually
minor-looking permissions — this skill is about finding and proving that
chain, not about finding the identity that starts it.

## Attack Surface

- Any identity (user, role, service account) whose policy grants a
  **self-modifying permission**: attaching or updating its own policy,
  adding itself to a more-privileged group, or creating a new access key
  for itself or another identity.
- Any identity that can **create or configure a resource that then runs
  with a different, more-privileged identity** — passing an execution
  role to a compute/serverless service it can also create or trigger
  (the canonical shape: permission to create a function plus permission
  to pass a role to it, where that role is more privileged than the
  identity doing the creating).
- **Resource-based policies and trust relationships** that grant a
  service or another account the ability to assume a role — a trust
  policy scoped more broadly than the specific principal it was intended
  for.
- **Policy versioning and rollback** permissions — where an identity can
  create a new policy version or set a non-current version as the default
  without a corresponding "manage policy" permission being obviously
  present in a cursory read.
- Group and role **membership-management** permissions distinct from
  policy-editing permissions — the ability to add a principal to a group
  is its own escalation primitive even when that principal cannot edit
  any policy directly.

## Recon

- Start from a concrete starting identity's *own* policy document — not a
  posture scanner's summary of it — and read every action it grants, not
  only the ones that look obviously dangerous by name.
- Cross-reference the granted actions against known escalation primitive
  categories (self-policy-modification, pass-role-to-controllable-service,
  policy-version manipulation, group/role membership management) rather
  than searching for one specific named technique — the categories
  generalize across providers even though the exact API names don't.
- Run a dedicated privilege-escalation enumeration tool (this project's
  runtime arsenal ships Pacu for AWS) against the starting identity's own
  credentials, read-only — it names the *specific* technique a given
  policy permits far faster than manual cross-referencing, and its output
  is a lead list to verify by hand, never the finding itself.
- Build the escalation graph as a real artifact before testing anything:
  which identity can reach which more-privileged identity, and via which
  specific permission — this is the same "map before you test" discipline
  [[access-control]] and [[graphql]] both apply at their own layer,
  applied here to the identity/permission graph instead of routes or
  resolvers.
- Use the `access_control_matrix` tool to track this systematically: build
  the matrix with each candidate identity against each target permission/
  resource it might reach via escalation, then mark each cell tested as
  you confirm or rule out that specific hop — this is what keeps "I
  assumed this permission was safe because it looked minor" from silently
  standing in for "I actually tested it."

## Techniques (start quiet, escalate only as needed)

1. **Enumerate escalation candidates from the policy document itself.**
   Before running any tool, read the starting identity's policy and note
   every action matching one of the primitive categories above — this
   costs nothing and often narrows the search before Pacu or an
   equivalent tool even runs.
2. **Automated escalation-path enumeration.** Run the arsenal's
   privilege-escalation tool read-only against the starting credential —
   it will name specific technique+permission combinations (the canonical
   AWS example: `iam:PassRole` combined with `lambda:CreateFunction` or
   `ec2:RunInstances`, letting the caller run code under a role it could
   never assume directly).
3. **Execute the minimal proof of one identified chain.** Where a chain is
   identified, execute only the steps needed to demonstrably gain the
   broader access — creating the minimal resource, passing the role, and
   confirming the resulting identity via the platform's own "who am I"
   API — never a destructive or persistence-creating action, and never
   more of the chain than is needed to prove the escalation actually
   works end to end.
4. **Confirm the gain, not just the permission.** A policy simulator or
   dry-run API telling you an action "would be allowed" is not the same
   as actually executing the minimal chain and observing the elevated
   identity — some services evaluate effective permissions differently
   under real execution (session policies, permission boundaries,
   service-control-policy interactions) than a static simulator predicts.
5. **Trust-relationship and cross-account chaining, once a same-account
   chain is settled.** Where a resource or role trust policy grants
   another account (or another role within the account) assumption
   rights, test whether that separately-reachable principal's OWN
   permissions extend the chain further — an escalation that crosses an
   account boundary is a materially different, usually higher-severity
   finding than one contained within a single account.
6. **Group/role membership-management chaining, as its own primitive.**
   Where an identity can add itself (or another identity it controls) to
   a group or role rather than editing a policy directly, prove the
   resulting membership actually grants the target group's permissions —
   this is a distinct mechanism from policy attachment and is easy to
   miss if you only searched for policy-editing actions.

## Proof Ladder

- **L1 — escalation candidate identified.** A specific permission or
  permission combination matching a known escalation primitive is
  identified in the starting identity's policy, but no chain has been
  executed yet.
- **L2 — chain technically available, not yet exercised.** A scanner or
  manual review confirms the specific API calls needed are permitted
  (via policy read or a dry-run/simulate call), but the actual escalation
  has not been executed end to end.
- **L3 — escalation executed and the resulting broader access confirmed.**
  The minimal chain was actually run, and the resulting elevated identity
  was confirmed via a real API call (the platform's own identity check, or
  a benign read only the elevated identity could perform). This is the
  threshold for a reportable finding.
- **L4 — administrator-equivalent or cross-account escalation.** The
  chain reaches an administrator-equivalent identity, crosses an account
  boundary via a trust relationship, or the same primitive is confirmed
  reachable from more than one starting identity (a systemic policy
  design flaw, not a single misconfigured principal).

Calibrate severity separately per [[severity-calibration]] — an escalation
reaching administrator-equivalent or crossing an account boundary is
typically critical; a chain confined to a narrow, already-low-privilege
lateral move is usually medium to high depending on what it actually
reaches.

## Validation and False-Positive Discipline

Apply [[closure-discipline]] before recording anything. Class-specific
traps:

- A permission *simulator* or dry-run result saying an action "would
  succeed" is a lead, never proof — permission boundaries, service-control
  policies, and session-policy restrictions can all make the real call
  fail even when a static simulation says it would pass. Execute the
  minimal real chain before claiming L3.
- The presence of a dangerous-looking permission (`iam:*`,
  `PassRole`) is not itself proof of escalation — confirm the SPECIFIC
  combination with a second permission that actually completes a known
  chain, and confirm no permission boundary or SCP narrows the effective
  grant.
- An escalation tool's own severity rating is its heuristic, not your
  confidence score — verify the specific chain against the real policy
  documents and, where possible, a real executed call before reporting at
  that severity.
- "This role is only used internally by CI" or an equivalent operator
  claim about intended usage does not change whether the policy itself
  permits escalation — test what the policy actually allows, not what the
  operator believes it is used for.
- An `access_control_matrix` cell marked untested is an open question, not
  a ruled-out one — do not report "no other escalation paths exist" from
  an incomplete matrix; say plainly which cells were never reached.

## Impact

Full account (or, via a cross-account trust chain, multi-account)
compromise from a starting identity with no individually alarming
permission; persistent administrator-equivalent access via a
self-attached policy or group membership; and lateral movement into
production compute/serverless resources via a passed execution role.

## Summary

Privilege escalation in cloud IAM rarely comes from one obviously
dangerous permission — it comes from chaining permissions that each look
minor on their own. Map the identity/permission graph before testing,
track exactly which hops were confirmed versus assumed with the
`access_control_matrix` tool, and always execute the minimal real chain
to confirm the resulting access rather than trusting a simulator's
prediction.
