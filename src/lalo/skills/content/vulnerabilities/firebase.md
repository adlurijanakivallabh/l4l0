---
name: firebase
category: vulnerability
description: Firebase-specific attack surface — Firestore/Realtime Database security-rule gaps, Cloud Functions trigger trust, and a per-class proof ladder
keywords: [firebase, firestore, realtime database, security rules, cloud functions]
---

# Firebase

Firebase's security model puts most enforcement in declarative Security
Rules evaluated CLIENT-side-callable but SERVER-enforced — the entire
class here is rules that look restrictive but have a logic gap, since
the client SDK itself enforces nothing on its own.

## Attack Surface

- Firestore/Realtime Database security rules — the actual enforcement
  boundary for every direct client read/write; a permissive default
  (`allow read, write: if true;` left from initial scaffolding) or a
  rule with a logic gap is a direct, unmediated data-access
  vulnerability.
- Cloud Functions triggered by a database write (`onCreate`/`onUpdate`)
  that trust the written data's shape/origin without revalidating it —
  since the trigger fires on ANY write that gets past the security
  rules, a rule gap upstream becomes a function-level trust violation
  downstream too.
- Firebase Authentication custom claims used for authorization in
  security rules — a claim set via a Cloud Function with insufficient
  validation of who can request it is a privilege-escalation path.

## Recon

- Obtain or infer the actual deployed security rules (via the Firebase
  console/CLI if access exists, or by direct probing if not) rather than
  assuming from the application's own client-side query patterns — a
  client only ever querying its own documents proves nothing about
  whether the RULES would also allow querying someone else's.
- Identify every custom claim used in a security rule (`request.auth.token.<claim>`)
  and trace how it gets set — a claim set by a Cloud Function
  triggered by a user-writable document (rather than an admin-only
  action) is a strong escalation lead.

## Techniques

1. **Direct rule-boundary probe**, applying [[access-control]]'s
   methodology directly against the Firestore/RTDB REST API or client
   SDK: attempt to read/write a document outside your own expected scope
   (another user's document, a collection the UI never queries) and
   observe whether the rules actually reject it.
2. **Custom-claim escalation via trigger.** If a custom claim is set by a
   Cloud Function reacting to a user-writable event, attempt to trigger
   that function with attacker-controlled input to obtain a claim you
   should not have, then confirm the claim now grants elevated access in
   a security rule that trusts it.
3. **List/query-based over-exposure check.** Even with per-document
   rules correctly scoped, check whether a COLLECTION-level list/query
   operation (rather than a get-by-id) inadvertently returns documents
   the rules would individually deny — a rules gap specific to how
   Firestore evaluates list queries against per-document rules.

## Proof Ladder

Follow [[access-control]]'s own proof ladder — this skill supplies the
Firebase-specific mechanism to reach it.

## Validation and False-Positive Discipline

Apply [[closure-discipline]]. A security rule confirmed to check
`request.auth.uid == resource.data.ownerId` (or an equivalent real
ownership check) on every read/write path for a collection is the
control working correctly — confirm this against the ACTUAL deployed
rules text, not the application's client-side query behavior alone.

## Impact

Direct, unmediated read/write access to any user's data via a security-
rule gap; privilege escalation via a custom claim set through an
insufficiently-validated Cloud Function trigger.

## Summary

The application's own client-side query behavior proves nothing about
what the security rules actually allow — always obtain or directly probe
the real rules, since Firebase's entire enforcement boundary lives
there, not in the client code.
