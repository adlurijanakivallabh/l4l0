---
name: access-control
category: vulnerability
description: Broken object- and function-level authorization (IDOR/BOLA/BFLA) — cross-identity proof, the role matrix, and a per-class proof ladder
keywords: [access control, idor, bola, bfla, authorization, broken access control, horizontal privilege, vertical privilege, cross tenant]
---

# Broken Access Control (Object- and Function-Level)

Authorization must bind subject, action, and the specific object on every
request. If that binding is missing anywhere — one transport, one content
type, one batch code path — the system is vulnerable there regardless of how
correctly every other path enforces it.

## Attack Surface

- **Horizontal access**: reaching another subject's object of the same
  type (another user's record, another account's resource).
- **Vertical access**: reaching a privileged object or action (admin-only
  data, staff-only actions) from a lower-privileged identity.
- **Cross-tenant access**: crossing an isolation boundary in a multi-tenant
  system — often the highest-impact variant, since one gap can expose every
  tenant, not just one other user.
- Object references appear in paths, query parameters, JSON bodies,
  headers, cookies, and — easy to miss — inside JWT claims, GraphQL
  arguments, and WebSocket/gRPC message fields, not only in REST-shaped
  URLs.
- Projection/expansion parameters (`fields`, `include`, `expand`,
  `populate`) are worth checking specifically: they frequently bypass a
  serializer-level authorization check that only guards the base object.
- Bulk and batch endpoints (multi-item update/delete, CSV/JSON import) are
  a recurring gap: many implementations validate only the first item in a
  batch, or the item at creation time but not at every subsequent access.

## Recon

- This is exactly what a role matrix (identity × endpoint) is for: build it
  explicitly rather than testing ad hoc, so that "which pairs were actually
  tried" is a real, checkable set rather than an impression.
- Collect real object identifiers before testing bindings — list/search/
  export endpoints, notifications, and activity feeds routinely leak valid
  IDs belonging to other subjects, which you need anyway to test horizontal
  access convincingly.
- Note every transport the same underlying resource is reachable through
  (a REST endpoint, a GraphQL field, a WebSocket subscription) — an
  authorization check enforced on one transport is not evidence it is
  enforced on all of them.

## Techniques (start quiet, escalate only as needed)

1. **Two-identity horizontal swap.** With two identities of equal
   privilege, request the same action against an object owned by the
   *other* identity's token. This is the minimal, cleanest proof of a
   horizontal gap and should be your first move for any object type.
2. **Vertical probe with a lower-privileged identity.** Repeat against an
   admin/staff-only object or action using a standard, non-privileged
   identity's token.
3. **Read before write.** Establish the authorization gap with a read
   action first — it is lower-impact and just as conclusive for proving the
   binding is missing — before attempting a state-changing action on
   someone else's object.
4. **Cross-channel repetition.** Once a gap is confirmed on one transport,
   test the same object/action through every other transport it is
   reachable from (REST vs. GraphQL vs. WebSocket) — a consistent gap
   across transports is stronger evidence and reveals whether the
   enforcement point is centralized or duplicated (and inconsistently
   duplicated) per transport.
5. **Content-type and parameter-shape variation.** Only if the direct swap
   is blocked: submitting the same object reference via a different
   content type, an alternate parameter name/casing, or a duplicated
   parameter can reveal that only one code path is actually guarded.
6. **Blind confirmation via differential response.** When content is
   masked but existence itself is the question, use status code, response
   length, or conditional-request behavior differences between an owned and
   a foreign object reference — treat an empty/null result as inconclusive,
   not as proof of enforcement, until compared directly against the
   equivalent request for an object you legitimately own.

## Proof Ladder

- **L1 — binding gap suspected.** A response difference (status, shape,
  timing) between an owned and a foreign object reference suggests missing
  binding, but you have not directly retrieved or modified foreign content.
- **L2 — foreign metadata confirmed.** You confirmed a foreign object's
  existence or non-sensitive metadata (via a differential response) without
  yet reading its actual content.
- **L3 — foreign content read or state changed.** You directly read
  another identity's actual data, or changed the state of an object you do
  not own, using your own credentials. This is the threshold for a
  reportable finding.
- **L4 — systemic or cross-tenant compromise.** The gap generalizes across
  an entire object class or tenant boundary (not just the one object you
  tested), or you chained the access into a further compromise (privilege
  escalation, credential exposure).

Calibrate severity separately per [[severity-calibration]] — a gap on a
low-sensitivity object is a different severity story than the same
mechanical gap on billing, health, or cross-tenant data, even at the same
proof level.

## Validation and False-Positive Discipline

Apply [[closure-discipline]] before recording anything. Class-specific
traps:

- The object is intentionally public or anonymous by design — confirm
  this by checking whether the *owner's* view shows any different content
  than what you retrieved, not by assuming publicness from the endpoint
  name alone.
- An empty array or null response for a foreign object reference can mean
  silent, correct enforcement rather than exposure — compare directly
  against the shape of a legitimate owner's response before treating an
  empty result as either a pass or a fail.
- A check enforced on the primary route does not imply the same check
  exists on a sibling route, an internal API, an async worker reprocessing
  the same object, or a batch/bulk variant — per [[closure-discipline]]'s
  "control on a different path" trap, each reachable path stands on its own
  evidence.
- Two identities that are actually the same underlying account (e.g. a
  shared team seat) will look like a horizontal-access confirmation but
  prove nothing — confirm the two identities are genuinely distinct
  principals before treating a successful cross-access as a finding.

## Impact

Cross-account or cross-tenant data exposure (including regulated categories
— financial, health, personal data), unauthorized state changes such as
transfers, role changes, or cancellations performed on another identity's
behalf, and — for vertical/cross-tenant gaps specifically — potential
privilege escalation or full multi-tenant isolation failure.

## Summary

Authorization has to bind subject, action, and object together, checked at
the point of use, on every transport the object is reachable through.
Identifier opacity (a UUID instead of a sequential integer) is not a
control — the binding check either exists at the sink or it does not.
