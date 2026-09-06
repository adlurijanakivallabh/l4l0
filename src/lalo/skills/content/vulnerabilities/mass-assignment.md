---
name: mass-assignment
category: vulnerability
description: Mass assignment — unauthorized field binding via extra JSON/GraphQL parameters, privilege escalation and ownership takeover, with a per-class proof ladder
keywords: [mass assignment, over-posting, autobinding, parameter pollution, privilege escalation via api]
---

# Mass Assignment

Mass assignment happens when a create/update endpoint binds a whole
client-supplied object straight into a model or ORM call instead of
picking out an explicit allowlist of fields — so a field the UI never
exposes (`role`, `isAdmin`, `ownerId`, a billing flag) can still be set
directly by anyone who knows or guesses its name. It is a binding-layer
failure, not an input-validation one: the value passed is often perfectly
well-formed, just for a field the caller was never supposed to touch.

## Attack Surface

- Any REST/JSON create or update endpoint, GraphQL mutation, or form-
  encoded/multipart submission that maps request fields onto a model or
  ORM object automatically.
- Nested/relational writes: a writable nested serializer or an ORM's
  "accept nested attributes" feature can let a caller create or re-link
  objects outside their own scope through a field that looks unrelated to
  the top-level resource being edited.
- Bulk/batch endpoints, where a per-item field allowlist is easy to skip
  for array elements even when the single-item endpoint enforces one
  correctly.
- Sparse/patch update formats (JSON Merge Patch, JSON Patch) — these are
  specifically designed to set only the fields present, which is exactly
  the shape a hidden extra field slips through unnoticed in.

## Recon

- Build a per-resource sensitive-field dictionary before testing anything:
  `role`/`isAdmin`/`permissions[]`, ownership fields (`ownerId`/
  `accountId`/`tenantId`/`organizationId`), quota/limit fields
  (`usageLimit`/`seatCount`/`creditBalance`), feature/beta flags, and
  billing fields (`plan`/`price`/`trialEnd`/`prorate`). Mine these names
  from API responses (even a field the UI never shows may appear in a raw
  JSON response), OpenAPI/GraphQL schemas, and client-bundle/mobile-app
  source.
- Identify how binding actually happens for the target framework — an
  explicit allowlist (Rails strong parameters, DRF serializer fields) is a
  real control; a permissive default (`guarded = []`, a serializer that
  mirrors the whole model, a hand-rolled `Object.assign(model, req.body)`)
  is not.
- Check whether validation runs on the SAME parsed object that gets bound,
  or on a separate pass that can be skipped by switching content type —
  the two are frequently different code paths.

## Techniques (start quiet, escalate only as needed)

1. **Direct field injection.** Submit a legitimate create/update request
   with one extra sensitive field added (`{"name": "x", "role": "admin"}`)
   and check whether it persists — the single most direct test, and often
   the whole finding.
2. **Content-type switching.** Resend the same injected field as
   `application/x-www-form-urlencoded`, `multipart/form-data`, and
   `text/plain` — a validator wired to only one content-type's parser
   leaves the others completely unchecked even when JSON looks safe.
3. **Key-path variants.** If a flat field is rejected, try dotted/bracket
   nested paths the same binder may still traverse (`profile.role`,
   `profile[role]`, `settings[roles][]`), and duplicate-key precedence
   (`{"role":"user","role":"admin"}` — confirm which value the server's
   JSON parser actually keeps).
4. **GraphQL input-object overreach.** Add a sensitive field to a mutation
   input object even though the documented schema/UI never sets it —
   field-level authorization on input types is commonly missing even where
   query-level authorization is enforced; immediately re-query the
   resource afterward, since a mutation's own filtered response may hide a
   change that still landed.
5. **Bulk/batch smuggling.** Where a single-item endpoint correctly
   allowlists fields, insert one malicious object inside an otherwise
   legitimate batch/bulk array — per-item allowlisting is a common gap
   even when the singular path is solid.
6. **Nested-write pivot.** Use a writable nested relation to create or
   re-link an object under a DIFFERENT owner/tenant than the caller's own
   — the top-level resource being edited may belong to the caller while
   the nested write silently escapes that scope.

## Proof Ladder

- **L1 — field accepted, not yet confirmed persisted.** The request with
  the injected field returns success (no validation error), but the
  actual persisted state has not yet been independently re-checked.
- **L2 — persistence confirmed via response only.** The server's own
  response to the SAME request echoes the injected value back — a real
  signal, but not yet independently confirmed via a separate read.
- **L3 — persistence confirmed via independent read.** A fresh GET/query —
  separate from the mutating request/response, ideally from a different
  privilege level or session — shows the sensitive field's new value.
  This is the threshold for a reportable finding.
- **L4 — concrete privilege/ownership/financial impact demonstrated.** The
  changed field actually grants elevated access (an admin action now
  succeeds), transfers a resource across tenants (confirmed from the
  OTHER tenant's own view), or alters a real financial value the server
  is supposed to compute itself.

Calibrate severity separately per [[severity-calibration]] — a mass-
assignable non-sensitive display field is a very different severity from
one that flips a role or moves a resource across a tenant boundary, even
though both are the identical binding failure.

## Validation and False-Positive Discipline

Apply [[closure-discipline]] before recording anything. Class-specific
traps to check before calling something confirmed:

- A server that silently DROPS an unknown/extra field (accepts the
  request, ignores the field, and a follow-up read shows no change) is not
  vulnerable — the L1→L2 jump above exists specifically to catch this; do
  not report from the request/response alone.
- A field the server always RECOMPUTES itself (a derived `plan` or `price`
  ignoring whatever the client sent) is not a finding, even if the client
  value was technically accepted somewhere in the pipeline — confirm the
  client-supplied value is what actually ends up persisted, not a value
  the server derived independently.
- Confirm the persistence check reads from a genuinely independent path —
  the SAME cached response object re-displayed is not independent
  confirmation.
- A change visible only in a UI element (a client-side flag) with no
  effect on server-authoritative behavior or a subsequent API read is a
  UI bug, not mass assignment — the persisted, server-side state is what
  matters.

## Impact

Privilege escalation to admin/staff roles, cross-tenant or cross-account
resource ownership takeover, billing/quota manipulation (raised limits,
altered prices, extended trials), and bypass of approval or verification
workflows by directly setting a status/verified flag.

## Summary

Mass assignment is eliminated only by an explicit, per-endpoint field
allowlist enforced consistently across every content type, nested/relation
write, and batch path — never by relying on the client (or the UI) to
simply not send a field the server would otherwise accept.
