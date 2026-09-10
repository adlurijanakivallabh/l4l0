---
name: fastapi-security
category: vulnerability
description: FastAPI-specific attack surface — Pydantic validation-bypass edge cases, dependency-injection auth gaps, background-task/async pitfalls, and a per-class proof ladder
keywords: [fastapi, pydantic, starlette, python async web framework, dependency injection]
---

# FastAPI-Specific Security

FastAPI's Pydantic-based validation and dependency-injection system
prevent whole classes of bugs by default, but create their own distinct
gaps when a developer works around them — a framework-specific
escalation of [[access-control]] and [[mass-assignment]].

## Attack Surface

- A response model (`response_model=`) that differs from the actual
  returned object — FastAPI serializes based on the response model, so a
  developer relying on this for redaction can be wrong if the model
  itself is too permissive or a field is aliased incorrectly.
- Auth enforced via a route-level `Depends(get_current_user)` — a route
  that FORGETS to declare this dependency is entirely unauthenticated,
  with no visual cue in the route decorator itself the way a
  decorator-based framework's `@login_required` would give.
- Pydantic model `.dict()`/`.model_dump()` used directly to build a
  database update — any extra field the client sends that happens to
  match a model attribute (even one marked `Optional` and not intended
  to be client-settable) can flow straight into a mass-assignment.
- `BackgroundTasks` running after the response is already sent — an
  error inside a background task is invisible to the client and often
  under-logged, and a background task that itself does unsafe work (an
  unvalidated file operation, an SSRF-shaped external call) is a
  lower-visibility surface than the main request path.

## Recon

- Enumerate every route via the auto-generated OpenAPI schema
  (`/openapi.json`, unless explicitly disabled) and cross-reference
  against which ones actually declare an auth dependency — a route
  present in the schema with no `Depends(...)` matching the app's own
  auth pattern is a strong lead, not yet a confirmed finding (some routes
  are legitimately public).
- Check whether a model used for a WRITE endpoint reuses a broader model
  also used for reads — a shared model with more fields than the write
  endpoint's own documented request body suggests can indicate a
  mass-assignment surface via extra JSON keys.
- Confirm whether Pydantic's `extra` config is set to `"forbid"` (rejects
  unknown fields, the safer default in Pydantic v2 for most models) or
  left permissive.

## Techniques

1. **Dependency-injection auth-gap probe.** For each route the OpenAPI
   schema exposes with no obvious auth dependency, send an unauthenticated
   request and confirm whether it succeeds where a sibling, clearly-
   protected route would reject it — this is [[access-control]]'s own
   methodology, applied to this framework's specific "forgotten
   decorator" failure mode.
2. **Mass-assignment via extra JSON keys.** Send extra fields in a write
   request's JSON body beyond the documented schema and observe whether
   they take effect (a role/privilege field flipped, a foreign-key
   ownership field changed) — this is [[mass-assignment]]'s methodology,
   specifically checking whether `.model_dump()` output flows unfiltered
   into a persistence call.
3. **Response-model over-exposure check.** Compare the actual JSON
   returned against the documented `response_model` — a field present in
   the response but absent from the schema (or a nested object the
   response model doesn't actually constrain) indicates the developer's
   redaction assumption doesn't hold at runtime.

## Proof Ladder

Follow [[access-control]]'s ladder for an auth-gap finding and
[[mass-assignment]]'s ladder for a write-endpoint finding — this skill
supplies the FastAPI-specific recon and technique, not a separate ladder.

## Validation and False-Positive Discipline

Apply [[closure-discipline]]. A route legitimately intended to be public
(a health check, a login endpoint itself) having no auth dependency is
expected, not a finding — confirm the route's actual intended
sensitivity before reporting a missing dependency. `extra="forbid"`
confirmed set on the write model closes the extra-JSON-key mass-
assignment path entirely for that endpoint.

## Impact

Full authentication bypass on a route missing its intended dependency;
privilege escalation or unauthorized data modification via mass-
assignment through an unfiltered `.model_dump()`; sensitive data exposure
via a response model that doesn't actually constrain what's serialized.

## Summary

Cross-reference the auto-generated OpenAPI schema against the app's own
auth-dependency pattern to find routes missing it — this framework gives
no visual decorator cue the way others do. Separately, always check
whether write-endpoint `.model_dump()` output is filtered before
reaching a persistence call.
