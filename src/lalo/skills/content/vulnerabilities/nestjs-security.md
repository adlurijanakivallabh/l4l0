---
name: nestjs-security
category: vulnerability
description: NestJS-specific attack surface — Guard/Interceptor ordering gaps, class-transformer/class-validator bypass edge cases, and a per-class proof ladder
keywords: [nestjs, nest, typescript backend framework, guard, interceptor, class-validator]
---

# NestJS-Specific Security

NestJS's decorator-based Guards/Interceptors/Pipes enforce auth and
validation declaratively, which creates a distinct framework-specific
failure mode when the DECORATOR ORDER or SCOPE doesn't do what a
developer assumes — a framework-specific escalation of
[[access-control]] and [[mass-assignment]].

## Attack Surface

- `@UseGuards()` applied at the controller (class) level vs. the
  individual route (method) level — a guard intended to protect an
  entire controller that is instead only applied to some of its routes
  (or applied but then a specific route uses `@Public()`/a custom
  bypass decorator incorrectly) leaves siblings unprotected.
- Global guards registered via `APP_GUARD` vs. per-module/per-controller
  guards — a route in a module that never imports the guard-providing
  module can be unprotected even when the "global" guard looks like it
  should apply everywhere.
- `class-validator`/`class-transformer` DTOs with `whitelist: true` not
  enabled globally on the `ValidationPipe` — without it, extra fields
  beyond the DTO's own declared properties pass through to whatever
  consumes the validated object, the same mass-assignment shape as an
  unfiltered FastAPI `.model_dump()`.
- A custom `@Roles()`/`RolesGuard` implementation with a logic bug
  (checking `some()` role match when `every()` was intended, or checking
  against a stale/cached user-role claim from the JWT rather than a
  fresh database read after a role change).

## Recon

- Read the actual module wiring (not just individual controller files)
  to determine which guards are TRULY global (`APP_GUARD` in the root
  `AppModule`) versus scoped to a specific feature module — a route in
  an unimported or lazily-loaded module can silently bypass an
  apparently-global guard.
- Check the `ValidationPipe`'s global configuration (usually in
  `main.ts`) for `whitelist: true` and `forbidNonWhitelisted: true` —
  their absence means extra DTO fields are silently accepted (whitelist)
  or silently stripped without erroring (forbidNonWhitelisted absent),
  each with a different exploitability implication worth confirming
  directly rather than assuming from the setting's mere presence.
- Read any custom Guard's actual role-check logic for an `Array.some()`
  vs. `Array.every()` mismatch against the endpoint's documented
  intended access policy.

## Techniques

1. **Per-route guard-gap probe**, following [[access-control]]'s own
   methodology — for every route in a controller whose SIBLING routes
   are protected, test the specific route unauthenticated/under-
   privileged and compare.
2. **Extra-field mass-assignment via DTO whitelist gap**, following
   [[mass-assignment]]'s methodology — send extra JSON fields beyond the
   DTO's declared shape and confirm whether they reach the persistence
   layer when `whitelist`/`forbidNonWhitelisted` is not enabled.
3. **Role-check logic probe.** Where a custom Guard checks membership in
   a role array, test with a role set crafted to exercise the specific
   `some()`/`every()` distinction (e.g. a user with one qualifying role
   among several required ones, if the endpoint is meant to require ALL
   of them).

## Proof Ladder

Follow [[access-control]]'s ladder for a guard-gap finding and
[[mass-assignment]]'s ladder for a DTO-whitelist finding.

## Validation and False-Positive Discipline

Apply [[closure-discipline]]. A route confirmed covered by a genuinely
global `APP_GUARD` (verified in the root module's actual providers array,
not assumed from naming) is the control working correctly. `whitelist:
true` confirmed set on the global `ValidationPipe` closes the extra-
field mass-assignment path for every DTO in the application at once —
verify this one global setting before testing each DTO individually.

## Impact

Authentication/authorization bypass on a route missing effective guard
coverage; privilege escalation or unauthorized data modification via a
DTO whitelist gap; access-control bypass via a role-check logic error in
a custom Guard.

## Summary

Read the actual module wiring to determine which guards are truly
global versus module-scoped before assuming a route is protected — a
route in an unimported module can silently bypass an apparently-global
guard. Separately, one global `ValidationPipe` setting
(`whitelist`/`forbidNonWhitelisted`) determines the DTO mass-assignment
exposure for the whole application at once.
