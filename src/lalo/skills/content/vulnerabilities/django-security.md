---
name: django-security
category: vulnerability
description: Django-specific attack surface — QuerySet injection edge cases, DEBUG-mode information disclosure, signing/session internals, and a per-class proof ladder
keywords: [django, python web framework, queryset, orm injection, debug mode]
---

# Django-Specific Security

Django's own ORM and middleware close most of the generic classes by
default; this skill covers where Django-specific mechanisms create their
own distinct gaps, framework-specific escalations of [[sql-injection]],
[[access-control]], and [[information-disclosure]].

## Attack Surface

- Raw SQL escape hatches: `.raw()`, `.extra()` (deprecated but still
  present in older codebases), and any `cursor.execute()` with
  string-formatted (not parameterized) input.
- `QuerySet` filter keys built from user-controlled strings passed via
  `**kwargs` to `.filter()`/`.exclude()` — Django's field-lookup syntax
  (`__gt`, `__contains`, `__isnull`, and critically `__year`/date-based
  lookups that can trigger a slow query) becomes attacker-controlled if
  the KEY itself, not just the value, comes from user input.
- `DEBUG = True` in a production-reachable deployment — Django's own
  debug error page discloses the full settings module (including
  `SECRET_KEY` if not filtered), installed apps, and local variable state
  at the point of the exception.
- `django.core.signing`/session-cookie internals: a leaked `SECRET_KEY`
  (via the DEBUG page above, a leaked `.env`, or a weak/default value)
  allows forging any signed cookie or session, not just re-reading one.

## Recon

- Trigger a genuine unhandled exception (an invalid type on a normally-
  validated parameter, a malformed multipart body) and check whether the
  response is Django's own yellow debug traceback page rather than a
  generic 500 — this is the highest-value single check for this
  framework given how much it discloses at once.
- Grep accessible source (if available) for `.raw(`, `.extra(`, and any
  `**request.GET`/`**request.POST` spread directly into a `.filter()` or
  `.exclude()` call — the field-lookup-key-injection pattern is easy to
  miss without seeing the actual call site.
- Check whether `SECRET_KEY` is Django's own well-known insecure
  development default (`django-insecure-...` prefix, or older
  versions' placeholder values) — a leaked or default key is a full
  session/signing compromise on its own, worth testing directly.

## Techniques

1. **Field-lookup-key injection.** Where user input controls a filter
   KEY (not just a value) reaching `.filter(**{user_key: value})`, probe
   with Django's own lookup suffixes to confirm the key is unsanitized:
   `__isnull=True` (bypasses an expected exact-match filter entirely,
   returning unintended rows), a chained relation traversal
   (`related_model__field`) that reaches data outside the intended
   query's scope, or a deliberately slow lookup for a DoS-adjacent signal
   (report only as a note, per this project's own non-destructive
   testing discipline — never actually execute a resource-exhaustion
   attack).
2. **DEBUG-page triggering**, per Recon — once triggered, extract
   `SECRET_KEY` (if present and not filtered by Django's own
   `SAFE_SETTINGS`/sensitive-variable masking, which is not applied to
   every custom setting) and any other credential visible in the local
   variable dump.
3. **Signed-cookie/session forgery**, once `SECRET_KEY` is known — use
   `django.core.signing.dumps`/a compatible forgery script to mint a
   session or signed value that the application will accept as
   legitimate; confirm by presenting it and observing the authenticated
   response.

## Proof Ladder

- **L1** — a Django-specific mechanism identified (a raw-SQL escape
  hatch, a user-controlled filter key, `DEBUG` possibly enabled) but not
  yet confirmed exploitable.
- **L2** — the mechanism confirmed reachable (the debug page actually
  renders; the filter-key injection changes the returned row set) but no
  concrete secret/data exposure demonstrated yet.
- **L3** — a concrete secret or unintended data extracted (`SECRET_KEY`
  from the debug page, out-of-scope rows via lookup-key injection) —
  reportable.
- **L4** — the extracted secret used to forge a session/signed value that
  the application accepts, demonstrating full authentication bypass.

## Validation and False-Positive Discipline

Apply [[closure-discipline]]. `DEBUG = True` confirmed disabled (a
generic error page, no traceback) closes the debug-disclosure path
entirely — do not report DEBUG-mode risk speculatively without actually
triggering an exception and observing the response. A `.filter()` call
built from a fixed, developer-authored key (never from `request.GET`/
`request.POST` directly) is not vulnerable regardless of how the VALUE is
validated — confirm the KEY's own source, not just the value's.

## Impact

Full settings/secret disclosure and subsequent session/signing forgery
via a triggered debug page; data exposure or access-control bypass via
field-lookup-key injection reaching unintended rows or relations.

## Summary

The Django debug page is the single highest-value target — always try to
trigger a genuine unhandled exception first. Separately, always check
whether a filter KEY (not just its value) is user-controlled before
assuming Django's ORM parameterization protects a `.filter()` call the
same way it protects a raw value.
