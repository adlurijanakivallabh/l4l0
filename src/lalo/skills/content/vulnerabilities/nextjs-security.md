---
name: nextjs-security
category: vulnerability
description: Next.js-specific attack surface — API-route/middleware auth gaps, Server Actions/RSC data-exposure edge cases, and a per-class proof ladder
keywords: [nextjs, next.js, react server components, server actions, middleware, api routes]
---

# Next.js-Specific Security

Next.js blends server and client code in one project in a way that
creates its own distinct failure modes — a framework-specific
escalation of [[access-control]], [[information-disclosure]], and
[[csrf]].

## Attack Surface

- `middleware.ts` used as the SOLE auth check for a set of routes — its
  `matcher` config can have gaps (a route pattern that doesn't actually
  match what the developer intended, especially with dynamic segments or
  trailing-slash variations), and a route handler reachable directly
  (bypassing the expected page-render path) may not re-check auth itself.
- Server Actions (`"use server"` functions) — each one is a real,
  independently-callable network endpoint the moment it's exported, even
  though it reads like a plain function call in the calling component;
  a Server Action performing no additional auth/ownership check of its
  own inherits none of the calling page's own access control.
- React Server Components accidentally serializing more than intended
  into the client bundle/payload — a server-only secret or an internal
  object passed as a prop to a Client Component crosses the server/
  client boundary and becomes visible in the page source or RSC payload.
- `getServerSideProps`/API routes reading environment variables without
  the `NEXT_PUBLIC_` prefix distinction — a variable meant to stay
  server-only that is mistakenly given the `NEXT_PUBLIC_` prefix is
  bundled into client-side JavaScript at build time.

## Recon

- Read `middleware.ts`'s `matcher` config against the actual route tree
  and test edge cases directly: a trailing slash, a case variation, a
  route one level deeper than the matcher pattern's own wildcard depth
  covers.
- Grep for `"use server"` directives and treat each exported function as
  its own endpoint — check whether it re-validates the caller's
  identity/ownership independently, or only relies on the calling page
  having already checked (which an attacker calling the action's own
  generated endpoint directly bypasses entirely).
- Diff the server-rendered page source and any RSC payload against what
  the corresponding React component's props actually need — an object
  passed wholesale to a Client Component (rather than the specific
  fields it uses) is a common source of accidental over-serialization.

## Techniques

1. **Middleware matcher-gap probe.** Request the protected route's exact
   path with common variations (trailing slash, differing case, an
   encoded segment) and confirm the middleware's auth check actually
   fires for each — a gap here fully bypasses the intended protection.
2. **Server Action direct-call probe.** Call a Server Action's generated
   endpoint directly (its `Next-Action` header-driven POST, discoverable
   from the client bundle or by simply invoking it from a page context
   other than the one it was written for) with a different user's
   identity/session and confirm whether it enforces the same ownership
   check the calling page assumed.
3. **Client-payload secret scan.** Search the actual rendered page
   source and any RSC payload/`__NEXT_DATA__` blob for a value that
   should have stayed server-only (an internal id scheme, a third-party
   API key, unredacted user data beyond what the visible UI needs).

## Proof Ladder

Follow [[access-control]]'s ladder for a middleware/Server-Action gap and
[[information-disclosure]]'s ladder for an over-serialization finding.

## Validation and False-Positive Discipline

Apply [[closure-discipline]]. A Server Action confirmed to independently
re-validate the caller's identity/ownership (not merely relying on the
calling page's own prior check) is the control working correctly even
though the action is technically callable directly. A value present in
the client bundle that is already intentionally public (confirmed via
the `NEXT_PUBLIC_` prefix and a check that it carries no actual secret
value) is expected behavior, not a finding.

## Impact

Full access-control bypass via a middleware matcher gap or an
unauthenticated/unauthorized direct call to a Server Action; sensitive
data or secret exposure via over-serialization into the client bundle or
RSC payload.

## Summary

Treat every exported Server Action as its own independently-callable
endpoint requiring its own auth/ownership check, never assuming the
calling page's own check carries over. Separately, always test
middleware matcher edge cases directly rather than trusting the config's
stated intent.
