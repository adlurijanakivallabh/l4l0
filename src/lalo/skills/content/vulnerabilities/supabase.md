---
name: supabase
category: vulnerability
description: Supabase-specific attack surface — Row Level Security policy gaps, service-role-key exposure, Postgres function trust boundaries, and a per-class proof ladder
keywords: [supabase, row level security, rls, postgres, service role key, anon key]
---

# Supabase

Supabase exposes a Postgres database directly to clients via
PostgREST, with Row Level Security (RLS) policies as the ENTIRE
enforcement boundary — the direct analog of Firebase's security rules,
specific to Postgres's own RLS mechanism and Supabase's two-key model.

## Attack Surface

- Row Level Security policies (or their absence) on every table exposed
  via the auto-generated REST/GraphQL API — a table with RLS disabled
  entirely, or enabled with an overly permissive policy, is a direct,
  unmediated data-access vulnerability the same shape as a Firestore
  rules gap.
- The `anon`/`service_role` key distinction — the `service_role` key
  bypasses RLS entirely and must never reach client-side code; its
  presence in a client bundle, a mobile app binary, or a leaked
  environment file is a full, unmediated database-bypass credential.
- Postgres functions exposed via RPC (`supabase.rpc(...)`) marked
  `SECURITY DEFINER` — these run with the DEFINING user's privileges
  (often elevated) rather than the calling user's, so an insufficiently
  validated `SECURITY DEFINER` function is a privilege-escalation path
  independent of RLS entirely.
- Storage bucket policies (Supabase Storage has its own RLS-like policy
  system, separate from the database's) with a similar permissive-
  default risk.

## Recon

- For every table reachable via the REST API (`/rest/v1/<table>`), check
  whether RLS is enabled at all and, if so, read the actual policy
  definitions where source/config access exists — a table's mere
  presence in the schema does not mean RLS is enforced on it.
- Search client-side code/bundles/mobile binaries for the `service_role`
  key specifically (distinct from the intentionally-public `anon` key) —
  check the JWT payload's own `role` claim if only a bare key string is
  found, since `service_role` and `anon` keys are both JWTs signed with
  the project's JWT secret and differ only in this claim.
- Enumerate RPC-exposed Postgres functions and identify which are marked
  `SECURITY DEFINER`.

## Techniques

1. **Direct RLS-boundary probe**, applying [[access-control]]'s
   methodology against the REST/GraphQL API using the `anon` key (or an
   authenticated low-privilege user's key): attempt to read/write rows
   outside the expected scope and observe whether RLS actually rejects
   it.
2. **`service_role`-key exposure scan**, per Recon — if found client-
   side, confirm its actual role via the JWT payload and demonstrate the
   bypass by reading/writing a row an RLS policy would otherwise deny,
   using that key directly.
3. **`SECURITY DEFINER` function privilege-escalation probe.** Call the
   function with adversarial arguments and confirm whether it performs
   an operation the CALLING user's own privileges would not otherwise
   permit, applying [[access-control]]'s methodology to this specific
   Postgres mechanism.

## Proof Ladder

Follow [[access-control]]'s own proof ladder — this skill supplies the
Supabase-specific mechanisms (RLS, key model, `SECURITY DEFINER`) to
reach it.

## Validation and False-Positive Discipline

Apply [[closure-discipline]]. RLS confirmed enabled on a table with a
policy checking `auth.uid() = owner_id` (or an equivalent real ownership
condition) on every operation is the control working correctly — confirm
against the actual policy definition, not the application's own client-
side query behavior. A found key confirmed to carry the `anon` role via
its JWT payload (not `service_role`) is expected and intentionally
public.

## Impact

Direct, unmediated read/write access to any row via a missing or
permissive RLS policy; full database bypass via a leaked `service_role`
key; privilege escalation via an insufficiently validated `SECURITY
DEFINER` function.

## Summary

Check RLS enablement and policy definitions directly for every exposed
table — a table's presence in the API is not evidence either way.
Separately, always distinguish an `anon` key from a `service_role` key
by its JWT payload before treating a found key as either benign or
catastrophic.
