---
name: business_logic
class: business_logic
summary: Workflow/state-machine abuse, race conditions, and domain-invariant violations.
---
# Business Logic Flaws & Race Conditions

Business logic flaws exploit intended functionality to violate domain
invariants: money moved without paying, limits exceeded, privileges retained.
They need a model of the workflow, not just a payload corpus.

## Attack surface
- Financial: pricing, discounts, refunds, credits, coupons, payments (auth/
  capture/void/refund sequencing, idempotency keys).
- Account lifecycle: signup/trial/upgrade/downgrade/deletion.
- Quotas/limits: rate limits, inventory, redemption caps, seat licensing.
- Multi-step workflows: checkout, approval chains, password reset, MFA enrollment.

## Techniques
- **State-machine abuse**: call step 3 before step 2 (skip a required precondition);
  replay a stale/completed step with altered parameters (change price after
  approval, before capture).
- **Parameter tampering on trusted-client values**: client-computed totals,
  currency/locale switches that trigger different rounding/rules, negative/zero/
  huge quantities.
- **Race conditions (single-packet attack)**: fire the SAME limited-use action
  (redeem a coupon, apply a discount, withdraw funds, vote once) concurrently
  many times in the same HTTP/2 connection/last-byte-sync window; check if it
  was applied more than once (limit bypass = confirmed).
- **Workflow bypass via alternate paths**: an alternate endpoint/version/mobile-
  API route that skips a check the web route enforces.
- **Idempotency-key reuse/omission**: replay a payment/order request without or
  with a stale idempotency key to duplicate an effect.

## Proof ladder
- L1: an invariant-relevant parameter is tamperable client-side.
- L2: a single altered request changes server behavior in a suspicious way.
- L3: demonstrated violation — a race duplicated a limited action, or a
  reordered/skipped step produced an unintended state (in a non-destructive,
  reversible test transaction where possible).
- L4: quantified financial/privilege impact (e.g., N-times discount stacking,
  privilege retained after downgrade).

## Validation
- Reproduce at least twice; a race win can be non-deterministic — report the
  observed hit rate.
- Prefer test/sandbox payment amounts and immediately note/reverse any real
  side effect created during proof (non-destructive discipline still applies).
