---
name: business-logic
category: vulnerability
description: Business logic and workflow abuse — state-machine bypass, invariant violation, and a per-class proof ladder
keywords: [business logic, workflow bypass, invariant, state machine, idempotency, discount abuse, quota bypass]
---

# Business Logic

Business logic flaws abuse *intended* functionality to violate a domain
invariant — conservation of value, uniqueness, monotonicity, or
exclusivity — rather than exploiting a parsing or memory-safety bug. They
require a model of the business before they require a payload: the first
real work is writing down what must always be true about a workflow, not
sending requests at it.

## Attack Surface

- Financial logic: pricing, discounts, payments, refunds, credits,
  chargebacks.
- Account lifecycle: signup, upgrade/downgrade, trial periods,
  suspension, deletion.
- Authorization-by-logic: feature gates and role transitions enforced by
  application state rather than a route-level check.
- Quotas and limits: usage caps, inventory reservations, seat licensing.
- Multi-tenant isolation: counters, credits, or admin actions that can
  bleed across organizations if a tenant key is missing from a query.
- Event-driven flows: queued jobs, webhooks, sagas, and their
  compensation logic.

## Recon

- Derive the full workflow from the UI and its network traffic, not from
  documentation — map every finalize/confirm/transition endpoint,
  including ones the UI never exposes directly.
- Identify the tokens and flags that gate transitions (a step token, a
  payment-intent ID, an order-status field, an approval ID) and note
  whether any of them look reusable across sessions or principals.
- Write down the actual invariants before testing: what must never
  decrease, what must only happen once, what must sum correctly across
  partial operations. This is the step that determines what "violated"
  even means for this specific workflow.

## Techniques (start quiet, escalate only as needed)

1. **Passive state-machine mapping.** Walk the intended flow once, end to
   end, recording every transition and its stated precondition. No request
   outside normal use is sent yet — this step is purely observational.
2. **Step skip, reorder, or replay.** Call a later step directly without
   its prerequisite (finalize before verify, cancel after ship), or replay
   a stale finalize/confirm request — the cheapest active test, and it
   needs no concurrency or scale to demonstrate a real gap if one exists.
3. **Numeric and currency boundary probing.** Negative amounts, zero-price,
   scientific notation, and cross-currency rounding edges on a single
   request path — still a single-request-at-a-time technique.
4. **Client-trust probing.** Submit a client-recomputed total, discount, or
   tax figure and see whether the server accepts it verbatim instead of
   recomputing from trusted server-side state.
5. **Quota and limit slicing.** Split a single constrained action into
   many sub-actions that each stay under a per-action threshold. Escalate
   to genuine concurrency only if the sequential version does not already
   prove the gap — see [[race-conditions]] for when an invariant only
   breaks under concurrent load, since that requires its own
   synchronization technique and its own proof standard.
6. **Cross-service and saga boundary probing, reserved for genuinely
   distributed workflows.** Trigger a compensation step without the
   original action having actually succeeded, or exploit the window before
   an eventually-consistent write becomes visible to a dependent service —
   the highest setup cost of this list, worth attempting only once
   single-service invariants are exhausted.

## Proof Ladder

- **L1 — invariant stated, no violation attempted.** The workflow and its
  state machine are mapped and at least one concrete invariant is written
  down, but no test has been run against it yet.
- **L2 — violation achieved, no real value.** A technique succeeds in
  producing an unintended state transition, but the result has no real
  value or falls within an explicitly documented policy exception (a
  goodwill credit, a stated promotional rule).
- **L3 — genuine invariant violation with durable value.** A real
  violation is achieved and confirmed durable in an authoritative source
  (a ledger, an admin view, a downstream record) — a double-applied
  discount, a completed action that skipped a required precondition. This
  is the threshold for a reportable finding.
- **L4 — durable or systemic abuse.** The violation is reproducible at
  scale for unbounded value extraction, or it chains into a second class
  (an IDOR revealing whose resource to target, a race condition removing
  the last remaining barrier) to affect other principals.

Calibrate severity separately per [[severity-calibration]] — a violation
enabling unbounded, repeatable financial extraction is typically critical
or high; a one-time, bounded, low-value anomaly is usually medium.

## Validation and False-Positive Discipline

Apply [[closure-discipline]] before recording anything. Class-specific
traps:

- A promotional or goodwill exception explicitly permitted by documented
  policy is not a finding — confirm against stated policy before flagging
  a price, credit, or refund anomaly as abuse.
- A visual-only inconsistency — a client-side total that looks wrong while
  the server recomputes and enforces the correct value — has no durable
  state change and is not a finding.
- An admin-only operation carried out with proper audit logging and
  approval workflow is the control working as intended, not a bypass,
  even if the same action would be a finding if reachable by a normal
  user.
- Durability has to be confirmed in an authoritative source. A value that
  appears changed in a single response but reverts, or was never actually
  persisted, is a proof gap, not a finding — re-read the state from a
  source of truth before recording anything.

## Impact

Direct financial loss through fraud, arbitrage, or over-issuance of
refunds and credits; regulatory or contractual exposure from billing
inaccuracy; denial of inventory or service to legitimate users through
resource exhaustion of a shared quota; and privilege or access retention
beyond what the current account state should permit.

## Summary

Business logic security is domain invariants holding under adversarial
sequencing, timing, and input — not under the happy path the UI enforces.
Start from the invariant and the ledger, not the payload; prove a
violation is both real and durable before treating it as a finding, and
escalate to concurrency or cross-service techniques only once the simpler,
single-request techniques are exhausted.
