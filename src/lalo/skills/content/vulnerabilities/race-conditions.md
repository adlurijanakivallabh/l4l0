---
name: race-conditions
category: vulnerability
description: Race conditions and TOCTOU — concurrent request synchronization, atomicity gaps, and a per-class proof ladder
keywords: [race condition, toctou, concurrency, double spend, idempotency, time of check time of use]
---

# Race Conditions

Every read-modify-write sequence and every multi-step
check-then-reserve-then-commit workflow is a potential race window.
Treat any such sequence as adversarially concurrent by default — the
question is not whether a race window theoretically exists (it almost
always does at the code level) but whether firing genuinely concurrent
requests actually breaks the workflow's invariant in practice.

## Attack Surface

- Any read-modify-write sequence lacking atomicity or proper row/entity
  locking.
- Multi-step operations with a gap between phases: check, reserve, then
  commit, each a separate request or a separate internal step.
- Cross-service workflows relying on eventual consistency (sagas, async
  jobs, queue-based fan-out).
- Rate limits and quotas enforced only at an edge layer (a gateway
  counter) rather than atomically at the point of consumption.

## Recon

- Look for explicit sequential-sounding operations in the workflow —
  "check balance then deduct," "verify coupon then apply" — these read as
  ordinary code but are exactly where a race window lives.
- Note the presence or absence of optimistic-concurrency markers
  (`ETag`/`If-Match`, a version field, an `updatedAt` check) — their
  presence tells you a control might exist to test against; their absence
  is itself a signal worth testing.
- Examine idempotency-key handling where present: what it is scoped to
  (a path, a principal, both), its TTL, and whether it is persisted
  durably or only cached — a key scoped to path but not principal is a
  distinct, common gap from a key with no scope at all.

## Techniques (start quiet, escalate only as needed)

1. **Baseline single-request behavior.** Establish the correctly-rejected
   or correctly-limited case with one request at a time — this is the
   control your concurrent test will be compared against, and it costs
   nothing to establish first.
2. **Small-N concurrent replay.** Fire 5–20 identical requests for the
   exact same operation as close to simultaneously as the client allows.
   This is the cheapest, least noisy way to reveal a missing atomic check
   — most real races show up at this scale; there is no need to start
   larger.
3. **Connection warming and last-byte synchronization, only if small-N is
   inconclusive.** Pre-establish sessions, cookies, and TLS ahead of time,
   then release the final byte of each request simultaneously to tighten
   the race window — escalate to this precision only when the coarser
   technique did not settle the question either way.
4. **Idempotency-key scope and timing probing.** Reuse the same key across
   different principals or paths if the scope looks inadequate, or fire a
   request before the idempotency store would plausibly have committed the
   prior one — this targets the dedup mechanism itself rather than the
   underlying operation.
5. **Cross-channel and cross-service variants, once a same-channel result
   is settled.** Repeat a confirmed-or-ruled-out race over a different
   channel for the same underlying mutation (REST versus GraphQL versus a
   background job trigger), or probe a saga's compensation step firing
   without the original action having actually succeeded — the underlying
   invariant being violated here is a [[business-logic]] concern; this
   class supplies the concurrency mechanism that breaks it.
6. **Distributed-lock and isolation-level probing, only when the backing
   mechanism is identifiable.** A Redis lock missing `NX`/`EX` or a
   fencing token, or a `READ COMMITTED` isolation level permitting phantom
   reads, are investigation targets once you can actually identify which
   lock or isolation level is in play — not a default step for every race
   test.

## Proof Ladder

- **L1 — race window identified.** An explicit check-then-act sequence or
  the absence of optimistic-concurrency markers is identified, but no
  concurrent request has actually been fired yet.
- **L2 — anomaly observed, no durable effect confirmed.** Concurrent
  firing produces an observable difference (an unexpected response shape,
  an unusual timing pattern) versus the sequential baseline, but no
  durable double-effect has been confirmed in the backing state yet.
- **L3 — durable double-effect confirmed and reproducible.** N concurrent
  requests succeed where exactly one should have, verified against the
  authoritative backing state (a ledger entry, an inventory count, a role
  flag) rather than the HTTP responses alone, and reproducible under a
  second controlled run. This is the threshold for a reportable finding.
- **L4 — durable or systemic exploitation.** The race reproduces reliably
  across multiple independent runs and channels, enables unbounded
  repeatable value extraction (a repeatable double-spend), or affects a
  principal other than the one who triggered it.

Calibrate severity separately per [[severity-calibration]] — a repeatable,
unbounded double-spend on a financial primitive is typically critical; a
single bounded duplicate effect (one extra unit of a rate-limited action)
is usually medium to high depending on what that unit is worth.

## Validation and False-Positive Discipline

Apply [[closure-discipline]] before recording anything. Class-specific
traps:

- A truly idempotent operation enforced via a real, server-verified
  `ETag`/version check or a genuine unique database constraint is a
  control working correctly — confirm you tested against the mechanism
  the server actually enforces, not an optional client-supplied header it
  silently ignores.
- An anomaly that appears once and does not reproduce under a second,
  independently controlled run is noise, not a finding — concurrency
  claims need the same reproducibility standard as any other class.
- A serializable transaction, or a correct advisory lock/queue that
  rejects every concurrent request but one, is the control working as
  designed, not an inconclusive result.
- Multiple HTTP-level successes (several 200 responses) is not itself
  proof of a durable double-effect — the authoritative backing state (the
  ledger, the counter, the inventory table) can disagree with what the
  response bodies claimed, and only the backing state settles the claim.
- A low per-attempt hit rate is not grounds to dismiss a confirmed race —
  if the narrow window can be automated and retried without limit, an
  attacker eventually wins regardless of how unlikely any single attempt
  is. Only dismiss it if something genuinely caps the number of attempts
  available (a hard per-account attempt limit, a cost per attempt that
  makes unbounded retry impractical) — never because the odds look small
  in isolation.

## Impact

Financial loss through double-spend or over-issuance of credits and
refunds; policy and limit bypass (quotas, single-use tokens, seat counts);
data-integrity corruption and inconsistent audit trails; and privilege or
role errors arising from concurrently-processed updates landing in an
unintended order.

## Summary

Concurrency safety has to hold for every state-mutating path, not just the
ones an obvious "race condition" name suggests. Establish the sequential
baseline first, fire the smallest concurrent batch that could reveal the
gap, and confirm any apparent win against the authoritative backing state
before treating it as durable — reproducibility under a second run is what
separates a real race from timing noise.
