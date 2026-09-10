---
name: fix-verification-discipline
category: methodology
description: How to re-test a previously reported finding against a claimed fix — ordered verification gates, and when to say the gap is still open rather than confirm a fix that wasn't actually tested
keywords: [fix verification, regression test, remediation, patch verification, re-test]
---

# Fix Verification Discipline

Verifying a fix is a different task from finding a vulnerability, with a
different failure mode: the temptation here is to accept "looks fixed"
(the obvious symptom is gone) instead of actually re-running the original
proof. A fix that suppresses the symptom without closing the underlying
gap is a false negative with a customer's name already on the release
notes — treat every verification with the same "assume it isn't fixed by
default" posture [[closure-discipline]] applies to a brand-new candidate.

## When This Applies

You are given (or you discover) a previously filed finding — your own or
another agent's — plus a claim that it has been remediated: a deployed
patch, a config change, a library upgrade. Your job is to determine
whether the vulnerability the ORIGINAL finding described is actually
closed, using the original evidence as your baseline.

## Verification Gates, in Order

Work through these in order; stop and report `not verified` at the first
gate that fails rather than skipping ahead to a later one.

1. **Re-read the original finding in full** — its `evidence_excerpt`,
   `evidence`, `target`, and `param`. You cannot verify a fix for a bug
   you have not re-read the exact original proof of; a summary or your
   own memory of "a SQLi somewhere in that endpoint" is not enough
   precision to re-test correctly.
2. **Reproduce the ORIGINAL proof exactly first, against the current
   target.** Fire the exact same request (same method, same payload, same
   parameter) the original evidence captured. If it still succeeds, the
   fix does not hold — stop here, do not proceed to variant testing, and
   record `fix_verified: false` with the reproduction as your evidence.
3. **If the original proof no longer succeeds, test at least two
   plausible bypass variants before calling it fixed** — the specific
   variants depend on the vuln class ([[closure-discipline]]'s own
   per-class validation traps are the starting list): a different
   encoding of the same payload, a different parameter carrying the same
   tainted data, a second HTTP method, a case variation on a
   denylist-style fix. A fix that blocks the literal original payload but
   not an equivalent one is not a real fix, and this is the single most
   common way a "verified" fix later turns out not to be.
4. **Read the actual code change if you have source access**
   ([[source-aware-review]] applies here directly) — confirm the fix is a
   real control at the point of use (parameterization, output encoding,
   an allowlist check), not a cosmetic change nearby (a renamed variable,
   an added comment, a check on a sibling code path that does not run on
   the vulnerable one). Record the specific before/after location as a
   `code_locations` entry on the finding.
5. **Confirm no adjacent regression.** A fix narrowly scoped to the exact
   original payload sometimes breaks a legitimate related code path or
   opens a new one (an added allowlist that now over-matches, an added
   try/except that swallows a DIFFERENT error class than intended) — a
   quick check of one adjacent legitimate use case is enough; this is not
   a full re-scan of the surrounding feature.

## The Escape Hatch

If you cannot complete gate 2 or 3 with genuine confidence — the original
reproduction environment is unavailable, you lack the credentials the
original finding used, or a bypass variant is plausible but you ran out
of time to test it — say so explicitly. Do not set `fix_verified: true`
on a guess. Use `record_finding`'s own `fix_verification_notes` field (or
`coverage_ledger` with outcome `needs-follow-up`) to name the specific gap
in your verification, the same honesty [[closure-discipline]]'s own
`open_proof_gap` state requires for a new finding.

## Filing the Result

A fix-verification result is not a new finding type — it is an update to
the EXISTING finding. Call `record_finding` again with the same
`vuln_class`/`target`/`param` (the existing dedup path merges it into the
original node) and set `fix_verified`/`fix_verification_notes`/
`code_locations` on that same call. Never delete or silently supersede the
original finding — a fix that turns out not to hold on a later re-check
needs the original evidence intact to make sense of what changed.

## Summary

Reproduce the original proof first, exactly, before trying anything else —
if it still works, you are done and the fix does not hold. If it doesn't,
test real bypass variants before calling it closed, and read the actual
code change when you can. Say so honestly, via `fix_verification_notes` or
a `needs-follow-up` coverage entry, whenever you cannot complete a gate
with real confidence — a confirmed fix you didn't actually verify is worse
than an honestly incomplete one.
