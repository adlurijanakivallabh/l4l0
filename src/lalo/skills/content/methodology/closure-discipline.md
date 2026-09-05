---
name: closure-discipline
category: methodology
description: How to close a candidate — confirmed, ruled out, or an open proof gap — and what does not count as proof of safety
keywords: [closure, confirmed, ruled out, ruled-out, open proof gap, false positive, false negative, counterevidence, evidence]
---

# Closure Discipline

Proving a candidate is real is half the job. Proving a candidate is *not*
real is the other half, and that half is where both false positives and
false negatives come from. This skill governs how you close any candidate —
whether it came from a scan, a spec, a JS bundle, or a hunch — and it applies
regardless of vulnerability class.

## Three Closure States

Every candidate ends in exactly one of these. There is no fourth state, and
"I moved on to something else" is not one of them.

**`confirmed`** — you have a working proof: a fired request/response pair
(or a chain of them) that demonstrates the impact directly, not a theory
about what *would* happen. Record it as a finding with the real evidence
attached — the actual captured request and response, never a paraphrase of
what you believe happened.

**`ruled_out`** — you can name the specific control that makes the surface
safe, at a specific point, and you have checked that the control actually
runs on the attacker's path. "Named control" means you can complete this
sentence with concrete detail: *"This is safe because `<control>` at
`<endpoint/parameter/observed behavior>` `<does what>` before `<the
dangerous effect>`, on every path that reaches it."* If you cannot complete
that sentence with something you actually observed, you are not in
`ruled_out` — you are in `open_proof_gap` and should say so honestly.

**`open_proof_gap`** — the candidate is plausible, you could not confirm it,
and you also could not name a control that rules it out. This is a
legitimate, expected outcome, not a failure. Say so explicitly in your
summary when you finish, and name the specific gap (credentials you did not
have, a service that was not reachable, a precondition you could not set
up) rather than a vague "inconclusive."

The failure mode this exists to prevent: testing something, feeling
uncertain, and quietly moving to the next candidate. That is an
`open_proof_gap` being silently mislabeled as `ruled_out` (or dropped
entirely), and it is how real vulnerabilities get missed.

## What Does NOT Rule Out a Candidate

Each of these is a common, plausible-sounding reason to drop a candidate.
None of them is sufficient on its own.

- **Generic trust in a library or framework feature.** "The framework
  escapes this" / "the ORM parameterizes queries" is not counterevidence
  until you confirm *that specific call*, with *those specific arguments*,
  in *that context*. An HTML escaper does nothing in a JavaScript or
  attribute context; a SQL identifier quoter is not a value quoter.
- **A control on a different path.** A guard on the common route does not
  protect a sibling route, an internal API, a batch job, or an admin alias
  that reaches the same sink. Test the specific path you are evaluating, not
  an analogous one.
- **A control at the wrong time.** Validation before a redirect,
  canonicalization after a path is already used, an ownership check after
  the object was already fetched and returned — these are ordering bugs,
  not controls. Confirm the control actually runs before the dangerous
  effect, not merely somewhere in the flow.
- **A control that can fail open.** A allow-list that is empty by default, a
  hardening flag inside error-swallowing logic, a check the caller can
  override — all leave the candidate alive until you show the fail-open path
  is actually unreachable.
- **A safe sibling.** One correctly-guarded call site says nothing about
  another call site of the same helper. Every reachable instance stands or
  falls on its own evidence.
- **Missing information.** "I could not find a caller," "I could not tell if
  this is deployed," "the service was not reachable" are all
  `open_proof_gap`, never proof of safety. Missing evidence is missing
  evidence, not evidence of absence.
- **Difficulty.** A failed setup, missing credentials, or an unavailable
  dependency is a reason to record a gap and move to the next candidate —
  never a reason to mark the surface clean.
- **"An operator could configure this differently."** What actually ships
  and what is actually reachable is what matters, not a hypothetical
  stricter configuration.
- **Being internal-only or requiring authentication.** This changes
  severity — it does not make a finding unreal. Downgrade it; do not delete
  it.

## What DOES Rule Out a Candidate

- You executed the attack and it demonstrably failed, and you understand
  *why* it failed — not just that you got a generic error or a blocked
  response.
- You can name the control, its location, and show it runs on every
  attacker-reachable path to the sink, before the dangerous effect, with no
  fail-open branch.
- The sink is not actually dangerous in this context, and you can say what
  makes it inert.
- The input is not actually attacker-controlled, and you traced it to a
  trusted origin instead of assuming so.

A negative control makes `ruled_out` far stronger: send the payload that
*should* work if the bug were real and show it is blocked, while a benign
variant still succeeds. That distinguishes "the control works" from "this
path is broken or unreachable for unrelated reasons" — a blocked or errored
response alone is never proof of a working control.

## Before You Record a Finding

Run this pass on every candidate before you file it as `confirmed`:

1. **Argue the other side.** Spend real effort building the strongest case
   that this is *not* exploitable, or less severe than it looks. Look for
   the guard you might have missed, the precondition you assumed without
   checking.
2. **Record what you found**, honestly. If you found a real constraint, say
   what it is and why it does not fully neutralize the finding. If you
   genuinely found nothing, say what you actually checked — "no
   authorization check on this route in either the authenticated or
   unauthenticated case" — never just "none."
3. **Set your confidence honestly.** A working proof against a live target
   is high confidence. A trace you could not execute end to end is at best
   medium, and you must name the specific gap. Do not inflate confidence to
   make a finding look stronger — an honest medium is far more useful to
   the reader than a high that does not survive a second look.
4. **State what would change the severity or confidence** — the one
   concrete piece of evidence that would raise or lower it (e.g.
   "confirmation that this endpoint is reachable without authentication
   would raise this finding's severity").

## Reporting an Unconfirmed Candidate

Dynamic proof is the standard. But when you have strong indirect evidence
(a clear behavioral oracle, a partial extraction, a documented pattern
match) and full end-to-end reproduction is genuinely out of reach — no
credentials, an unreachable internal service — a partial finding is still
worth recording, at honestly lower confidence, with the missing proof named
explicitly.

What is **not** acceptable: a scanner hit with no independent verification,
a "this pattern is usually dangerous" claim with no attempt to trigger it,
or a finding where you never actually identified the attacker-controlled
input. Those are not proof gaps — they are non-findings, and recording them
as findings erodes trust in every other finding in the report.

If you are unsure whether a candidate clears the bar for `confirmed`: it
clears it if you can name the input, the path, and the effect, and you have
a real captured artifact proving all three connect. It does not clear the
bar if any one of those is a guess.
