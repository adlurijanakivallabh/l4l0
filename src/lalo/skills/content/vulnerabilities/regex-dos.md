---
name: regex-dos
category: vulnerability
description: Catastrophic-backtracking regex denial-of-service against input-validation patterns (email/username/format fields) — an explicitly opt-in, mission-authorized-only technique
keywords: [regexdos, redos, catastrophic backtracking, denial of service, regex dos]
---

# Regex Denial-of-Service (ReDoS)

**This technique causes genuine service disruption by design — it is never a
default technique.** Every other skill in this library assumes CLAUDE.md's
standing "non-destructive testing and no-DoS" mission-prompt discipline;
this is the one class where the whole point of a confirmed finding is
proving the target *does* degrade or hang under a crafted input. Only
attempt this when the mission text explicitly authorizes destructive or
DoS-adjacent testing against this specific target — never infer that
authorization from a broad "test everything" mission, and never run it
against a target that isn't already known to be disposable/non-production
(a shared engagement host, or any service other clients might depend on
during the test window, is off-limits regardless of how the mission is
worded). If the mission is silent on destructive testing, treat this class
as out of scope and say so, rather than assuming permission.

## Attack Surface

- Any field validated against a hand-written regex with nested
  quantifiers or ambiguous alternation — email, username, URL, phone
  number, and other "format-looking" input fields are the most common
  offenders, since developers often hand-roll these patterns.
- Both directions matter: a vulnerable pattern used for validation
  (rejecting malformed input) and one used for extraction/matching
  (e.g., log parsing, template rendering) are equally exploitable if the
  backtracking behavior is present.
- A single-threaded or otherwise easily-saturated request-handling model
  (a dev server, a small worker pool) makes the impact of one hung
  request disproportionately larger — note the server/framework in use
  during recon, since it changes expected blast radius.

## Recon

- If source is available, grep for validation regexes and look for the
  classic catastrophic-backtracking shapes: nested quantifiers
  (`(a+)+`, `(a*)*`), overlapping alternation with a shared prefix
  under a quantifier (`(a|a)+`), or a quantified group followed by
  another quantifier over the same character class.
- Without source, black-box fingerprint candidate fields by sending a
  short, clearly benign near-miss input (e.g., a valid-looking email
  missing the final character) and timing the response — a pattern
  susceptible to backtracking often shows a measurable timing curve as
  the near-miss input grows, even before a full hang is attempted.
- Confirm the field is actually regex-validated (not just length-capped
  or type-checked) before investing further — a 400 that arrives
  instantly regardless of input shape is not evidence of a vulnerable
  pattern.

## Techniques (start quiet, escalate only as needed)

1. **Timing-curve probe.** Send a short series of near-miss inputs of
   increasing length (e.g., a run of a repeated character before an
   invalid terminator) and record response time at each length. A flat
   timing curve is a real, informative negative result — stop here,
   this field is not exploitable this way.
2. **Single hang confirmation.** Only once the timing curve shows
   genuine exponential-looking growth, send one crafted payload sized
   to cause a multi-second (not multi-hour) hang, and confirm the
   specific request actually blocks rather than merely being slow for
   an unrelated reason (compare against a concurrent unrelated request
   to the same service — if that ALSO stalls, the impact is broader
   than one endpoint).
3. **Never scale past confirmation.** A single confirmed hang is
   sufficient proof — do not send repeated or larger payloads once
   impact is confirmed; that shifts from "proving a vulnerability
   exists" into an actual, avoidable extended-outage attack, which is
   not the goal even under an explicit DoS-testing mission.

## Proof Ladder

- **L1 — vulnerable pattern suspected.** A timing curve trends upward
  with input length, or source review found a nested-quantifier shape,
  but no hang has actually been produced yet.
- **L2 — a measurable slowdown observed.** A crafted input produces a
  clearly elevated response time (well beyond normal variance) but not
  yet a full hang or timeout.
- **L3 — a genuine hang or timeout confirmed on the live target.** A
  single crafted request causes the target to fail to respond within
  its own normal timeout window, and this is reproduced exactly once to
  confirm it wasn't transient. This is the threshold for a reportable
  finding.
- **L4 — service-wide impact.** The hung request blocks other, unrelated
  requests to the same service (a single-threaded or small-pool
  bottleneck), demonstrating the impact extends beyond the one
  triggering request.

Calibrate severity separately per [[severity-calibration]] — a ReDoS
that blocks the whole service (L4) on a single request is typically
high; one that only ever delays the same request/thread without wider
impact (L3) is usually medium.

## Validation and False-Positive Discipline

Apply [[closure-discipline]] before recording anything. Class-specific
traps:

- A slow response caused by an unrelated backend dependency (a slow
  downstream call, cold-start latency) is not a ReDoS finding — confirm
  the delay scales specifically with the crafted input's length/shape,
  not with unrelated request volume or timing.
- Network jitter alone can look like a timing curve on a small sample —
  repeat the shortest and longest probes a few times each and compare
  medians before concluding a real trend exists.
- Stop at L3 exactly once reproduced; a finding does not get stronger by
  re-triggering the hang repeatedly, and doing so risks a real,
  unnecessary extended outage on the target.

## Impact

Denial of service on the specific endpoint, or on the whole service where
a small worker pool means one hung request starves others — a real
availability impact, not merely a performance nuisance, and the reason
this class stays opt-in rather than default.

## Summary

Prove the pattern is actually vulnerable via a timing curve before ever
sending a payload sized to hang the service, confirm the hang exactly
once, and never escalate volume once confirmed — the goal is evidence of
the flaw, not an extended real outage, even under an explicit
DoS-testing-authorized mission.
