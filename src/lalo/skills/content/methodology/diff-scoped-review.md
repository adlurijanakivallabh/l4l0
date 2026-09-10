---
name: diff-scoped-review
category: methodology
description: Incremental, diff-scoped source review — prioritizing what actually changed since a known-good baseline, for a CI/PR-triggered or re-engagement scan
keywords: [diff review, incremental scan, pull request review, changed files, regression scope]
---

# Diff-Scoped Review

[[source-aware-review]] covers reviewing source code in general; this
skill covers the DISTINCT situation where a known-good baseline exists
(a prior scan's own findings/coverage, or a specific commit/tag) and the
actual task is to prioritize what CHANGED since then, rather than
re-reviewing the entire codebase from scratch every time.

## When This Applies

A mission explicitly scopes you to a diff (a specific commit range, a
pull request, "changes since the last scan"), or a prior scan's own
`baseline`/`coverage_ledger` entries are available for the same target
identity and a re-engagement's real value is in what's new, not
re-confirming what a prior pass already covered.

## Method

1. **Establish the actual diff** — the specific commit range or file set
   that changed, via `run_command` (`git diff --name-only <base>..<head>`
   or equivalent) rather than assuming from a PR description alone,
   which can understate scope (a generated lockfile change, a config
   touched incidentally by a broader refactor).
2. **Read the prior baseline first**, if one exists — call `baseline`
   (action=get) for this target's identity, and `coverage_ledger`
   (action=list) for what a prior pass already tested and its outcome.
   Never re-derive from scratch what a trustworthy prior pass already
   established; extend it.
3. **Prioritize changed files by risk shape**: a change touching
   authentication/authorization logic, an input-handling boundary, a
   dependency version bump, or a new endpoint/route is high priority
   regardless of diff size; a change confined to styling, a comment, or
   test-only code is low priority — apply [[source-aware-review]]'s own
   "production code vs. test fixture" and "git-tracked vs. untracked"
   filters to each changed file before spending time tracing it.
4. **Re-test any FINDING from the prior baseline whose code path was
   touched by the diff** — a fix, a refactor, or an unrelated change near
   a previously-reported finding's location all warrant a
   [[fix-verification-discipline]] pass even if the diff wasn't intended
   to be a fix.
5. **File new findings and coverage entries exactly as any other scan
   would** — a diff-scoped scan produces the same `record_finding`/
   `coverage_ledger` output shape as a full scan; only the SELECTION of
   what to spend time on is different.

## Validation and False-Positive Discipline

Apply [[closure-discipline]] to every new candidate exactly as in a full
scan — diff-scoping changes what you prioritize looking at, never how
rigorously you validate what you find. A file appearing in the diff
purely due to a mechanical reformat (confirm via the actual diff content,
not just the file being listed) needs no security review at all.

## Summary

Read the prior baseline and coverage ledger before doing any new work,
establish the real diff via the actual git history rather than a
description, and prioritize by risk shape rather than treating every
changed line equally — but validate anything found with the exact same
rigor a full scan would.
