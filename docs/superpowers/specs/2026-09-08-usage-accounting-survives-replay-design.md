# Usage Accounting Survives Replay — Design Spec

**Status:** approved for planning (operator's standing autonomy grant
applies — design decisions below are mine, made and recorded).

## Why

The last item from the user's selected shannon-comparison list (after
[[lalo-llm-driven-intake]]'s sub-projects 1-3: LLM-driven intake, the
confined source-reviewer role, and per-child mid-flight resume, all done).
`docs/OPERATING.md` and `src/lalo/core/usage.py`'s own module docstring
already candidly document the exact remaining gap: "a resumed step whose
result is already in the journal is purely replayed (no model call, no
`record_usage`), so it never double-counts. The one real window is a crash
between a step's own LLM call recording its usage and that same step's
tool-dispatch result finishing its journal write: on resume that ONE step
re-runs in full (a genuinely new LLM call), double-recording that single
step's usage." That prior text called this "accepted as-is rather than
built around" — this spec revisits that call now that the user has
explicitly asked for it, and finds a fix narrow enough to be worth doing
without the invasive ledger rework the "accepted" framing was avoiding.

## Where the race actually lives (verified against the real code)

`agent/loop.py`'s `run()` step loop, per step:
1. `response = self._complete(prompt)` — calls the LLM. `_complete()`
   calls `record_usage(...)` immediately once `response` comes back
   successfully, durably persisting that usage to `usage_path`.
2. `call = parse_tool_call(response.text)` — parse the tool call.
3. `entry = journal.run_once(f"{agent_key}:{step}", _dispatch_once)` —
   dispatch the tool and durably journal `(tool, args, observation)` for
   this step.

A crash between step 1 finishing and step 3's journal write finishing
leaves usage recorded for a step whose own journal entry never landed.
On resume, `journal.has(f"{agent_key}:{step}")` is `False` (nothing to
replay), so the WHOLE step re-runs live: a genuinely new completion, a
genuinely new `record_usage()` call — the same logical step now counted
twice in the ledger, even though only one of the two completions'
resulting tool call ever actually shaped the mission.

## Why the obvious "just add a lock" fix doesn't apply

This isn't a concurrency race (no two threads touch the same step
concurrently) — it's a **crash-timing** gap between two separate durable
writes (`usage.json` and `journal.jsonl`) that can never be made atomic
with each other without a shared transaction across two different files,
which is exactly the "Temporal-replay-grade complexity" this project's own
design center rejects. The fix has to accept that both writes can happen,
and make a **second** occurrence of the same step's usage a no-op instead
of an addition.

## Chosen design: recompute-from-attempts via a per-step dedup key

Reuse the *exact* `f"{agent_key}:{step}"` string the journal already uses
for this same step — no new key scheme, no new coordination between
`journal.py` and `usage.py`.

1. `UsageStats` gains one new field: `by_step: dict[str, dict[str, object]]`,
   keyed by that exact string, each value recording the ONE attempt's own
   `provider`/`agent_id`/`input_tokens`/`output_tokens`/`cost_usd`. Every
   existing field (`total_requests`, `total_input_tokens`,
   `total_output_tokens`, `total_cost_usd`, `by_provider`, `by_agent`)
   keeps its exact current shape and meaning — nothing downstream
   (`report/collect.py`, `report/markdown.py`, `report/html.py`,
   `scan.py`'s own before/after usage-delta diffing) needs to change at
   all.
2. `record_usage(..., step_key: str | None = None)` — when `step_key` is
   given and already present in `by_step`, the PRIOR attempt's exact
   recorded delta is subtracted back out of every total/by_provider/
   by_agent field it had contributed to, before the NEW attempt's delta is
   added. The step's `by_step` entry is then overwritten with the new
   attempt's delta. Net effect: only the LATEST attempt at any given step
   is ever reflected in the totals — a step redone once, twice, or any
   number of times after repeated crashes is still counted exactly once.
   `step_key=None` (the default) preserves today's exact behavior — a
   caller that doesn't have step-level granularity to offer stays exactly
   as before this change.
3. `agent/loop.py`'s `run()` computes `step_key = f"{agent_key}:{step}"`
   once per step (using the SAME `agent_key`/`step` already in scope at
   that call site — no new state needed) and threads it through both
   `_complete(prompt, step_key=step_key)` and, on a provider-outage retry,
   `_retry_through_provider_outage(prompt, step_key=step_key)` (so a step
   that succeeds only after an outage retry is still correctly deduped if
   IT later gets redone by an unrelated later crash). `_compact_history`'s
   own `_complete(...)` call is deliberately NOT given a step_key — history
   compaction isn't tied to a journaled mission step and is never replayed
   by the resume mechanism, so a compaction call redone after a crash is a
   legitimately new, separate real completion, not a duplicate of a prior
   one.

## What this does and does not close

**Closes:** the exact documented race — a step whose usage was recorded
but whose journal entry never landed before a crash no longer double-counts
on resume, regardless of how many times it gets redone.

**Deliberately accepted, not silently dropped:** if the SAME step's two
attempts used a genuinely different provider (a mid-outage failover
between the pre-crash and post-crash attempt) or a different `agent_id`
(not possible today — an `AgentLoop`'s `agent_id` is fixed for its whole
`run()` call — named for completeness), the subtract-then-add correction
can leave a `by_provider`/`by_agent` sub-entry sitting at all-zero values
for whichever one no longer has any contributing step (a cosmetic residue,
never a `total_*` correctness issue). Not worth guarding against — cleaning
up an all-zero entry from a JSON dict a report never distinguishes from
"never happened" is speculative complexity for a doubly-narrow edge case
(the already-narrow crash-timing race, further narrowed to only matter
when a provider failover ALSO happened in that exact window).

**Not attempted:** a full ledger rework where `total_*`/`by_provider`/
`by_agent` themselves become computed properties derived from `by_step` on
every read. That would be strictly more "pure," but touches serialization
round-tripping for zero behavior difference over the chosen design — the
subtract-then-add correction produces bit-for-bit the same totals a full
recompute would, with a far smaller diff.

## Testing

- `core/usage.py`: a second `record_usage(...)` call with the SAME
  `step_key` but a different response only counts once in
  `total_requests`/`total_input_tokens`/`total_output_tokens`/
  `total_cost_usd`/`by_provider`/`by_agent`, reflecting the SECOND
  response's numbers, not the sum of both; two DIFFERENT `step_key`s both
  count independently; `step_key=None` preserves today's plain-accumulate
  behavior (regression coverage — no existing test with `step_key`
  omitted may see any behavior change); `to_dict()`/`from_dict()`
  round-trips `by_step`.
- `agent/loop.py`: a real end-to-end scripted resume test — a step's
  completion succeeds and records usage, then a plain `RuntimeError` (no
  need for sub-project 3's `BaseException` workaround: that was only
  needed because `agent/spawn.py`'s own `_spawn` wraps a CHILD's run in
  `except Exception` specifically to keep a crashed child from taking the
  whole scan down; nothing in `agent/loop.py`'s own step loop catches a
  broad exception around the completion call itself, so a plain
  `RuntimeError` genuinely propagates all the way out, matching the
  established root-level crash tests in `test_scan.py`) simulates the
  crash before that step's journal write, then a resumed `run()` call
  against the same journal redoes that step and its usage is still
  counted once, not twice.
