# Operating L4L0

Short, practical notes for things that exist in the code today but aren't
obvious from the README alone.

## Provider credentials and failover order

`uv run lalo-setup` is the fastest way to get a verified credential in
place — it prompts for a provider, masks the key entry, runs a real
verification call, and writes a `.env` file for you. Skip it and set the
env vars yourself if you prefer.

L4L0 resolves every *configured* provider (whichever of these have a
credential actually set) and tries them in this fixed order until one
succeeds, per completion call:

1. **`opencodex`** — `OPENCODEX_API_KEY` (a local gateway, `http://localhost:10100`
   by default; override with `OPENCODEX_BASE_URL`/`OPENCODEX_MODEL`)
2. **`anthropic`** — `ANTHROPIC_API_KEY` (override the model with `ANTHROPIC_MODEL`)
3. **`openai`** — `OPENAI_API_KEY` (override with `OPENAI_MODEL`)
4. **`gemini`** — `GEMINI_API_KEY` (override with `GEMINI_MODEL`)
5. **`custom`** — any other OpenAI-compatible endpoint: `LALO_CUSTOM_API_KEY` +
   `LALO_CUSTOM_BASE_URL` + `LALO_CUSTOM_MODEL` (all three required)

You don't need to pick one — set as many as you have, and L4L0 fails over
automatically if the first one in the list errors or refuses. The order
above is fixed (local/self-hosted first, then hosted providers) unless you
override it:

```bash
LALO_MODEL="anthropic:claude-opus-5"   # forces anthropic to the FRONT of the
                                        # chain with this specific model,
                                        # only if ANTHROPIC_API_KEY is also set
```

Only a provider with credentials actually present ever appears in the
chain — `LALO_MODEL` naming an unconfigured provider is silently ignored,
not an error.

## Resuming a crashed or stopped scan

A scan's own progress is durably journaled (`journal.jsonl` in its run
directory) as it goes, so a killed process — or one that stopped on its own
(budget exhausted, an unverified stop) — can pick back up exactly where it
left off rather than restarting from scratch.

To resume one: open the **Past Runs** panel in the GUI rail and click
**Resume** next to the run you want to continue. The mission, targets,
exclusions, rules of engagement, and egress-lock setting all come back
from that run's own locked record automatically — you don't retype them,
and the server won't let you accidentally continue it under different
parameters than what it originally started with.

What actually happens on resume: every step the root agent already
completed is replayed straight from the journal (no tool re-fires, no
model call happens for it) until the root's own live loop reaches the
first step it never journaled, then continues from there as a normal
run. A spawned child whose task had already fully finished before the
crash needs no resume at all — its result is already part of the root's
own replayed history, recorded as the single root step that spawned it.
A child that was still genuinely mid-execution when the crash happened
does NOT resume automatically the way the root does — the root's own
not-yet-completed spawn step still re-runs in full on the next live turn.
But `view_agent_graph` now shows that child as `[orphaned]` (durably
detected from the journal, not guessed), and the agent can explicitly
continue it with `spawn_agent`'s `resume_agent_id` argument instead of
starting a new one — the orphan's own original task and every step it
already completed carry forward under its own unchanged agent id, at no
extra LLM cost for the replayed portion. Nothing does this automatically;
an agent that doesn't call `view_agent_graph` after a resume, or chooses
not to resume a shown orphan, gets the old fresh-restart behavior exactly
as before — a deliberate choice, not an oversight, matching this
project's "the agent decides" design center.

Usage accounting under resume no longer double-counts, even in the one
narrow window where it used to: a crash between a step's own LLM call
recording its usage and that same step's tool-dispatch result finishing
its journal write used to mean the redone step's usage landed twice on
resume. `record_usage` now takes the exact same `f"{agent_key}:{step}"`
key the journal itself uses for that step and recomputes the affected
totals from the current set of per-step attempts — a step's second
attempt subtracts its own prior contribution back out before adding the
new one, so only the latest attempt at any given step is ever reflected
in the ledger, however many times a crash forces it to redo.

## Gaps this project intentionally does not close

A few items a comparison against another agent's own architecture might
flag as missing are addressed here once, so they aren't re-proposed as
gaps without a fresh, explicit reason:

- **Finding reconciliation across producers** doesn't apply to L4L0's
  architecture. `dedup_key(vuln_class, target, param)` computed at
  `record_finding` time is the only producer this project has — the
  attribution-leak problem a multi-pipeline architecture (a separate
  dynamic-testing pipeline and a separate static-analysis pipeline, each
  filing its own findings) has to solve with a dedicated reconciliation
  stage never arises here, since there's only ever one producer to begin
  with.
- **GUI authentication** was deliberately removed, not merely never
  built — the server binds to `127.0.0.1` only regardless, and re-adding
  a connection token was explicitly declined by the operator when asked
  directly, specifically to make watching a live scan easier. Don't
  re-propose it without a fresh, explicit ask.

## Pointing a scan at a target on your own machine

The agent's free shell and `http`/`browser` tools run *inside* the
disposable runtime container (Docker's default `bridge` network, not host
networking), so `localhost`/`127.0.0.1` inside that container is the
container itself, not your machine. There's no `host.docker.internal`
convenience name wired up (that's a Docker Desktop feature; this project
targets Linux). To reach something you're running locally (a dev server, a
lab target container you've brought up for eval purposes), use the bridge
network's own gateway address instead of `localhost` — find it with
`docker network inspect bridge | grep Gateway` (commonly `172.17.0.1` on
an unmodified install) — or bind the local service to a real LAN interface
and use that IP as the target.
