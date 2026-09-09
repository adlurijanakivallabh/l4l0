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
2. **`musespark`** — `MUSE_SPARK_API_KEY` (a hosted gateway speaking the OpenAI
   Responses API, not Chat Completions — override with
   `MUSE_SPARK_BASE_URL`/`MUSE_SPARK_MODEL`)
3. **`anthropic`** — `ANTHROPIC_API_KEY` (override the model with `ANTHROPIC_MODEL`)
4. **`bedrock_anthropic`** — `AWS_BEARER_TOKEN_BEDROCK` (an Amazon Bedrock API
   key/bearer token from the Bedrock console, not an IAM secret key — reaches
   Claude via Bedrock's `/anthropic/v1/messages` route, no AWS SigV4 signing
   needed; override with `LALO_BEDROCK_BASE_URL`/`LALO_BEDROCK_MODEL`)
5. **`openai`** — `OPENAI_API_KEY` (override with `OPENAI_MODEL`)
6. **`gemini`** — `GEMINI_API_KEY` (override with `GEMINI_MODEL`)
7. **`xai`** — `XAI_API_KEY` (Grok, override with `XAI_MODEL`)
8. **`custom`** — any other OpenAI-compatible endpoint: `LALO_CUSTOM_API_KEY` +
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

**Resuming a run that already finished cleanly is a pure no-op**, not a
wasted re-run: if the run directory already holds a report whose own
manifest (`report_manifest.json`, a per-format SHA-256 digest) still
verifies against the files on disk, the resumed run adopts that report
directly — no fresh mission turn, no re-running confidence/adversarial
review for every already-reviewed finding, no report rewrite. The GUI's
Resume button says "Resume (already finished)" for exactly this case, so
it's clear in advance that clicking it won't redo any real work.

**Every operational tuning knob is adjustable on resume, not just on a
fresh launch** — `max_steps`/`spawn_max_depth`/`budget_ceiling`/
`cost_limit_usd`/`max_duration_s`/`redact_findings`/
`fail_on_unreachable_targets`/`enable_second_opinion_review` all read from
whatever you set in the advanced-options panel (or the request body) at
resume time, not from the original run. This is the whole point of
`cost_limit_usd`/`max_duration_s` being resumable at all: a scan that hit
a $5 cost ceiling can be resumed with a raised (or removed) one instead of
being permanently stuck. Only the engagement's own locked fields —
mission, targets, exclusions, rules of engagement, egress-lock — stay
pinned to the original run and can't be changed on resume.

## Cost and wall-clock ceilings

Two opt-in ceilings exist alongside the older `max_steps`/`budget_ceiling`
(turn-count) knobs, both off (unbounded) by default:

- **Cost limit (USD)** (`cost_limit_usd`) — a hard-dollar ceiling compared
  against the SAME lifetime usage ledger real completions already record
  to. Meaningless unless usage recording is active, which the GUI's own
  scan-launch path already opts into automatically.
- **Max duration (seconds)** (`max_duration_s`) — a wall-clock ceiling,
  checked the same cooperative way a manual stop is, independent of how
  many steps a scan has actually used (a mission spending most of its
  steps on slow network waits can otherwise run a long time while
  technically still "within budget").

Both are set from the GUI's Advanced Options panel (or the `/scan`
request body directly) and are visible there on every launch, including a
resume — see above.

## The narrative log

Every run's raw event stream (`events.jsonl`) is also rendered once, at
scan completion, into a plaintext `narrative.log` — one line per event,
prefixed with the real agent that did it (`[agent-3] tool_call: http GET
https://...`), not just the display name `"root"`. It's meant to actually
be read top to bottom, unlike the raw JSON stream. Find it as a separate
"Narrative" link next to each run's "Report" link in the GUI's Past Runs
panel, or fetch it directly at `/runs/{run_id}/report/narrative`.

## Debugging a failed run's container

By default the disposable per-scan container is removed the moment a scan
stops, success or failure alike. Set `keep_on_failure=True` on
`RuntimeConfig` (a Python-API-only knob today, not GUI-exposed) to skip
that removal specifically when the run being torn down actually raised —
a successful run is always removed exactly as before regardless of this
flag. When it fires, the log names the real container so you can inspect
it (`docker logs <name>`) and remove it yourself (`docker rm -f <name>`)
when you're done.

## Login flows that email a code instead of returning one

A target whose second factor (or only login mechanism) is an emailed
one-time code or magic link — rather than something returned directly in
the HTTP response — has its own tool: `fetch_email_code` connects to a
pre-configured IMAP mailbox (`EmailAccount`: address/password/imap_host,
Python-API-only today, not GUI-exposed), reads the most recent message
matching an optional subject/sender filter, and extracts a code or URL via
your own regex. Configure it the same way `identities`/`login_schemes`
already are — as a `ScanConfig.email_accounts` entry — and the agent can
call it directly whenever a login flow needs it.

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
container itself, not your machine. Every sandbox is started with
`--add-host host.docker.internal:host-gateway`, so `host.docker.internal`
reaches your machine from inside the container — this is a native Docker
Engine 20.10+ feature on Linux, not a Docker-Desktop-only convenience, so
it's wired up unconditionally rather than left as a manual lookup. Point a
target at `host.docker.internal` (a dev server, a lab target container
you've brought up for eval purposes) instead of `localhost`.

Any custom entry already in your own `/etc/hosts` (a lab DNS name, your
machine's own hostname) is also forwarded into the sandbox automatically as
its own `--add-host`, so a target you can already reach by name on your own
machine is reachable by that same name from inside the container too — no
extra step needed. Set `forward_etc_hosts=False` on `RuntimeConfig` to turn
this off if a specific entry ever causes a problem.
