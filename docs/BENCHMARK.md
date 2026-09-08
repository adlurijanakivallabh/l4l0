# Benchmark

Real numbers from `src/lalo/eval`'s own scoring harness (`recall`,
`precision`, `calibration_gap`, `score_composite`) against all four of this
project's lab targets, run against commit `44d414507d576b83f3346dc06c4960fa7224befd`.

## Methodology

Every case is scored on **recall and precision, never gated** — a finding is
never withheld, blocked, or dropped based on its score; the score is
reported alongside it. This is a deliberate design choice (see CLAUDE.md's
"Confidence, not gates"), and it is worth stating explicitly because at
least one comparable agent's own published benchmark reports a CTF-style
binary win-rate only (challenge solved or not), with no precision/false-
positive measurement at all — a flag-capture format has no "nothing here"
case to score. Recall and precision together measure a strictly harder,
more honest question: not just "did it find something," but "did it find
the right things, and did it also claim things that weren't real."

Two genuinely different kinds of run are reported below, and they are not
comparable to each other:

- **Scoring-harness smoke tests** (VAmPI, crAPI, Juice Shop, DVWA — one
  each): a single, hand-verified, well-known vulnerability is triggered
  with a fully scripted sequence of real HTTP requests against a real
  running container, recorded via the same `record_finding` tool a live
  agent uses, and scored. No LLM is involved. These prove the harness
  itself — `run_case`/`score_composite` reading a real graph produced by a
  real target, not synthetic fixtures — is wired correctly end to end
  against all four targets. They are **not** a measure of autonomous-agent
  capability: recall and precision are 1.0 by construction, because the
  vulnerability was already confirmed by hand before the finding was
  filed. Source: `tests/lalo/test_eval_live_<target>.py`.
- **Genuine autonomous-agent runs** (VAmPI only, so far): a real
  `ScanRunner`/`AgentLoop` run, no scripted request, no hand-picked
  vulnerability — the agent decides what to test and what to file. This is
  the number that actually measures how well L4L0 performs, and it is
  markedly lower than the smoke-test numbers above, which is expected and
  correct. Source: `tests/lalo/test_eval_live_vampi_agent.py`, historical
  results in `docs/eval_history.json`.

crAPI, Juice Shop, and DVWA have no autonomous-agent numbers yet. That run
needs a real, configured LLM provider credential (none was configured in
the environment this benchmark was run in) and is a materially larger
undertaking than scripting one known request per target — extending
`test_eval_live_vampi_agent.py`'s own pattern to the other three targets is
real future work, not silently folded into this pass. Reported here as
"not run," never implied as "clean" or estimated from the smoke-test
numbers above.

## Results

### Scoring-harness smoke tests (real runs, this pass)

| Target | Image | Vulnerability class | Recall | Precision | Calibration gap |
|---|---|---|---|---|---|
| VAmPI | `erev0s/vampi` (pre-existing test, not re-run this pass) | access-control | 1.0 | 1.0 | n/a (1 case) |
| crAPI | OWASP/crAPI v1.1.5, `deploy/docker/docker-compose.yml` | ssrf | 1.0 | 1.0 | n/a (1 case) |
| Juice Shop | `bkimminich/juice-shop@sha256:e68144772eba...f26850a` | sql-injection | 1.0 | 1.0 | n/a (1 case) |
| DVWA | `vulnerables/web-dvwa` | sql-injection | 1.0 | 1.0 | n/a (1 case) |

Each row above is the real, single-case `CompositeScore` produced by
actually bringing the container up, firing the request, scoring the
resulting graph, and tearing the container down immediately after (this
project's own standing "eval targets on-demand only" convention) —
confirmed by running `uv run pytest tests/lalo/test_eval_live_<target>.py
-v -m live` against each one during this pass. `calibration_gap` is `n/a`
for every row because it needs at least one *incorrectly* claimed class to
be meaningful (see `eval/scoring.py`) — a single true-positive smoke case
never exercises it, by design.

Not appended to `docs/eval_history.json`: that file tracks genuine
autonomous-agent performance over time, and a smoke test that is
guaranteed 1.0/1.0 by construction (the vulnerability was hand-confirmed
before the finding was filed) would misleadingly sit alongside real
agent-performance entries with no way to tell them apart at a glance.
`test_eval_live_vampi.py`'s own existing smoke test follows the same
convention — it doesn't call `append_composite_history` either.

### Genuine autonomous-agent runs (historical, from `docs/eval_history.json`)

| Label | Recorded at | Recall | Precision | Case count |
|---|---|---|---|---|
| `vampi-live-agent` | 2026-09-06T13:57:40Z | 0.0 | 0.0 | 1 |
| `vampi-live-agent` | 2026-09-06T14:27:03Z | 0.25 | 1.0 | 1 |

VAmPI's own ground-truth set (`eval/targets.py`) has been corrected TWICE
now, each time by real evidence, not assumption — see that file's own
comment on `VAMPI` for the full account. It was originally recorded here as
`{access-control, sql-injection, jwt, insecure-deserialization}`. **Pass 1**
(prompted by a live run's own results) found `insecure-deserialization` was
never a real VAmPI vulnerability at all (no source connects it to
deserialization), and — based on a web-research pass over the author's own
blog and one independent writeup — also dropped `jwt` as "not one of the
target's documented intended vulnerabilities," landing on
`{access-control, sql-injection, mass-assignment, weak-credentials}`.
**Pass 2** (four independent, detailed, hands-on exploitation writeups
supplied directly by the operator, spanning April 2025 to March 2026, each
showing real commands/payloads/results) found pass 1's `jwt` removal was
itself wrong: all four writeups independently forge a valid JWT against the
real, default `erev0s/vampi` image using a guessed weak secret (most
commonly the literal string `"secret"`) and use it to reach protected/admin
endpoints — one names it explicitly as one of erev0s.com's own documented
vulnerabilities, directly contradicting pass 1's summary of that same
source. The current, twice-corrected set is
`{access-control, sql-injection, mass-assignment, weak-credentials, jwt}` —
five classes. None of the four writeups mention insecure-deserialization at
all, reaffirming pass 1 was right about that half. The target's other two
real, documented issues (a RegexDoS and no rate limiting — confirmed
reproducible in two of the four writeups, not reproducible in a third,
apparently environment-dependent but genuinely real either way) stay
deliberately excluded from ground truth: both need DoS-adjacent request
patterns this project's own mission-prompt discipline treats as opt-in, not
default black-box testing.

The historical numbers below were scored against the ORIGINAL (twice-wrong)
set and are kept as-is rather than retroactively rescored — recomputing
recall for a run that already happened would be indistinguishable from
quietly rewriting history; the correction is the important thing to record,
not a revised number for a run nobody can re-observe. A real run finding
one of the (nominally four, actually partly-wrong) classes with no false
positives is still a genuine signal: a live autonomous run under a hard
15-minute/20-step ceiling found *something* real. These two entries were
produced in an earlier session (not this pass) and are reproduced here
rather than re-run, since the point of a durable history file is exactly
this: not re-deriving the trend on every read.

**Three separate, later live runs (GUI-driven, not the automated
`test_eval_live_vampi_agent.py` harness above — so not appended to
`eval_history.json`, which only ever holds harness-scored entries) are
worth recording in prose here instead**, since they exercised three
different fixes in sequence:

1. After encouraging `spawn_agents` per vulnerability class in the agent's
   own system prompt and raising `max_steps` 25→40: a broad, unrestricted
   mission spawned 3 concurrent children and found 10 findings across 4 of
   the (now correctly) 5 corrected ground-truth classes (`access-control`
   x5, `jwt` x2, `sql-injection` x1, `weak-credentials` x2) — missing only
   `mass-assignment`. Recall against the corrected 5-class set: **0.8
   (4/5)**. (This finding was originally reported against the pass-1 set as
   "a bonus class outside ground truth" at 0.75 recall — pass 2's
   correction reclassifies it as a genuine ground-truth hit, at 0.8.) Real
   cost: ~1.3M input / 71K output tokens, ~21 minutes wall-clock, roughly
   8x the tokens of the single-agent, 25-step run above for that
   improvement — not free, and worth knowing before assuming deeper
   coverage is a pure win with no tradeoff.
2. After also fixing a per-agent step-ceiling gap (spawned children got no
   advance warning as they approached their OWN `max_steps`, independent of
   the shared cross-agent budget, and often failed to comply with the
   single abrupt final-turn cutoff) and a journal-gap resume bug (a
   no-tool-call nudge or a repeat-skip could leave a gap in a per-agent
   journal's key sequence, letting a later resumed step collide with a
   stale entry from an abandoned history): 2 concurrent children found 5
   findings across 3 of 5 classes (`access-control` x3, `mass-assignment`
   x1, `sql-injection` x1); recall 0.6 (3/5).
3. A follow-up re-run of the same broad mission: 2 concurrent children
   found 7 findings across 2 of 5 classes (`access-control` x5,
   `mass-assignment` x1) plus a bonus class outside ground truth
   (`debug-exposure`); recall 0.4 (2/5). **The real point of this run**:
   both spawned children reached `status: "completed"` (not `"failed"`) in
   the GUI's own agent-lifecycle event — one at its exact 40-step ceiling,
   one one step short — and the WHOLE scan reached `status: "completed"`
   (not `unverified_stop`), live-proving the step-ceiling fix actually
   works. A genuinely eventful, non-code incident during this run: a
   child's own JWT-cracking script loaded the ENTIRE seclists wordlist
   collection into memory unbounded, pushing its runtime container to its
   3GB Docker memory limit and exhausting the host's swap — legitimate
   agent behavior (JWT cracking via wordlist is a real technique this
   project's "run/install anything" design intentionally allows), not a
   code bug; killing the specific runaway process (not the whole
   container) let the agent recover gracefully and continue with smaller,
   targeted wordlists instead.

Run-to-run coverage variance here (which classes get found each time) is
expected, not a regression: the agent dynamically chooses which
vulnerability classes to spawn children for, rather than following a fixed
checklist, matching this project's own "the agent decides" design center.

**A 4th change, not yet live-run**: the operator explicitly authorized
destructive/DoS-adjacent testing against this specific disposable
container and asked for full coverage. `test_eval_live_vampi_agent.py`
now scores against `VAMPI_DESTRUCTIVE` (`eval/targets.py`) — the same
5-class set plus `regex-dos` and `rate-limiting`, the two classes real
in the source writeups but excluded from VAmPI's default, non-destructive
ground truth. Its mission now names all 7 classes explicitly and asks for
one spawned agent per class (rather than leaving lane selection fully to
the model, per the "run-to-run variance" paragraph above) specifically to
maximize the odds of full coverage in one run — a genuine trade of some
agent autonomy for completeness, made deliberately for this benchmark
only, not a change to the product's own default mission-prompt discipline.
A new `regex-dos.md` skill was added (opt-in-gated: it refuses to be used
unless the mission explicitly authorizes destructive testing), and
`weak-credentials.md` gained an equivalent opt-in escalation from
"fingerprint rate-limiting with a handful of probes" (the default) to
"send a genuinely large sustained volume" (only once authorized). `40`
steps/agent and a `400`-budget/`1800`s ceiling replace the smaller
values used for the 5-class runs above, since 7 lanes need more headroom
than 3-4 did. This entry will be replaced with real results the next time
this test is actually run.

## Reproducing this

```bash
# VAmPI
docker compose up -d
uv run pytest tests/lalo/test_eval_live_vampi.py -v -m live
docker compose down

# crAPI (needs a local checkout: git clone https://github.com/OWASP/crAPI)
CRAPI_COMPOSE_PATH=/path/to/crAPI/deploy/docker/docker-compose.yml \
  docker compose -f docker-compose.crapi.yml up -d
uv run pytest tests/lalo/test_eval_live_crapi.py -v -m live
CRAPI_COMPOSE_PATH=/path/to/crAPI/deploy/docker/docker-compose.yml \
  docker compose -f docker-compose.crapi.yml down

# Juice Shop
docker compose -f docker-compose.juiceshop.yml up -d
uv run pytest tests/lalo/test_eval_live_juice_shop.py -v -m live
docker compose -f docker-compose.juiceshop.yml down

# DVWA
docker compose -f docker-compose.dvwa.yml up -d
uv run pytest tests/lalo/test_eval_live_dvwa.py -v -m live
docker compose -f docker-compose.dvwa.yml down

# Genuine autonomous-agent run (needs a real LLM provider credential, see
# docs/OPERATING.md) - VAmPI only today:
docker compose up -d
uv run pytest tests/lalo/test_eval_live_vampi_agent.py -v -m live
docker compose down
```
