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

VAmPI's own ground-truth set (`eval/targets.py`) is
`{access-control, sql-injection, jwt, insecure-deserialization}` — four
classes. A real run finding one of them (recall 0.25) with no false
positives (precision 1.0) is a genuine, moderate result for an autonomous
run with no prior knowledge of which four classes were planted, run under
a hard 15-minute/20-step ceiling. These two entries were produced in an
earlier session (not this pass) and are reproduced here rather than
re-run, since the point of a durable history file is exactly this: not
re-deriving the trend on every read.

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
