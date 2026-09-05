# L4L0 — CLAUDE.md

Project: **L4L0** (package `lalo`) — an autonomous agentic offensive-security
agent for web/API + network/infra + cloud + binary targets. Mission-prompt
driven: you point it at an authorized engagement and give it an objective; it
runs an autonomous think→act→observe loop, freely running or installing any tool
it needs inside a disposable container, and reports everything it finds with
honest, non-blocking confidence scores.

This is a from-scratch successor to the prior ReachAgent codebase. **No prior
ReachAgent code is used.** Studied reference agents informed the design but their
code is not copied (see `THIRD_PARTY_NOTICES.md` for the clean-room policy and the
AGPL/proprietary reasons behind it).

- Architecture / execution plan: `/home/kali/.claude/plans/snuggly-wibbling-ember.md`
  (the numbered 0–18 phase plan) and `docs/CODEBASE_MAP.md` (auto-generated
  as-built map; regenerate via the `cartographer` skill when the code drifts).
- This file is operating instructions, not a replacement for either.

## Execution model (the design center)

A hierarchical agent loop: a root agent takes the mission and spawns specialist
sub-agents; each agent has a flat, powerful toolset centered on a **free shell**
(`run_command` — runs/installs anything) plus `http` (multi-protocol firer),
`browser`, `spawn_agent`, `record_finding`, `poll_oast`, `query_graph`/`note`,
and `recall` (RAG over the skill library + past findings). The LLM drives; a
durable orchestrator checkpoints every step so a crashed scan resumes exactly.

## Safety posture (the whole of it — stated once)

The agent runs/installs **anything** — no command/tool allowlist, no per-action
gate, no confirmation gate on findings, and **no network-egress cage by default**.
The mechanical guarantees, and the only hard lines, are:

1. **Host isolation.** Every scan runs in a disposable container with
   `CapDrop:[ALL]` + minimal caps, **no host mounts, no Docker socket, non-root**.
   A malicious target response (or a bad tool install) can only dirty the
   throwaway container — never the operator's host, credentials, or daemon. This
   line does not move.
2. **Operator-declared targets.** L4L0 tests the engagement the operator
   specifies. This is target *definition*, not a cage: the structured
   `http`/`network`/`cloud` tools carry a soft in-engagement check, the free shell
   is prompt-scoped, and an **optional egress-lock toggle** is available for
   cautious runs (off by default). L4L0 does not autonomously attack hosts the
   operator never named; there is no "no-target, hit-anything" mode.

Everything else offensive **within the declared engagement is in scope**: full
exploitation, RCE (command injection / SSTI / deserialization / file-upload /
SSRF-to-internal → prove by running a benign command on the target), exploit
chaining, multi-host chaining across the engagement, network service
exploitation, cloud IAM/storage/K8s/serverless assessment, binary/pwn to prove
memory-corruption RCE, and read-only Active Directory/LDAP mapping.

Non-destructive testing and no-DoS are **prompt-guided** (mission-prompt
discipline), not mechanically blocked — impact is demonstrated by reading/proving,
not by breaking.

**Not built into the autonomous agent:** persistence / C2 / lateral-movement
infrastructure, and Active Directory *offensive* post-exploitation tradecraft
(DCSync, golden tickets, kerberoast→lateral). Read-only AD *mapping* is built;
weaponizing it into credential theft or lateral movement is not.

## Confidence, not gates

There is no oracle/confirmation gate and nothing is withheld from the report.
Every fired candidate that trips a detector becomes a `Finding` immediately, with
a deterministic, auditable **Confidence Score (0–100)** and a component breakdown
(reproducibility, corroboration count, specificity, cross-context reproduction,
chained-impact success, evidence-provenance match). Unverifiable evidence *lowers*
the score and is flagged, never dropped. The LLM describes findings and proposes
corroboration probes; it is never the sole arbiter of whether something is
reported.

## Stack

- Python 3.13+, `uv` for env/deps — never call `python`/`pip` directly; always
  `uv run` / `uv add`.
- Ruff for lint + format (`S` = bandit-equivalent security rules on).
- `ty`/mypy (strict) for types. pytest for tests.
- Package lives at `src/lalo/`; tests at `tests/lalo/`.

## Commands

- Lint: `uv run ruff check src/lalo tests/lalo`
- Format: `uv run ruff format src/lalo tests/lalo`
- Type check: `uv run mypy`
- Test: `uv run pytest` (defaults to `tests/lalo`)
- Eval targets: bring up a target container **only** for a live run
  (`docker compose ...`), tear it down immediately after — never leave one idle.

## Working conventions

- **Clean-room / original code.** Read reference agents to understand a pattern,
  then implement it originally. No reference-project names in code, comments, docs,
  module names, or commit messages. No copied source (legal — see
  `THIRD_PARTY_NOTICES.md`).
- **Best-in-class tools.** When tools are interchangeable, pick the objectively
  strongest current one and say why (feroxbuster over dirb/gobuster, etc.). The
  arsenal is a curated starting image; the agent can install anything else at
  runtime.
- **Honest coverage.** A surface that wasn't tested reads "not assessed," never
  "clean." Coverage is machine-observed, not asserted.
- **Commit per phase.** Each completed phase is implemented → reviewed
  (`pr-review-toolkit`) → tests green → live-eval where applicable → map refresh
  (`cartographer`) → committed.
- **Test discipline.** Run only the tests related to a change by default; reserve
  full runs for phase-gate/release moments. Non-trivial logic leaves a runnable
  check behind.

## What not to do

- Never build persistence / C2 / lateral-movement infrastructure, or AD offensive
  post-exploitation (DCSync / golden tickets / kerberoast→lateral). Read-only AD
  mapping only.
- Never let the disposable container reach the host filesystem, host credentials,
  or the Docker daemon — host isolation is the one non-negotiable mechanical line.
- Never add a "no-target, attack-anything" mode; L4L0 tests operator-declared
  engagements.
- Never copy reference-project source or use their names anywhere; never introduce
  an AGPL/copyleft-contaminating dependency without an explicit relicensing decision.
