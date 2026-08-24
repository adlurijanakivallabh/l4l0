# ReachAgent

A Web/API authorization-and-vulnerability testing agent. ReachAgent targets what
the field still does poorly: **confirmed, multi-hop attack chains that cross
vulnerability classes**, found via a live reachability graph and deterministic
verification instead of LLM judgment.

Full design: [`docs/reachagent-final-plan.md`](docs/reachagent-final-plan.md)
(v1.14, locked). Build plan for the GUI loop: `.claude/plans/gui-llm-driven-plan.md`.

## What it does

A **web GUI** (`reachagent-gui`) drives a four-phase, LLM-assisted pentest loop —
recon → endpoint/insertion-point discovery → tagged-payload firing → report —
across **all attack classes** (the §9 coverage matrix, 22+ classes). The LLM
proposes (which recon profile, which vuln classes to prioritize per endpoint,
which payload to try first, the report narrative); every finding is still written
only by the **Validator on a confirmed `run_oracle` verdict** — the LLM never
adjudicates.

No CLI, no TUI: the GUI is the only entry point (plan v2). No Docker is needed to
run the loop itself; Docker Compose provisions the eval *target* labs only.

## Run

```bash
uv run reachagent-gui --host 127.0.0.1 --port 8000
# open http://127.0.0.1:8000, enter target + in-scope, hit Start scan
```

Optional: `ANTHROPIC_API_KEY` enables the LLM proposers and the LLM report; a
`config/*-identities.example.yaml` file enables cross-identity classes (BOLA).

## Non-negotiable principles

- No `Finding` is written without a `confirmed` result from `run_oracle`. LLM
  judgment proposes candidates; it never writes findings directly.
- Tool access is role-bounded: the Explorer never calls `write_finding`; the
  Coordinator never calls `fire_request` or `run_oracle`; only the Validator
  calls `run_oracle` and `write_finding`.
- No external scanners (sqlmap, Nuclei, ZAP, Burp/Caido Scanner) as detection
  dependencies.
- Read-only-first: no state-changing request against a live target until the
  read-only case is confirmed safe.
- The scope allowlist is enforced at the execution layer, not just documented.

## Layout

```
src/reachagent/
  gui/         FastAPI web GUI + static frontend (primary entry, plan v2)
  scan/        orchestrator (all-class loop) + entrypoint (generic sink loop)
  graph/       reachability graph — nodes, edges, store, persistence, Neo4j seam
  identity/    isolated per-identity session/token store (§10)
  recon/       surface mapping, spec-first API discovery, 26 fact-emitter wrappers,
               live-reasoning proposers (profile / vuln-class / payload)
  payloads/    tagged payload library + vendored corpora, sink-matched lookup (§9)
  oracles/     the six deterministic verification families (§7)
  execution/   scope enforcement + request firing (§10, §12)
  tools/       role-bounded tool manifest — explorer/coordinator/validator (§13)
  mcp/         publishes the tools as an MCP server (§13)
tests/         phase-gate + recon/report/scan/e2e suites (§14, §15)
```

## Stack & commands

Python + [`uv`](https://docs.astral.sh/uv/). Never call `python`/`pip`
directly — always `uv run` / `uv add`.

| Task | Command |
|---|---|
| Lint | `uv run ruff check --fix .` |
| Format | `uv run ruff format .` |
| Security lint | `uv run ruff check --select S .` |
| Type check | `uv run mypy` |
| Test | `uv run pytest` |
| Eval gates | `docker compose up -d` then `uv run python -m reachagent.eval` |
