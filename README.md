# ReachAgent

A Web/API authorization-and-vulnerability testing agent. ReachAgent targets what
the field still does poorly: **confirmed, multi-hop attack chains that cross
vulnerability classes**, found via a live reachability graph and deterministic
verification instead of LLM judgment.

Full design: [`docs/reachagent-final-plan.md`](docs/reachagent-final-plan.md)
(v1.4, locked). Read it before any architectural change.

## Status

Phase 1 — Foundation (plan §15). This tree is **scaffolding only**: directory
layout, packaging, and module stubs matching the §13 tool manifest. No detection
or verification logic is implemented yet.

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
  graph/       reachability graph — nodes, edges, store (§6)
  identity/    isolated per-identity session/token store (§10)
  recon/       surface mapping into the structural graph (§3)
  payloads/    tagged payload library, sink-matched lookup (§9)
  oracles/     the six deterministic verification families (§7)
  execution/   scope enforcement + request firing (§10, §12)
  tools/       role-bounded tool manifest — explorer/coordinator/validator (§13)
  mcp/         publishes the tools as an MCP server (§13)
tests/
  phase1/      phase-gate tests (§14, §15)
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
| Phase gate | `uv run pytest tests/phase1/ -v` |
