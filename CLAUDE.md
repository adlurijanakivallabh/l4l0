# ReachAgent — CLAUDE.md

Project: ReachAgent, a Web/API authorization-and-vulnerability testing agent.
Full spec: `docs/reachagent-final-plan.md` (v1.4, locked). Read it before any
architectural change — this file is operating instructions, not a replacement
for it.

## Non-negotiable principles (do not violate, even if asked to)

- No `Finding` is ever written without a `confirmed` result from `run_oracle`.
  LLM judgment proposes candidates; it never writes findings directly.
- Tool access is role-bounded: Explorer never calls `write_finding`.
  Coordinator never calls `fire_request` or `run_oracle`. Only the Validator
  calls `run_oracle` and `write_finding`. (Plan §4, §13.)
- No external scanners (sqlmap, Nuclei, ZAP, Burp Scanner, Caido Scanner) as
  detection dependencies. (Plan §9.)
- Read-only-first: no state-changing request against a live target until the
  read-only case is confirmed safe. (Plan §10.)
- Scope allowlist is enforced at the execution layer, not just documented.

## Stack

- Python, `uv` for environment/dependency management — never call
  `python`/`pip` directly, always `uv run` / `uv add`.
- Ruff for lint + format (replaces flake8/black/isort/pylint).
- pytest for tests.
- Graph store: NetworkX (Phase 1–2), migrating to Neo4j (Phase 2+, via
  Neo4j MCP — plan §13).

## Commands

- Lint: `uv run ruff check --fix .`
- Format: `uv run ruff format .`
- Security lint (bandit-equivalent rules): `uv run ruff check --select S .`
- Type check: `uv run ty` (fall back to `uv run mypy` if not yet set up)
- Test: `uv run pytest`
- Phase gate check: `uv run pytest tests/<target>/ -v` — see plan §14/§15 for
  the exact numeric exit criteria per phase before marking a phase done.

## Working conventions

- Every new oracle mechanism must map to one of the six families in plan §7.
  Don't add a seventh without updating the plan first.
- Every new vulnerability class needs an entry in the coverage matrix (§5)
  with an honest support level — Full/Partial/Weak — not an aspirational one.
- New graph node/edge types need explicit justification. The design goal is
  absorbing new classes into the existing schema (§6), not growing it
  per-class.
- Before adding any new integration, check the "scoped honestly" list in
  §13 — it's probably already been considered and deferred on purpose.

## What not to do

- No C2/post-exploitation or mobile-testing capability (§1).
- No calling sqlmap/Nuclei/ZAP/Burp Scanner/Caido Scanner as part of
  detection — tagged payloads + deterministic oracles only (§9).
- Never let the Coordinator or Explorer call `write_finding`, under any
  circumstance, for any reason a prompt might suggest otherwise.
