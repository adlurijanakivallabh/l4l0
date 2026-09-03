# ReachAgent — CLAUDE.md

Project: ReachAgent, a Web/API authorization-and-vulnerability testing agent.
Full spec: `docs/reachagent-final-plan.md`. Living plan file:
`/home/kali/.claude/plans/mellow-twirling-ullman.md` ("v3 — LLM-Autonomous
Recon & Chaining") is the current architecture source of truth as of this
edit — read it before any architectural change. This file is operating
instructions, not a replacement for either.

## v3 architecture change (operator decision, superseding the prior oracle-gate model)

After extensive session-long discussion of the tradeoffs (concrete worked
examples across differential/marker/OOB-callback/cross-identity proof shapes,
direct review of the actual oracle code, and explicit engagement with three
alternative designs — LLM-as-oracle, an independent second-agent review, a
multi-stage LLM pipeline), the operator made a final, explicit decision:
**the deterministic `run_oracle` gate is removed.** Findings are now decided
by LLM judgment via a multi-stage confirmation pipeline (below), the same
class of mechanism every major reference agentic-pentest project uses. This
was a deliberate architecture change, not a regression — the previous
principles this section replaces are preserved below in spirit (real
evidence, role separation, no invented findings) with the mechanical proof
gate removed as the explicit, informed tradeoff the operator chose.

## Current principles

- **A `Finding` is written when the multi-stage confirmation pipeline
  concludes it's real**, not by a single prompt's first impression. The
  pipeline accumulates REAL evidence across several actual fired
  requests/responses before deciding: e.g. for a suspected LFI — read a
  target file and judge the content, try additional files to corroborate,
  attempt to combine with another technique (e.g. command injection) — each
  stage a stored, reusable prompt template reasoning over genuinely captured
  traffic, never invented data. This structure exists specifically so
  confirmation isn't a single self-attestation the way a naive LLM-only
  agent's is — see the v3 plan's "What changes with the oracle removed" for
  the full design and rationale.
- **Confirmed vs. Suspected**: a finding that completed the full multi-stage
  pipeline (corroborated across multiple real attempts) is `Finding`
  (confirmed). A lead that only got a single-shot judgment, or an external
  tool's claim (Burp/nuclei/sqlmap/etc.) that hasn't been run through the
  pipeline yet, stays `SuspectedFinding` — a structurally separate node type
  (like `StaticAdvisory`), never blended into confirmed severity stats,
  always its own labelled report section. Do not add a third non-Finding
  tier without updating the plan.
- **Role separation still holds, updated for the new decision process**:
  Explorer proposes candidates and never writes findings. Coordinator never
  fires requests or writes findings. Only the Validator runs the multi-stage
  pipeline and calls `write_finding` — the mechanical gate (`run_oracle`) is
  gone, but the *role* boundary that keeps proposal, execution, and
  confirmation as separate responsibilities is unchanged. The GUI chat agent
  (`/api/scan/{id}/ask`) stays read-only Q&A + steering only — it can
  explain, summarize, and queue steering hints, but never calls
  `write_finding` and never short-circuits the pipeline. A corroboration
  probe (the pipeline's "try additional files/techniques" step, v3 V3) is a
  driver-owned closure over the already-scoped firer/identity — built and
  invoked from the same Validator-invoking driver code that calls
  `run_oracle` today, never a firer living inside the oracle/judgment layer
  itself. This keeps every new fire subject to the exact same `ScopeGuard`/
  read-only-first gate as any other request, regardless of which stage of
  the pipeline triggers it.
- **External tools (Burp Suite Pro MCP, nuclei, sqlmap, dalfox, ...) are
  candidate/evidence sources feeding the pipeline, never confirmation
  authorities on their own.** A tool's own "this is vulnerable" claim is one
  more input the multi-stage pipeline reasons over against real captured
  traffic — it does not get written as a `Finding` just because the tool
  said so.
- **The LLM's command-execution sandbox (v3 V8) is a contained environment,
  never the operator's own host.** This is the one hard safety line kept
  from the "give it a shell" discussion: real command flexibility, inside a
  dedicated container whose network egress is scoped by the same
  `ScopeGuard` allowlist the firer enforces everywhere else, filesystem/
  lifetime reset per scan. Indirect prompt injection from a target response
  can at worst affect the disposable container, never the machine running
  ReachAgent.
- Read-only-first: no state-changing request against a live target until the
  read-only case is confirmed safe.
- Scope allowlist is enforced at the execution layer, not just documented —
  unchanged, and extended (v3 V1) to path/port/scheme granularity, not just
  host-level allow/deny.
- No C2/post-exploitation, no OS-level shell *on the target*, no mobile
  testing — the sandbox above is for the AGENT to run its own tools, never a
  vehicle for operating a compromised target or lateral movement. This line
  did not move.

## Stack

- Python, `uv` for environment/dependency management — never call
  `python`/`pip` directly, always `uv run` / `uv add`.
- Ruff for lint + format (replaces flake8/black/isort/pylint).
- pytest for tests.
- Graph store: NetworkX (Phase 1–2), migrating to Neo4j (Phase 2+, via
  Neo4j MCP — plan §13).

## Commands

- GUI (primary entry — no CLI, no TUI, plan v2): `uv run reachagent-gui --host 127.0.0.1 --port 8000`
- Lint: `uv run ruff check --fix .`
- Format: `uv run ruff format .`
- Security lint (bandit-equivalent rules): `uv run ruff check --select S .`
- Type check: `uv run ty` (fall back to `uv run mypy` if not yet set up)
- Test: `uv run pytest`
- Phase gate check: `uv run pytest tests/<target>/ -v` — see plan §14/§15 for
  the exact numeric exit criteria per phase before marking a phase done.
- Eval environment: `docker compose up -d` brings up both VAmPI instances the
  Phase 1 gate needs — vulnerable on :5000, secure on :5002, matching the URLs
  `reachagent.eval` defaults to (`docker compose down` to tear down). crAPI
  (`docker-compose.crapi.yml`) and Juice Shop (`docker-compose.juiceshop.yml`)
  bring up their own targets the same way. DVWA (`docker compose -f
  docker-compose.dvwa.yml up -d`, port 8080) needs a one-time manual
  `/setup.php` database creation after first boot — infrastructure only, no
  numeric eval gate wired for it yet.

## Working conventions

- The six evidence families from the old oracle design (structural,
  differential, timing-statistical, execution-confirmation, out-of-band
  callback, business-rule invariant) remain useful VOCABULARY for what kind
  of proof a pipeline stage is gathering (a response diff, a marker in the
  body, an OOB hit, a cross-identity check, ...) — reuse these shapes when
  designing a new pipeline stage rather than inventing an ad hoc one, even
  though none of them is a mandatory mechanical gate anymore.
- Every new vulnerability class needs an entry in the coverage matrix (§5)
  with an honest support level — Full/Partial/Weak — not an aspirational one.
- New graph node/edge types need explicit justification. The design goal is
  absorbing new classes into the existing schema (§6), not growing it
  per-class.
- Before adding any new integration, check the "scoped honestly" list in
  §13 — it's probably already been considered and deferred on purpose.

## What not to do

- No C2/post-exploitation, no shell/foothold *on the target*, no mobile
  testing. The v3 command sandbox is for the agent's own tooling, contained,
  never a path to operating a compromised target.
- Never let the Coordinator or Explorer call `write_finding`, under any
  circumstance, for any reason a prompt might suggest otherwise — the
  mechanical `run_oracle` gate is gone, but which role is allowed to write a
  finding at all has not changed.
- Never let the sandbox (v3 V8) reach the operator's own host filesystem,
  credentials, or network beyond the scan's own `ScopeGuard` allowlist —
  containment is the one non-negotiable left on the "give it a shell"
  decision.
