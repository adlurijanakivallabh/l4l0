# ReachAgent

A Web/API authorization-and-vulnerability testing agent. ReachAgent targets what
the field still does poorly: **confirmed, multi-hop attack chains that cross
vulnerability classes**, found via a live reachability graph and LLM judgment
over real, already-fired request/response evidence.

Full design: [`docs/reachagent-final-plan.md`](docs/reachagent-final-plan.md).
Current architecture (v3 — LLM-Autonomous Recon & Chaining) supersedes the
prior oracle-gate model; see `CLAUDE.md` for the operating principles.

## What it does

A **web GUI** (`reachagent-gui`) drives a validated LLM execution plan through
recon → endpoint/insertion-point discovery → custom tagged payloads → optional
signal-gated verification → chains → report. The planner selects only existing
ReachAgent adapters (including nmap, gobuster, feroxbuster, sqlmap, nuclei,
dalfox, commix, and the other catalogued tools) for the target shape and budget.
The orchestrator attempts all 29 supported attack classes; every finding is
written only by the **Validator**, whose confirmation is an **LLM judgment
over real, already-fired evidence** (`oracles/llm_judgment.py`) — never a raw
tool claim, and never the Explorer/Coordinator roles.

You can **talk to the agent** in the chat box during a scan — ask what it has
found, why it made a decision, or steer it; it answers from live scan state and
factors your guidance into its next decision (it can never write a finding). The
report has two clearly-separated tiers: **Confirmed** (the Validator's judgment
reached over real fired evidence) and **Suspected / Unconfirmed** —
tried-but-unproven leads (a judgment pass that didn't confirm, or a scanner
claim not yet run through judgment), surfaced for manual review and never
blended with confirmed findings. An optional **LLM-authored report** writes the
full narrative end to end (falls back to the deterministic template if it
can't be verified to cover every confirmed finding by ID).

A confirmed auth-bypass (nosqli/ldap) that captures a real session
automatically spawns a synthetic identity and **re-hunts** under it
(attack-path chaining, open-ended and parallel — see the v3 plan), linking any
new finding back via an `enables` edge. An opt-in **aggressive mode**
(`REACHAGENT_AGGRESSIVE`, default off) loosens when signal-gated tools
(nuclei/sqlmap/dalfox) are allowed to fire — every extra claim still only
reaches the confirmed tier through the same judgment path, or lands in
Suspected. A per-host **circuit breaker** opens after repeated transport-level
failures so a dead host can't be hammered. An optional repo path enables
**white-box mode** (SAST/SCA/secrets fused with live testing).

No CLI, no TUI: the GUI is the only entry point (plan v2). No Docker is needed to
run the loop itself; Docker Compose provisions the eval *target* labs only.

## Run

```bash
uv run reachagent-gui --host 127.0.0.1 --port 8000
# open http://127.0.0.1:8000, enter target + in-scope, hit Start scan
```

Configure one server-side provider before starting a scan. For DeepSeek:

```bash
export REACHAGENT_LLM_PROVIDER=deepseek
export REACHAGENT_DEEPSEEK_API_KEY='...'
export REACHAGENT_DEEPSEEK_MODEL=deepseek-chat
```

Named provider configs can be added, tested, and switched from the GUI Settings panel, including custom base URLs and /responses vs /chat/completions endpoint shapes. See 
[`docs/llm-providers.md`](docs/llm-providers.md). A
`config/*-identities.example.yaml` file enables cross-identity classes (BOLA).
Set `REACHAGENT_LLM_API_STYLE=responses` when the selected endpoint uses the
Responses JSON API; Chat Completions remains the default.

## Current principles (v3 — see CLAUDE.md for the full, current list)

- A `Finding` is written only when the Validator's multi-stage confirmation
  pipeline (LLM judgment over real, already-fired evidence) concludes it's
  real — never a single prompt's first impression, never a raw tool claim.
- Tool access is role-bounded: the Explorer never calls `write_finding`; the
  Coordinator never fires requests or writes findings; only the Validator
  runs the confirmation pipeline and calls `write_finding`.
- External tools (Burp Suite Pro MCP, sqlmap, Nuclei, Dalfox, Commix, Nikto,
  jwt-tool) are candidate/evidence sources feeding that pipeline — never
  confirmation authorities on their own.
- Read-only-first: no state-changing request against a live target until the
  read-only case is confirmed safe.
- The scope allowlist is enforced at the execution layer (host/path/port/
  scheme granularity), not just documented.
- The LLM's command-execution sandbox is a contained environment, never the
  operator's own host.

## Layout

```
src/reachagent/
  gui/         FastAPI web GUI + static frontend (primary entry, plan v2)
  scan/        orchestrator (all-class loop) + entrypoint (generic sink loop)
  graph/       reachability graph — nodes, edges, store, persistence, Neo4j seam
  identity/    isolated per-identity session/token store (§10)
  recon/       surface mapping, spec-first API discovery, fact-emitter wrappers,
               live-reasoning proposers (profile / vuln-class / payload)
  payloads/    tagged payload library + vendored corpora, sink-matched lookup (§9)
  oracles/     llm_judgment.py (the live confirmation path); the six legacy
               family modules remain as evidence-shape vocabulary (§7)
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
