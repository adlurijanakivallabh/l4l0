# ReachAgent

A Web/API authorization-and-vulnerability testing agent. ReachAgent targets what
the field still does poorly: **confirmed, multi-hop attack chains that cross
vulnerability classes**, found via a live reachability graph and deterministic
verification instead of LLM judgment.

Full design: [`docs/reachagent-final-plan.md`](docs/reachagent-final-plan.md)
(v1.14, locked). The current GUI execution plan is
[`docs/llm-first-execution-plan.md`](docs/llm-first-execution-plan.md).

## What it does

A **web GUI** (`reachagent-gui`) drives a validated LLM execution plan through
recon → endpoint/insertion-point discovery → custom tagged payloads → optional
signal-gated verification → chains → report. The planner selects only existing
ReachAgent adapters (including nmap, gobuster, feroxbuster, sqlmap, nuclei,
dalfox, commix, and the other catalogued tools) for the target shape and budget.
The orchestrator attempts all 23 supported attack classes; every finding is
written only by the **Validator on a confirmed `run_oracle` verdict** — the LLM
never adjudicates.

You can **talk to the agent** in the chat box during a scan — ask what it has
found, why it made a decision, or steer it; it answers from live scan state and
factors your guidance into its next decision (it can never write a finding). The
report has two clearly-separated tiers: **Confirmed** (oracle-proven, zero false
positives) and **Suspected / Unconfirmed** — tried-but-unproven leads (an oracle
that ran and didn't confirm, or a scanner claim the oracle couldn't re-prove),
surfaced for manual review and never blended with confirmed findings.

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

## Non-negotiable principles

- No `Finding` is written without a `confirmed` result from `run_oracle`. LLM
  judgment proposes candidates; it never writes findings directly.
- Tool access is role-bounded: the Explorer never calls `write_finding`; the
  Coordinator never calls `fire_request` or `run_oracle`; only the Validator
  calls `run_oracle` and `write_finding`.
- External scanner output is advisory only: sqlmap, Nuclei, Dalfox, Commix,
  Nikto, and jwt-tool are signal-gated candidates; ReachAgent's deterministic
  oracle must reconfirm every claim. No ZAP/Burp/Caido scanner is a required
  dependency.
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
  recon/       surface mapping, spec-first API discovery, fact-emitter wrappers,
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
