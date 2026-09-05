# L4L0 — Codebase Map (as-built)

Autonomous web/API + network + cloud offensive-security agent. Package `lalo`
(`src/lalo/`), branch `project-lalo`. Original clean-room code; safety posture and
execution model in `CLAUDE.md`; phase plan in the plans dir.

## Module guide

| Module | Responsibility |
|---|---|
| `core/` | typed errors; shared **secret-redaction** (single source of truth); redacting logger; settings; **multi-provider model router + failover**; provider adapters (`providers.py`, Anthropic) |
| `observability/` | stdlib span/counter tracer scaffold |
| `runtime/` | disposable per-scan Docker container; **host isolation** (no mounts/socket, cap-drop, no-new-privileges); `docker/lalo-runtime.Dockerfile` arsenal image |
| `execution/` | engagement **target model**; **ScopeGuard** (in→allowed / out→skipped / egress-lock→denied / metadata-denied); HTTP/1.1+2 firer + circuit breaker; raw TCP |
| `oast/` | self-hosted HTTP+DNS callback server for blind bugs (per-probe correlation) |
| `agent/` | autonomous think→act→observe **loop**; tool protocol/registry/parser; loop monitor |
| `agents/` | multi-agent **coordinator** (isolated snapshots, merge findings by id), completeness critic, re-hunt |
| `orchestrator/` | durable **journal (checkpoint/resume)**; budget bands; scan scheduler (ASM) |
| `graph/` | reachability + attack-chain graph; byte-verified persistence; chain solver |
| `identity/` | per-identity token store (graph-mirrored sessions); login (json/form); JWT tamper; role matrix |
| `recon/` | runner framework (httpx/subfinder/naabu/katana/nuclei) + JS mining + spec ingestion + orchestrator |
| `payloads/` | tagged corpus + resolver + mutation + OAST substitution |
| `detectors/` | pure analyzers (sqli/xss/lfi/rce/ssti/redirect/oob) + **coverage ledger** |
| `confirmation/` | semantic diff + **non-blocking confidence scoring** (6 components) |
| `exploit/` | automated **fire→detect→score** prober + engine (RCE proof, OOB, chaining) |
| `knowledge/` | skill library (md+frontmatter) + RAG retriever + cross-scan store + `recall` |
| `integrations/` | external MCP (fail-closed cred + allowlist); tool-claim→evidence; CVE enrichment |
| `prompts/` | SYSTEM_PROMPT + mission text + per-role registry (overridable, schema-validated) |
| `scan/` | `run_scan` wiring the agent pipeline; concrete tools (http/run_command/record_finding) |
| `report/` | (planned) deterministic report templates + exporters |
| `eval/` | benchmark cases + recall-first scoring + calibration |
| `gui/` | FastAPI app + cursor-resumable WebSocket event stream + SPA (`lalo-gui`) |

## Data flow (one scan)

`run_scan(targets, objective, router)` → build `Engagement`+`ScopeGuard`+`HttpFirer`
+`ReachGraph` → `AgentLoop` drives the LLM with tools (`http` fires scope-checked
requests capturing bodies by `fire_ref`; `run_command` runs freely in the isolated
container; `record_finding` builds a `Finding`, scores it against captures, stores
it) → findings + transcript returned. Independently, `run_probes(firer, url, param)`
automates fire→detect→score. The GUI streams events live and renders findings by
confidence.

## Conventions
Python 3.13, `uv`, Ruff (+S), `mypy --strict`, pytest (`tests/lalo/`). Every
subsystem imports `core.redaction` (no per-module secret regex). Enums are
`StrEnum` (JSON-ready). New graph node/edge types need justification. Reference
implementations are read for understanding then reimplemented originally (no
reference-project names; see `THIRD_PARTY_NOTICES.md`).

## Verified guarantees (tests, 125 passing)
Host isolation (live Docker) · scope denial-before-socket + rebinding + metadata ·
nothing-withheld confidence scoring + unverifiable-evidence-ships · automated
XSS/SQLi/LFI/RCE/SSTI discovery vs a real server · OAST correlation · durable
crash-resume · multi-agent authoritative-merge isolation · session-graph mirror ·
coverage "not assessed" · GUI WebSocket cursor-resume.
