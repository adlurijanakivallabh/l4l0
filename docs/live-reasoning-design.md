# Live-Reasoning Recon Tuning — Three-Layer Propose / Validate / Execute

**Status:** Three layers + recon profiles built. This document is the safety
contract for live-reasoning proposal-only tuning: `live_tuning.py` (recon
wordlist/flags + 6 `RECON_PROFILES`), `vuln_tuning.py` (vuln classes per
endpoint shape), and `payload_tuning.py` (payload choice from existing library)
— all Anthropic-only, allowlist-validated, flag-gated. No oracle, firing, or
role-boundary code is bypassed; all extensions are proposal-only with
fixed-code validation and existing `fire_request`/`run_oracle`/`Validator`
execution.

## 0. Reference posture

All five references were cloned to `~/Downloads/references/{pentagi,cai,hexstrike-ai,PentestGPT,claude-bug-bounty}`
and each project's LICENSE stated before browse:

- **pentagi** — MIT `Copyright (c) 2025 PentAGI Development Team`
- **cai** — dual: `src/cai/agents` MIT (from openai/openai-agents-python), `src/cai` proprietary research-use-only `Copyright (c) 2025 Alias Robotics S.L.` (commercial use prohibited)
- **hexstrike-ai** — MIT `Copyright (c) 2026 Muhammad Osama (0x4m4)`
- **PentestGPT** — MIT `Copyright (c) 2023 Grey_D` (`LICENSE.md`)
- **claude-bug-bounty** — MIT `Copyright (c) 2026 Claude Bug Bounty Hunter Contributors`

Paraphrase only, no verbatim paste without attribution. Techniques absorbed as
generic enumeration/payload/oracle/chaining ideas, not per-target hardcode.
PentAGI is the primary reference (user assessment: closest match).

## 1. Three-layer model (this task and future)

```
Target signals (headers, tech hint, initial page)
        │
        ▼
┌─────────────────────┐
│ 1. Claude PROPOSES  │  live_tuning.propose_recon_tuning(signals) -> ReconTuningChoice
│   (thin client)     │  LLM picks FROM allowlist, not freeform shell
└─────────┬───────────┘
          │ raw proposal dict {wordlist_path, flags, filter_codes}
          ▼
┌─────────────────────┐
│ 2. Fixed code       │  allowlist membership in live_tuning._validate_choice()
│    VALIDATES        │  + second check in GobusterRunner.command() (defense in depth)
│                     │  outside allowlist → safe default + log why
│                     │  API error/timeout/missing key → safe default
└─────────┬───────────┘
          │ validated ReconTuningChoice (all fields allowlisted)
          ▼
┌─────────────────────┐
│ 3. Existing tools   │  ReconToolRunner fires gobuster with chosen safe config
│    EXECUTE +        │  → writes ONLY Host/Endpoint + resolves_to facts
│    CONFIRM unchanged│  → Explorer fingerprint → get_payloads → fire_request/
│                     │     fire_browser → run_oracle (six families) → is_violation
│                     │     → Validator.write_finding (role-bounded, §4)
└─────────────────────┘
```

At no point does the live call get to write a Finding, call `run_oracle`,
bypass the Validator, or invent a payload string. Blast radius is capped at
**which safe wordlist/flags/status filter the recon tool runs with** (this
task) and, in future, **which existing tagged payload to try first** — never
"this is confirmed vulnerable".

Why this ordering matters: references that trust model output more directly
would violate the CLAUDE.md non-negotiable "No Finding without confirmed
run_oracle" if applied here. The allowlist is intentional, not oversight.

## 2. Allowlist — the safety boundary

`RECON_ALLOWLIST` in `src/reachagent/recon/live_tuning.py` is the single
source of truth. Nothing outside it can be selected, even if the model
invents it.

- **wordlists** (7 safe on-disk paths, read-only):
  `/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt`,
  `/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt`,
  `/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt`,
  `/usr/share/wordlists/dirb/common.txt`,
  `/usr/share/seclists/Discovery/Web-Content/CMS/wordpress.fuzz.txt`,
  `/usr/share/seclists/Discovery/Web-Content/api/api-seen-in-wild.txt`,
  `/usr/share/seclists/Discovery/Web-Content/common.txt`.
  Safe default is `dirb/common.txt`.
- **flag_presets** (5 safe argv fragments appended after `gobuster dir -q -u <target> -w <wordlist>`):
  `()`, `(-t 20)`, `(-t 50)`, `(--timeout 10s)`, `(-t 20 --timeout 10s)`.
  No shell, no extra binary, no arbitrary flag.
- **status_codes** (3 safe filter sets):
  `200,204,301,302,307,401,403`, `200,301,302`, `200,204,301,302,307`.

Validation is two-layer: `propose_recon_tuning` calls `_validate_choice`
first, then `GobusterRunner.command()` re-checks the returned
`ReconTuningChoice` against the same allowlist before building the argv.
Any mismatch at either layer falls back to the safe default and logs why.
`command()` also validates that the target is a distinct list element
(`shell=False` in the base runner) so the wordlist path is never an
injection surface.

Flag-gated, default OFF: `REACHAGENT_GOBUSTER_LIVE_TUNING=1` or
`REACHAGENT_RECON_LIVE_TUNING=1` enables the live path. Default OFF means
zero regression — `preferred_wordlist("REACHAGENT_GOBUSTER_WORDLIST")`
and env `REACHAGENT_GOBUSTER_THREADS`/`TIMEOUT` behavior is unchanged.
Signals are collected by `_collect_signals(target)` via a 5 s best-effort
`httpx.get` for `server`/`x-powered-by` plus body hints
(`wp-content` → wordpress, `api`/`swagger` → api); env
`REACHAGENT_GOBUSTER_TECH_HINT` overrides for hermetic tests. Failure
yields `{"target": target}` only.

## 3. Model-agnostic interface

Single entry point:

```python
def propose_recon_tuning(
    target_signals: dict[str, str],
    *,
    client: ReconTunerClient | None = None,
) -> ReconTuningChoice: ...
```

`ReconTunerClient` is a `Protocol` with `propose(signals, allowlist) -> dict`
returning raw `{wordlist_path, flags, filter_codes}`. `AnthropicTunerClient`
is the only implementation in this commit. It reads `ANTHROPIC_API_KEY`,
uses model `claude-3-5-sonnet-20240620`, and is lazily imported so hermetic
tests without the SDK still load. The `client` parameter is injectable so
tests pass a fake without env.

The interface is provider-neutral by construction — a future
`OpenAITunerClient` implementing the same `Protocol` is a one-class swap
with no logic, allowlist, or tool-wiring change. Only Anthropic is
implemented now. The generic name `ReconTunerClient` / `propose_recon_tuning`
is deliberate to avoid a provider-locked name that would need renaming when
OpenAI is added. No OpenAI client ships in this commit.

## 4. How the same pattern extends (§4a built, §4b built — three-layer map complete)

### 4.1 §4a — vuln classes per endpoint shape — BUILT

Same `propose → validate → execute`, different question. Given an
`Endpoint`/`Parameter` shape (method, path, param location,
`inferred_sink_type`, Host technology), Claude proposes which vuln classes
to probe first, e.g. `["sqli", "xss_reflected"]` vs `["path_traversal"]`.

- Allowlist: `VULN_CLASS_ALLOWLIST` in `src/reachagent/recon/vuln_tuning.py`
  — 22 classes with existing oracle wiring (`sqli`…`race`), no invented
  string. Safe default is `_SAFE_DEFAULT_CLASSES` (sink-matched ordering).
- Interface: `propose_vuln_targets(endpoint_signals) -> VulnTargetChoice`
  via `VulnTunerClient` Protocol / `AnthropicVulnClient` (Anthropic-only,
  same swappable shape as `live_tuning.py`), validated per-item against
  `VULN_CLASS_ALLOWLIST` + dedup + empty→fallback before return.
- Wiring: `_live_vuln_class_for(selection, graph, base_url)` in
  `src/reachagent/scan/entrypoint.py` — flag-gated `REACHAGENT_VULN_TUNING=1`
  or `REACHAGENT_RECON_LIVE_TUNING=1` (default OFF), reads
  `Endpoint`/`Parameter`/`Host` shape from graph, calls proposer, re-validates
  against same allowlist + sink-compatibility check (`_sink_for_vuln_class`
  vs `param.inferred_sink_type`) before overriding `vuln_class`. Proposal-only
  — never fires, never calls `run_oracle`/`write_finding`, never invents
  strings.

### 4.2 §4b — payload choice from already-existing tagged library — BUILT

Same pattern, last layer. Given endpoint shape + `vuln_class` + the
sink-matched bucket `get_payloads` already returned (confidence ordered
`0 STRUCTURAL…5 TIMING` template-first), Claude ranks which *existing*
`payload_ref` to try first for THIS target (e.g. WordPress `sqli` sink
prefers WP-flavored `sqli` payload_ref before raw `api`).

- Allowlist: **dynamic** — the exact set of `payload_ref` strings in that
  bucket (`candidate_refs: list[str]`). Nothing outside the bucket can be
  selected; invented ref → fallback. Safe default is original confidence
  order (first 20).
- Interface: `propose_payload_choice(endpoint_signals, vuln_class,
  candidate_refs) -> PayloadChoice` via `PayloadTunerClient` Protocol /
  `AnthropicPayloadClient` (Anthropic-only, same shape), validated every
  returned ref is member of `candidate_refs`, dedup, empty→fallback, logs
  why. Model-agnostic — `client` swappable, OpenAI later different session.
- Wiring: `_maybe_reorder_payloads(entries, vuln_class, sink_type,
  slot_kit)` in `src/reachagent/tools/payload_chain.py` — flag-gated
  `REACHAGENT_PAYLOAD_TUNING=1` or `REACHAGENT_RECON_LIVE_TUNING=1`
  (default OFF), builds `candidate_refs` from `entries`, calls proposer
  with `{"vuln_class","sink","tech"}` signals, re-validates via
  intersection with `candidate_refs` (defense in depth), reorders bucket
  as `ordered + remaining` while respecting `max_attempts=20` and sibling
  harvest. Proposal-only — never invents a ref, never bypasses
  `fire → run_oracle → Validator`.

Three-layer map complete; Phase 4 reporting closes the loop — no further
live layer planned without review. OQ2 (graph-aware signals) closed via
bucket-aware ranking; OQ3 (explicit recon budget) enforced via `max_attempts`
still honored.

### 4.3 §4c — recon profile picker — BUILT (Phase 1)

Same propose→validate→execute, now LLM picks ONE named `ReconProfile` from
`RECON_PROFILES` (6 profiles: api/cms/static/spa/aggressive/quiet each
bundling wordlist+flags+status+tool hint, all drawn from `RECON_ALLOWLIST`).
Validated `profile_name in RECON_PROFILES` before use; outside→fallback
`static_site` and log why. Wiring: `GobusterRunner` + `FfufRunner` +
`FeroxbusterRunner` + `DirbRunner` + `X8Runner` (flags-only for x8, wordlist
stays param list) when `REACHAGENT_RECON_PROFILE=1` (default OFF); second
allowlist check `profile.wordlist in allowed_wl` etc. before argv. Facts-only
unchanged, env overrides still win.

### 4.4 §4d — reporting from confirmed findings only — BUILT (Phase 4)

Same pattern, safest layer. Input is ONLY `graph.findings()` where
`status is CONFIRMED_VIOLATION` (via `render_findings_*`). LLM proposes
`narrative` prose (what was tested, severity, reproduction per finding_id);
fixed code validates `narrative` is non-empty string (and logs, but never
blocks the deterministic table which is always appended). Report cannot
retroactively promote an unconfirmed candidate — it only describes what's
already real. `src/reachagent/report/llm_report.py` (`ReportClient`
Protocol / `AnthropicReportClient`, `generate_llm_report`) + deterministic
fallback via `render_findings_markdown` on any failure/timeout/empty.

## 5. Blast radius and what live reasoning will never do

- Live code **never writes a Finding.** Only `run_oracle` (six families in
  `src/reachagent/oracles/`) → `is_violation` → `Validator.write_finding`
  via `finding_id` can produce a `Finding` with `CONFIRMED_VIOLATION`.
  `graph.store.add_finding` refuses anything else.
- Live code **never calls** `run_oracle`, `write_finding`,
  `mark_inconclusive`, `fire_request`, or `fire_browser` directly. It only
  returns a validated `ReconTuningChoice` that `GobusterRunner.command()`
  turns into a safe argv. It never bypasses the Validator and never
  invents payload strings, wordlist paths, or flags outside
  `RECON_ALLOWLIST`. Future (a)(b) will similarly pick FROM
  `VULN_CLASS_ALLOWLIST` and FROM `library.get_payloads(...)` refs, not
  generate new strings.
- Scope and read-only-first remain at the `RequestFirer` layer. Every fire
  is still audited. Recon still writes only facts (`Host`/`Endpoint` +
  `resolves_to`); a discovered `401`/`403` is tagged `access_restricted`
  but never auto-exploited.
- Operational: requires `ANTHROPIC_API_KEY` when enabled. Missing key,
  timeout, or non-JSON response → safe default with warning, no crash.
  Timeout and model choice are operational, not safety-relevant, and are
  not allowlisted values.

## 6. References — how four questions are answered (PentAGI primary)

### PentAGI (primary, closest match)

PentAGI source lives at `~/Downloads/references/pentagi` (Go, `backend/pkg`
microservices). Key docs: `backend/docs/flow_execution.md`,
`backend/docs/controller.md`, `backend/docs/chain_ast.md`,
`backend/docs/chain_summary.md`, `backend/docs/prompt_engineering_pentagi.md`.

1. **Propose next action — single call or batch? Prompt/schema?**
   PentAGI loops `for iteration` in `backend/pkg/providers/performer.go`
   `performAgentChain()` with `maxGeneralAgentChainIterations=100` (and 20
   for limited agents). Per iteration it makes a single `CallWithTools`
   (`callWithRetries`, 3 retries, 5 s delay) with an OpenAI-compatible
   `llms.Tool` array. Tools are registered via `jsonschema.Reflector` in
   `backend/pkg/tools/registry.go`. Prompt is Markdown+XML with
   `<container_constraints>{{.DockerImage}}`, `<terminal_protocol>`,
   `<team_specialists>{{.ToolName}}`, `{{.ExecutionContext}}`,
   `{{.ToolPlaceholder}}` for function definitions. `TaskWorker` creates a
   `Task`, `Generator` agent decomposes it into 1..15 ordered
   `SubtaskInfo{Title,Description}` via the `subtask_list` barrier tool,
   then `Primary Agent` executes per-subtask, persisting the chain to
   Postgres `msgchains` JSON. Not a single shell string per turn but a
   planned sequence that is iteratively refined.

2. **Validate/sandbox before execute — allowlist or trust?**
   Per-agent allowlist in `backend/pkg/tools/tools.go` — e.g.
   `GetPentesterExecutor` only `hack_result + advice/coder/maintenance/
   memorist/search + terminal/file` (plus optional browser/graphiti).
   Checked via `IsFunctionExists`/`GetToolSchema`/`toolTypeMapping` (7
   `ToolType`). Unknown tool rejected before exec. JSON schema validation
   + `SanitizeToolCallArguments` + `ToolCallFixer` agent (3 retries) for
   bad args. Repeating detection (`repeatingDetector`, threshold 3 soft
   error, 7 abort) and `ExecutionMonitor` (mentor after 5 same-tool or 10
   total calls) add brakes. Sandbox is per-Flow Docker
   `PrimaryTerminalName(tenant,flowID)` with `CapDrop:ALL`, minimal
   `CapAdd`, isolated network, volumes synced only to
   `/work/uploads /work/resources`. `terminal`/`file` via
   `ContainerExecCreate/Attach` only.

3. **Recon "done enough" to move to exploitation?**
   No fixed recon-complete flag. Hierarchy `Flow -> Task -> Subtask` via
   controller. After each Subtask `done`, `Refiner` agent
   (`performSubtasksRefiner`) reloads history, compares `Completed` vs
   `Planned` subtasks, and returns a `SubtaskPatch` (add/remove/modify/
   reorder, respecting `TasksNumberLimit=15`). If the patch is empty, the
   Task is complete. Recon steps are just early Subtasks; exploitation
   Subtasks appear when the Refiner deems prior recon output sufficient.
   Transition is a planning decision, not a numeric gate.

4. **Multi-step state without re-sending full history?**
   `backend/pkg/cast/chain_ast.go` `ChainAST{Sections[] {Header, Body[]}}`
   with per-node `sizeBytes`, plus `backend/pkg/csum/chain_summary.go`
   `SummarizerConfig{PreserveLast, KeepQASections, MaxBPBytes, ...}` that
   collapses all but last sections via concurrent `GenerateSummary`,
   never summarizing the last `BodyPair` (preserves `thought_signature`
   for Gemini/Anthropic/Kimi), with LRU cache (1000 entries, 4 h TTL,
   SHA-256 keyed). Persistence is Postgres `msgchains` per
   Flow/Task/Subtask/MsgchainType (14 types) plus pgvector long-term
   memory and optional Graphiti temporal graph (`acme-flow-<id>`). The
   model sees compressed `ExecutionContext`, not a full chain replay.

### CAI, hexstrike-ai, PentestGPT, claude-bug-bounty (secondary)

- **cai** — Single ReAct turn per `Runner.run` (`src/cai/sdk/agents/run.py`
  `get_response` → `execute_tools_and_side_effects`), loop until
  `NextStepFinalOutput`/`Handoff`. Tools grouped by kill chain but agents
  expose recon+exploitation together; transition is LLM-decided via
  `orchestration_agent`/`red_team` handoffs, not a deterministic gate.
  Guardrails are regex + HITL (`src/cai/agents/guardrails.py`,
  `generic_linux_command.py`, `CAI_GUARDRAILS` flag) plus output
  compression (`_compress_output_for_model`, `CAI_CTX_TRUNC`).

- **hexstrike-ai** — Single live LLM call per step via `hexstrike_mcp.py`/
  `hexstrike_server.py` MCP server; model proposes one tool call per turn.
  Minimal validation beyond MCP tool schemas; no allowlist for shell args.
  Done when tool output yields no new hosts.

- **PentestGPT** — Single call per step with CoT + Tree-of-Thought task
  trees; prompt-level prohibitions but no code allowlist; done when task
  tree nodes all marked done; memory is a condensed `pentestgpt.session`
  file.

- **claude-bug-bounty** — Single call per step via MCP
  `fire_request → classify_response → run_oracle`; strict `ScopeGuard` +
  `is_violation` gate (closest to this repo); done via
  `check_budget(path_id)` + `score_and_select`; memory is
  `ReachabilityGraph` + `ChainSolver` + `AuditLog`.

### Comparison table — PentAGI vs THIS task

| # | Question | PentAGI approach | THIS task proposes | Assessment |
|---|----------|------------------|--------------------|------------|
| 1 | Propose next action — single or batch? Prompt/schema? | Single `CallWithTools` per iteration inside a batch Task/Subtask plan (Generator ≤15 Subtasks, Refiner patches iteratively). Prompt is Markdown+XML with `ExecutionContext` + `ToolPlaceholder` injecting `[]llms.FunctionDefinition` via `jsonschema.Reflector`. Per-iteration may execute multiple `ToolCall`s sequentially, then `Summarizer` before next LLM turn. | Single `propose_recon_tuning(signals) -> ReconTuningChoice` returning JSON `{wordlist_path, flags, filter_codes}` chosen FROM allowlist. Prompt lists allowlists verbatim and demands JSON; response parsed with fallback regex extraction of first `{...}`. One safe triple, not a plan. | THIS intentionally narrower — correct for proposal-only recon tuning. PentAGI batch planning is more powerful but overkill for "which wordlist". No silent adoption of batch planning; keep single-choice until (a)(b) need richer proposals. |
| 2 | Validate/sandbox before execute — allowlist or trust? | Docker isolation + prompt constraints + per-agent tool allowlist, but no fixed allowlist for commands/flags — model can propose arbitrary `terminal` shell inside the container. JSON schema validation + repeating/mentor brakes, but no semantic cap on which wordlist or flag is safe. | Fixed `RECON_ALLOWLIST` (7 wordlists, 5 flag presets, 3 status sets). `propose_recon_tuning` validates membership, falls back to `dirb/common.txt`; `GobusterRunner.command()` re-validates (defense in depth). Blast radius is semantic (only safe values), not just container-bound. | **THIS MORE cautious — intentional, not oversight.** PentAGI container isolation does not prevent a hallucinated wordlist path exfiltrating data or a wrong-flag DoS. Allowlist caps blast radius to safe values even though it makes the proposer less "creative". Keep it. Do not silently adopt PentAGI looser trust. |
| 3 | Recon "done enough" trigger | `Refiner` reviews completed vs planned after each Subtask; no numeric gate — planning decision adds an exploit Subtask when recon output deemed sufficient. `TasksNumberLimit=15` is the only budget. | Gobuster remains one recon runner in a larger `scan_target` loop. Done when `score_and_select` returns `None` or budget exhausted (`max_attempts=20`), not a separate recon gate. Live tuning does not change when recon ends, only its wordlist. | PentAGI refiner is more adaptive than a fixed tool list. **Open question worth closing within allowlist discipline:** Should a future live tuner also propose when to stop a recon tier (e.g. "WordPress detected, no need for generic dir brute") and signal `scan_target` to skip remaining content-discovery runners via an allowlisted `skip_reason` choice? Currently out of scope, but worth a refiner-like signal later — without adopting PentAGI arbitrary-shell freedom. |
| 4 | Multi-step state / token efficiency | `ChainAST` + `chain_summary` summarizer (LRU 1000, 4 h TTL, SHA-256 keyed) + compact `ExecutionContext` injected per turn + vector-store `search_in_memory` first + Graphiti. Full chain stored in DB but not always re-sent. | `target_signals` dict (target + 2 headers + tech hint, each capped at 80 chars / 2000 body chars) is the entire context for tuning — no chain, no vector DB. Future (a)(b) will pass `Endpoint`/`Parameter` shape, still a compact struct, not the full `ReachabilityGraph`. | THIS leaner by design (one 5 s `httpx.get` + env hint). **Open question worth closing:** Would a one-line `tech=wordpress` from `whatweb` or `graph.objects()` email/domain hint improve the wordlist pick beyond header/body, without leaking the graph to the prompt? Flagged, not adopted — current 80-byte cap is intentionally minimal to avoid prompt bloat. No silent expansion of prompt context. |

Where PentAGI does something THIS task is missing and worth closing, all
three can be closed within the allowlist discipline without adopting
looser trust:

- **OQ1 — Recon skip signal** (from Q3): refiner can cancel planned
  subtasks; this task only tunes gobuster, never skips it. A future
  allowlist could include `skip_reason` rather than running every runner.
- **OQ2 — Graph-aware signals** (from Q4): `ExecutionContext` + vector
  memory give the model more context than two headers. A later iteration
  could add a one-line technology fact without dumping the graph.
- **OQ3 — Explicit recon budget** (from Q3): PentAGI Generator max 15 is
  a budget; this task relies on `scan_target` `max_attempts=20` implicitly.
  Worth making explicit if live tuning expands to multiple tools.

## 7. Honest note — multi-provider

The `ReconTunerClient` Protocol is provider-neutral by design so that an
equally good OpenAI integration does not require rework, but only the
Anthropic adapter ships in this commit and that is deliberate. Prompt
phrasing, JSON extraction robustness, and error handling differ per
provider, and a Claude session building an OpenAI client from a Claude
context risks shipping a half-tested adapter. A different session or model
that lives closer to the OpenAI SDK and eval harness should own that second
adapter; the interface is ready and the second implementation should be
reviewed on its own, not bundled as an afterthought. Work that touches
live LLM calls should be owned by whoever is closest to that provider's
tooling, so each adapter gets the attention it needs.

## 8. Operational notes

- Flag-gated: `REACHAGENT_GOBUSTER_LIVE_TUNING=1` or
  `REACHAGENT_RECON_LIVE_TUNING=1` (default OFF).
- Requires `ANTHROPIC_API_KEY` when enabled. Missing key → safe default
  with warning, no crash. `anthropic` SDK is lazily imported so hermetic
  tests without it still load.
- Timeout and model are operational, not safety-relevant, and are not
  allowlisted values.
- `httpx.get` for signals is 5 s best-effort. Failure → signals
  `{"target": target}` only.

## 9. References

- `docs/reachagent-final-plan.md` §4 (role boundaries), §9 (recon tier
  facts-only), §13 (tool manifest)
- `src/reachagent/recon/live_tuning.py` — allowlist + `propose_recon_tuning`
- `src/reachagent/recon/tools/gobuster.py` — flag-gated hook + double
  allowlist check
- `src/reachagent/recon/tools/_wordlist.py` — preferred wordlist source
- `src/reachagent/oracles/{differential,structural,timing_statistical,oob_callback,execution_confirmation,business_rule}.py`
  — six families, not modified
- `~/Downloads/references/pentagi/backend/pkg/providers/performer.go`,
  `helpers.go`, `backend/pkg/tools/tools.go`, `backend/pkg/cast/chain_ast.go`,
  `backend/pkg/csum/chain_summary.go`, `backend/docs/flow_execution.md`
