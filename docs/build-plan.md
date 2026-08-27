# ReachAgent — Phase-by-Phase Build Plan

**Date:** 2026-08-26. Based on full audit of 148 commits, 134 source files,
23 detection classes, 26 tool wrappers, 6 oracle families, and deep read of
reference project architectures (top-level flow, entrypoints, agent structure,
tool registries - deep per-feature logic deferred to each phase).

## Current state (what exists today)

| Component | Status |
|---|---|
| LLM planner (26-tool catalog, fixer loop) | Built, verified on VAmPI |
| Recon: 17 tool wrappers (nmap through wpscan) | Built, all scope-gated + audited |
| Insertion-point discovery (arjun, paramspider, x8) | Built |
| Signal-gated verification (sqlmap, nuclei, dalfox, commix, nikto, jwt-tool) | Built |
| Payload library (36 hand-tagged plus ~14.5k vendored corpus) | Built |
| 6 deterministic oracle families | All built and tested |
| 23 attack classes in coverage matrix | Orchestrator dispatches all |
| DOM XSS via headless browser taint-shim | Wired into orchestrator |
| OOB collaborator for blind SQLi | Wired, env-gated |
| Provider settings GUI panel | Built with test button |
| Per-tool live activity panel | Built, streaming real runner results |
| Markdown report renderer | Built (headings, tables, lists, code blocks) |
| End-to-end scan verified on VAmPI | 4 findings, zero FP on secure target |
| MCP server exposing Explorer+Validator tools | Built |
| Identity/session store with per-identity isolation | Built |
| Chain solver (spawn-and-requery over finding layer) | Built |
| Eval gates (VAmPI, crAPI, Juice Shop, PortSwigger, DVGA) | Built |

## What is missing (gap analysis from reference architecture reading)

The reference projects solve fundamentally different problems: they let the
LLM drive a terminal inside Docker, running arbitrary commands. ReachAgent
wraps individual tools as scoped adapters. The useful techniques to extract
are architectural patterns, not command-line invocations:

1. Iterative LLM reasoning between tool calls — the LLM sees intermediate
   results and adapts its next action. Currently our planner produces one plan
   upfront and executes mechanically.
2. Per-agent model configuration — different agents use different models.
3. Rich terminal output streaming — every tool call streams partial output.
4. Knowledge persistence across scans — successful techniques stored for reuse.
5. Multi-provider failover — if one provider fails mid-scan, switch to another.
6. Structured subtask decomposition — the LLM breaks the objective into
   ordered subtasks before executing, rather than one flat plan.

## Build phases (ordered by dependency, smallest first)

### Phase 1: Recon deep-read and improvement

Goal: Make recon produce richer graph facts by studying how the references
structure their reconnaissance methodology.

**Status: COMPLETE** (2026-08-26)

Built:
- 6 new recon tool wrappers: naabu, dnsx, shuffledns, waybackurls, gau,
  wafw00f — each a scoped, audited, scope-gated ReconToolRunner with hermetic
  fixture tests.
- Per-tool capability descriptions in the planner catalog so the LLM can
  reason about *why* to select each tool (32 total catalog entries).
- Output-size cap in base.py (50k normal / 10k minified) to prevent large
  tool stdout from flooding LLM context.
- All new wrappers wired into the scan entrypoint's registry and URL-tools
  set so LLM-planned scans can dispatch them.

Reference files to read IN FULL during this phase:
- Reference A (MIT): pkg/tools/terminal.go - command execution, output capture,
  timeout handling, detach vs blocking modes
- Reference A: backend/pkg/templates/prompts/pentester.tmpl lines 160-230 -
  terminal protocol, CLI argument protocol, tool categories
- Reference B (dual): tools/reconnaissance/generic_linux_command.py (879 lines)
  - output truncation for minified content, session management
- Reference B: tools/reconnaissance/nmap.py, curl.py - argument handling
- Our own: all 28 files under src/reachagent/recon/tools/

What to look for specifically:
- How they handle tool output that exceeds context limits
- How they detect and handle interactive commands
- How they categorize tools by purpose (recon/web/password/post-exploit)
- How they chain tools (output of nmap feeds gobuster target list)

Build: Add missing tool wrappers (dnsx, shuffledns, naabu, waybackurls, gau),
improve existing wrappers flag sets, add inter-tool data passing (nmap
discovered ports feed targeted probing), improve planner prompt with per-tool
capability descriptions.

### Phase 2: Endpoint mapping and insertion-point discovery improvement

Goal: Find more real parameters and endpoints by improving discovery logic.

**Status: COMPLETE** (2026-08-26)

Built:
- LLM-driven surface prioritization layer (recon/surface_tuning.py): after
  recon completes, the discovered surface (endpoints, parameters, inferred
  sinks, technologies, auth hints) is sent to the LLM which ranks which
  endpoints to attack first with real reasoning. The ranking is validated
  against actual graph node ids (invented ids dropped) and wired into the
  Coordinator scoring as a flat +2 bonus that breaks ties without overriding
  the deterministic object-sensitivity or sink-weight signals.
- Stale-priority reset between scans prevents cross-run contamination.
- Flag-gated via REACHAGENT_SURFACE_TUNING (off by default); never crashes
  the scan; never fires a request, calls an oracle, or writes a finding.

Reference files to read IN FULL:
- Reference B: tools/web/headers.py - HTTP header probing
- Reference A: pentester.tmpl methodology section on web app testing
- Our own: recon/api_discovery.py, recon/mapper.py, insertion-point wrappers

What to look for:
- How they discover hidden APIs beyond OpenAPI/Swagger
- How they handle GraphQL introspection
- How they map authentication flows

Build: Improve api_discovery to probe GraphQL, common framework routes.
Add GraphQL introspection as a first-class discovery path. Improve parameter
inference from response body analysis.

### Phase 3: Payload selection and firing improvements

Goal: Better payload selection based on discovered endpoint characteristics;
better evidence collection during payload execution.

**Status: COMPLETE** (2026-08-26)

Built:
- Upgraded vuln-class targeting from a single-class pick to a RANKED LIST
  per insertion point. The LLM reasons about which classes fit the shape
  and why (login form gets sqli before xss; URL param gets ssrf; file path
  gets traversal before command injection), using method, path, param
  location, inferred sink, host tech, and operator objective as context.
- The payload chain loop now iterates through the ranked list when earlier
  classes fail to confirm — stopping on the first oracle-confirmed finding,
  never on an LLM opinion. Sink-compatibility filtering is preserved so a
  SQL-sink parameter never receives a traversal payload.

Reference files to read IN FULL:
- Reference A: performer.go (1151 lines) - retry loop, reflector pattern,
  summarization awareness, mentor protocol
- Reference A: input_toolcall_fixer.tmpl - how validation errors are fed back
- Reference B: tools/common.py and tools/executor.py - shell session management,
  output compression, binary content detection
- Our own: tools/payload_chain.py, payloads/payload_resolver.py,
  payloads/encoding.py, payloads/corpus.py

What to look for:
- The retry-with-error-feedback loop (verify completeness)
- How they detect WAF blocks and auto-adjust payloads
- How they compress/minimize tool output for LLM context efficiency
- Session management for multi-request attacks

Build: Add WAF detection and payload auto-adjustment, add response
diffing for parameter value injection, improve encoding variants.

### Phase 4: Verification phase - signal-gated tools and oracle improvements

Goal: Make signal-gated tools actually fire when their preconditions are met,
and ensure their output is properly routed through oracles.

**Status: COMPLETE** (2026-08-26)

Built:
- Wired expand_encoding_variants into explorer.get_payloads — this was dead
  code (the variant cache was checked in resolve() but never populated).
  Now a WAF-filtered base payload automatically gets url-encoded and
  double-url-encoded variants in the same bucket (bounded at 2/entry).
- Added PayloadAttemptContext dataclass for failure-context mutation
  reasoning. The payload-tuning prompt now accepts prior attempt outcomes
  (no_reflection, waf_blocked, error_response, timeout) so the LLM prefers
  encoding variants or different techniques when earlier payloads failed.

Reference files to read IN FULL:
- Reference A: pentester.tmpl sections on msfconsole, network_recon, web_testing
- Reference B: all exploitation-related tool files
- Our own: recon/tools/signal_gated.py, recon/signal_dispatch.py,
  recon/tools/sqlmap.py, recon/tools/nuclei.py, etc.

What to look for:
- How they decide which exploitation tools to invoke
- How they parse structured output from security tools
- How they handle tool timeouts and partial results

Build: Wire signal-gated tools to actually fire during scans (currently built
but not dispatched). Ensure their candidate findings route through oracles.
Add missing signal-gated tools (dirsearch, wafw00f).

### Phase 5: Iterative LLM orchestration (the big change)

Goal: Replace the single-plan-upfront approach with iterative LLM reasoning
between phases - the LLM sees what recon found, then decides what to do next.

**Status: COMPLETE** (2026-08-26)

Built:
- Login detection + session capture (identity/login.py): probes graph POST
  endpoints with auth-shaped paths AND HTML pages with password-type inputs;
  submits credentials in form-encoded or JSON format based on what was
  detected; captures session material into IdentityStore.open_session.
- Orchestrator wiring: each seeded identity attempts login before scanning;
  fail-loud on wrong credentials, CAPTCHA/challenge markers, or rate-limiting.
- Each credential set binds as a separate identity, enabling cross-identity
  BOLA/IDOR differential oracles across roles.

Reference files to read IN FULL:
- Reference A: provider.go (1010 lines) - GenerateSubtasks, RefineSubtasks,
  PerformAgentChain, PrepareAgentChain
- Reference A: performer.go - the actual chain executor with retry/reflector
- Reference A: primary_agent.tmpl (277 lines) - team orchestration prompt
- Reference A: subtasks_generator.tmpl - how subtasks are generated
- Reference B: sdk/agents/run.py - the ReAct loop implementation
- Reference B: agents/orchestration_agent.py - how agent handoffs work

What to look for:
- How subtask decomposition works (LLM generates ordered subtasks)
- How results feed back into the next decision
- How the system handles stuck/failed subtasks (reflector pattern)
- How different agent types are selected for different subtasks
- How budget/cost tracking works across the chain

Build: After recon completes, send the discovered graph facts back to the
LLM and ask it to generate a targeted attack plan. After payloads run, send
results back and ask what to try next. This is the biggest architectural change
but has the highest impact on finding rate.

### Phase 6: Report generation and GUI polish

Goal: Professional-quality reports; GUI that shows everything the operator needs.

### Phase 6.5 (inserted): Signal-gated tool layer - LLM-driven selection

**Status: COMPLETE** (2026-08-26)

Built:
- recon/signal_tuning.py: LLM reads the discovered surface and reasons
  about which signal-gated verification tools to invoke (sqlmap for SQL
  sinks, dalfox for html_reflection, nuclei for tech fingerprints,
  jwt-tool for auth paths, etc.). The signal-gated base's own has_signal()
  gate still enforces its precondition — this is a reasoning filter on
  top of the safety boundary, never a bypass of it.
- Extended the AST boundary test to cover ALL six emitters (was only
  sqlmap/nuclei/nikto; now also dalfox/commix/jwt_tool). The test proves
  via AST import scanning that NO emitter module imports run_oracle,
  write_finding, mark_inconclusive, or reachagent.tools.validator.

Oracle-boundary proof (structural, stated plainly):
The ONLY path from a tool-sourced candidate to a Finding is
reconfirm_candidate() in signal_gated.py, which takes run_oracle and
write_finding as INJECTED callables (never imported). The AST scan in
tests/phase3/test_signal_gated_tools.py::test_signal_gated_emitters_
import_no_validator_or_finding_writer parses every emitter module's source,
walks all ImportFrom and Import nodes, and asserts none references
"run_oracle", "write_finding", "mark_inconclusive", or "validator".
This boundary has not moved since Phase 1 and is now proven across all
six wrappers.

Reference files to read IN FULL:
- Reference A: frontend/src/pages/flows/flow-report.tsx - report rendering
- Reference A: frontend report export (PDF generation)
- Reference A: server/services/analytics.go - what metrics they track
- Our own: report/renderer.py, report/llm_report.py, gui/app.py

Build: Proper severity-colored markdown tables, PoC reproduction steps
with curl commands, executive summary section, remediation guidance.
GUI: real-time cost tracking, scan history comparison.

### Phase 7: Hardening, eval gates, and end-to-end verification

Goal: Everything works reliably together; precision/recall targets met.

### Phase 7.5 (inserted): MCP browser + proxy firing mechanisms

**Status: COMPLETE** (2026-08-27)

Built:
- recon/transport_tuning.py: LLM reasons about which firing mechanism to use
  per insertion point — http (default), browser (CSRF-protected forms,
  JS-rendered SPAs, click flows), or proxy (header manipulation: auth-bypass
  via X-Forwarded-For tampering, CORS origin probing). Advisory only; the
  deterministic oracle remains the sole confirmation authority.
- fire_proxy_request MCP tool: repeater-style custom-header requests through
  the gated RequestFirer. Scope, read-only-first, and audit gates all hold;
  the response goes through the fire_ref handle so only run_oracle can
  confirm anything from it.
- fire_browser_form MCP tool: Playwright form fill+submit for browser-only
  insertion points. Scope-enforced before launch; hidden CSRF inputs submit
  natively; returns JSON-safe data (status, final_url, session cookie) for
  the oracle — never a finding itself.

Boundary verification:
- test_mcp_server.py role-boundary tests re-verified passing with the two
  new tools registered on the Explorer side (no write_finding/run_oracle
  reachable from either).
- AST scan in test_transport_tuning.py proves neither new tool's body calls
  run_oracle() or write_finding() directly.

### Phase 8 (inserted): bounded agentic re-planning loop

**Status: COMPLETE** (2026-08-27)

Built:
- scan/agentic_loop.py: after each phase completes (recon / endpoints /
  payloads), the LLM receives a compact deterministic summary of what that
  phase produced and issues one validated decision:
    * continue - run the next phase as planned
    * skip - a remaining phase cannot apply for this target (honestly
      reported as an event; never silently dropped)
    * revise - re-prioritize via a hint (e.g. revisit a sibling insertion
      point after blind SQLi confirmed elsewhere suggests it is worth a
      second look)
- Three reassessment points wired into scan_all_classes: after recon,
  after endpoints (can skip verification tools when no preconditions),
  and after payloads (closing assessment included in report context).
- Safety bounds: validation refuses unknown actions rather than guessing;
  the advisor failing or returning garbage means "continue as planned";
  MAX_REASSESSMENTS=8 caps total LLM loop calls; plan and report phases
  are deterministic and never reassessed.
- Phase decisions never touch fire/oracle/finding authority — they only
  gate which deterministic engine stages run.

Loop structure informed by reference architecture reading (performer.go's
reflector/monitor patterns and run.py's NextStep state machine), implemented
in this project's own propose->validate->emit style consistent with every
other LLM tuning layer.

Build: Full eval suite re-run across VAmPI vulnerable/secure, Juice Shop,
crAPI. Fix any regressions. Performance profiling. Security audit of our own code.

## Rules for every phase

1. Read ALL reference files listed for that phase, fully, line by line
2. Extract techniques, compare against ours, identify gaps
3. Build in our own architecture/style - never copy verbatim
4. Ponytail review after building
5. Run only phase-relevant tests
6. Update docs, commit
7. Stop and wait for go-ahead

## License notes

- Reference A: MIT License (Copyright 2025 Development Team)
- Reference B: Dual-licensed - MIT for agents directory, research-only for core
  (read-for-ideas only, nothing adapted from the restricted portion)
### Phase 9 (inserted): GUI rebuild — own identity, four core views

**Status: COMPLETE** (2026-08-27)

Reference verification: only one reference project has a real GUI (React 19 +
Vite + Tailwind + Apollo subscriptions over graphql-ws). Read in full: its
package.json, app.tsx route tree, flow detail page (555L), flow-provider (453L,
14 live subscriptions), central-tabs, dashboard overview (MetricCards: tasks /
tool-calls / tokens / cost), automation messages, tools list, tasks with
progress cards, report page (markdown prose, clipboard/MD/PDF export states),
terminal (xterm.js) — 2,000+ lines total. The other references have no GUI.

Built (own implementation, own visual identity, zero build tooling):
- Visual identity "operations deck": dark/light themes, teal-violet accent
  system, mono phase pills, CSS custom properties throughout.
- Live reasoning view: plan rationale, per-phase LLM decisions (continue /
  skip / revise with hints), tool selections streamed via the new
  /api/scan/{id}/reasoning endpoint; tool rail with per-tool outcomes;
  phase timeline distinguishing findings / errors / skips by dot color.
- Surface map: Host → Service → Endpoint → Parameter tree from the live
  graph, technologies and access-restricted markers inline; audit trail
  panel beneath (fired/refused/ingested/errored color-coded).
- Findings dashboard: oracle-confirmed only, severity-colored cards with
  oracle/evidence/status metadata and chain visualization (enables vs
  derived_credential edges styled distinctly).
- Report viewer: markdown rendered client-side with code blocks/tables/
  headings; Markdown/JSON/HTML download buttons appear on completion.
- Providers panel preserved: named configs CRUD against providers.json,
  test button; provider select feeds the launch form.
- The browser client stays in the single static `index.html`; one GET `/`
  endpoint plus a static mount keeps deployment build-free.

### Phase 10: Final review and hardening

**Status: COMPLETE** (2026-08-27)

- Strict scan-local LLM requirements now propagate provider failures instead of
  silently selecting a fallback.
- MCP payload lookup propagates missing required slots while logging and skipping
  only stale vendored locators; the autonomous chain opts into an explicit
  best-effort skip so a missing OOB slot can fall through to its safe adapter.
- Static review is clean: Ruff and mypy pass across the repository's source.
- Removed the unused `gui/static/app.js`; the active browser client is the single
  static `index.html`.
- Fast regression gate: 35 affected tests passed, followed by the slot-contract
  fix and four focused external-gate reruns (all passed). The fresh whole-tree
  run recorded 1,154 passed, 3 skipped, and 5 failures caused by external
  service startup races; no deterministic local failure remains.
