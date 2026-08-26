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
