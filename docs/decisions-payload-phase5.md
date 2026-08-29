---
title: Phase 5 payload library, context selection, and mutation decisions
---

# Phase 5 — payload library, context selection, and mutation

Date: 2026-08-28. Scope: explicitly authorized web/API targets and intentionally
vulnerable laboratories only.

## Invariants and authorization boundary

The model may rank an existing, sink-matched payload reference and request a
bounded mutation descriptor; it never supplies executable payload text, chooses
an oracle, fires a request, or writes a finding. Every fired value must resolve
from an in-tree reference, retain its parent metadata, pass the same sink and
oracle compatibility checks as its parent, and travel through the existing
Explorer → fire → deterministic oracle → Validator path. Missing slots, dead
references, incompatible sinks, and over-limit mutations fail closed and are
audited rather than treated as clean results.

## Licenses recorded before deep reading

| Alias | License | Phase-5 posture |
|---|---|---|
| R1 | MIT | Technique-level reuse only |
| R2 | MIT for the agent-origin subtree; research-use-only for authored core | Paraphrased ideas only |
| R3 | MIT | Technique-level reuse only |
| R4 | MIT | Paraphrased ideas only |
| R5 | MIT | Technique-level reuse only |
| R6 | Apache-2.0 | Technique-level reuse only |
| R7 | MIT | Vendored payload metadata only |
| R8 | MIT | Vendored wordlist metadata only |

## Full reads and concrete techniques

The Phase 5 read covered R1's strict tool argument schemas, terminal result
limits, execution observation wrappers, registry metadata, and pentester prompt;
R2's web agent composition, category/key-gated registry, MCP tool registry, and
execution tool; R3's shared MCP registry, name/description validation, and
stdio tool server; R4's payload catalog, context-aware encoding helpers, WAF
baseline/fingerprint/diff/classifier, and browser/response summaries; R5's
persistent HTTP session, match/replace locations, repeater, sniper baseline,
reflection/status/body-delta signals, and bounded fuzzing; R7/R8 source manifests
and machine-readable in-tree payload/wordlist files; and ReachAgent's complete
library, corpus, resolver, encoding, tuning, Explorer, MCP, and payload-chain
call paths plus focused tests.

The useful techniques are: strict schemas and output caps (R1/R2), stable tool
registries and descriptions (R2/R3), baseline plus body/status/reflection
classification (R4/R5), explicit encoding families and deduplication (R4),
per-parameter sniper mutation with a bounded request count (R5), and immutable
source-line provenance (R7/R8).

Files read in full for this phase were:

- **R1:** `pkg/tools/args.go`, `terminal.go`, `executor.go`, `registry.go`,
  `context.go`, `tools.go`, `controller/prompter.go`, and the pentester prompt
  template.
- **R2:** `agents/web_pentester.py`, `agents/available_tools.py`,
  `tool_registry.py`, `sdk/agents/tool.py`, `tools/executor.py`, and web
  `tools/web/fetch_url.py`, `tools/web/headers.py`.
- **R3:** `unified_agent/tools.py` and `unified_agent/tool_server.py`.
- **R4:** `tools/hai_payload_builder.py`, `tools/waf_encoder.py`, and
  `tools/waf_response_analyzer.py`.
- **R5:** the HTTP testing framework, repeater, match/replace, sniper, and
  fuzzing handlers in the server module.
- **R7/R8:** both pinned source manifests and all machine-readable payload and
  wordlist files included by the repository's corpus loader.
- **ReachAgent:** `payloads/{library,corpus,payload_resolver,encoding}.py`,
  `recon/payload_tuning.py`, `tools/{explorer,payload_chain}.py`,
  `mcp/server.py`, and all focused payload/corpus/resolver tests.

## Gap and smallest safe design

ReachAgent already had six-field sink/oracle tags, line-locator resolution,
two URL-encoding variants, and allowlisted LLM ordering. It lacked explicit
method/content-type/framework/auth/location dimensions, parent metadata on
variants, delimiter/casing/wrapper mutations, per-parent accounting, and
passing prior response outcomes into the next ranking call. The smallest safe
design extends entries with optional context and parent fields, adds a pure
mutation module that resolves a parent then creates at most four variants, and
revalidates sink, oracle, graph edge, reference provenance, and decoded semantic
shape for every child. The LLM receives only bounded metadata and prior outcome
summaries; raw payload values remain outside its prompt.

## Compatibility proof

`PayloadLibrary.get_payloads` filters context only after exact
`vuln_class`/sink matching. `expand_payload_mutations` copies the parent
vulnerability class, sink, oracle family, graph edge, and parent reference;
`validate_mutation` rejects any mismatch and checks the decoded value against
the declared sink. A focused test exercises SQL→HTML and structural→timing
cross-routing attempts and confirms they are rejected before the MCP fire step.
`tests/recon/test_phase5_payloads.py::test_incompatible_sink_or_oracle_mutation_is_rejected`
is the explicit compatibility proof; the same file's hard-cap test proves the
four-child per-parent limit, and `test_prior_attempt_outcome_is_forwarded_to_the_model`
proves failed-attempt context reaches selection.

## Oracle-boundary proof

The new mutation/context code imports neither Validator nor an oracle runner. It
only creates immutable stimulus metadata and resolver cache values. The existing
payload chain still performs `fire_request`, `classify_response`, `run_oracle`,
and `write_finding` in that order; a model-selected reference can therefore
change ordering or a safe mutation, never confirmation authority.

## Implementation and focused verification

Implemented in `src/reachagent/payloads/{library,encoding,payload_resolver}.py`,
`src/reachagent/recon/payload_tuning.py`, `src/reachagent/tools/{explorer,payload_chain}.py`,
and `src/reachagent/mcp/server.py`, with focused coverage in
`tests/recon/test_phase5_payloads.py`. The complete Phase 5 focused gate passed
153 tests. No files were deleted.
