---
name: llm-applications
category: vulnerability
description: LLM-application architecture-level attack surface — plugin/tool-calling trust boundaries, RAG data-source poisoning, and a per-class proof ladder (application design, distinct from prompt-injection technique itself)
keywords: [llm application, rag, retrieval augmented generation, tool calling, agent security, vector database]
---

# LLM Application Security

This skill covers APPLICATION-ARCHITECTURE gaps in a system built around
an LLM — where the untrusted-input boundary actually is, and what the
LLM's own output is allowed to DO — distinct from
[[llm-prompt-injection]], which covers the injection TECHNIQUE itself.
Apply both together: prompt injection is usually the delivery mechanism,
the gaps here are what makes it consequential.

## Attack Surface

- Tool/function-calling where the LLM's OWN output selects and
  parameterizes a real action (a database query, an API call, a file
  operation, a code-execution sandbox) with insufficient validation of
  the LLM-chosen arguments before they execute — the LLM's output is
  attacker-influenceable the moment any untrusted content (a document it
  reads, a webpage it browses, a tool's own output) enters its context,
  so an unvalidated tool argument is functionally the same trust
  violation as an unvalidated user input.
- RAG (retrieval-augmented generation) pipelines where the vector
  database/document store can be written to (directly or via an
  application feature) by a lower-trust actor than the one who queries
  it — a poisoned document injected into the retrieval corpus becomes
  part of a LATER, higher-trust user's context.
- Conversation/session memory persisted and later replayed into a new
  context — if one user's adversarial input can be persisted (a shared
  document, a multi-tenant memory store with an isolation gap) and later
  retrieved into a DIFFERENT user's session.
- System-prompt/instruction leakage treated as a confidentiality boundary
  when it also contains a real secret (an API key, an internal policy
  meant to stay undisclosed) rather than being purely a behavior
  specification.

## Recon

- Map every tool/function the LLM can call and, for each, identify what
  happens with NO further validation if the LLM supplies an arbitrary,
  adversarial value for each parameter — this is the single most
  consequential thing to establish before attempting any prompt-
  injection technique at all.
- Identify every place untrusted content enters the LLM's context (a
  user message, a retrieved document, a browsed page, a prior tool's
  output) and whether the application treats ALL of them as equally
  untrusted, or incorrectly trusts one channel (commonly: retrieved
  documents) more than direct user input.
- For a RAG system, identify who can write to the retrieval corpus and
  whether that writer population is a strict subset of (or overlaps
  with, at a lower trust level than) the query population.

## Techniques

1. **Tool-argument injection via untrusted content**, building on
   [[llm-prompt-injection]]'s own technique — plant an instruction in a
   channel the LLM will read (a document it's asked to summarize, a
   webpage it browses) directing it to call a real tool with an
   attacker-chosen argument, and confirm the tool actually executes with
   no independent validation.
2. **RAG corpus poisoning.** If the retrieval corpus is writable by a
   lower-trust actor, insert a document containing an instruction
   targeting a LATER query from a higher-trust user, then trigger a
   query that would plausibly retrieve it, and confirm the injected
   instruction reaches and influences that later user's response.
3. **Cross-session memory bleed check.** If conversation memory is
   persisted, attempt to plant content in one session and confirm
   whether it becomes retrievable in a DIFFERENT user's/tenant's session
   — a multi-tenancy isolation gap in the memory store, not a prompt-
   injection technique per se.
4. **System-prompt secret-leakage check.** Attempt to have the model
   disclose its system prompt/instructions (a known family of prompt-
   injection techniques, see [[llm-prompt-injection]]) and, separately,
   assess whether anything disclosed constitutes an actual secret
   (credential, internal policy meant to stay confidential) versus
   merely revealing intended behavior — only the former is a
   confidentiality finding.

## Proof Ladder

- **L1** — an unvalidated tool-argument path or an untrusted-content
  channel identified, but no actual injected instruction has been
  delivered through it yet.
- **L2** — an injected instruction delivered through the identified
  channel and confirmed to influence the model's own output/tool
  selection, but the triggered tool call's real-world effect not yet
  observed.
- **L3** — a concrete real-world effect observed from the triggered tool
  call (a benign file written, a query executed against unintended
  scope, a cross-session memory bleed confirmed) — reportable.
- **L4** — the effect chained to a durable, high-impact outcome (data
  exfiltration across a tenant boundary, a destructive action on
  a resource outside the intended scope, reliable cross-session
  compromise) reproducible on a second run.

## Validation and False-Positive Discipline

Apply [[closure-discipline]]. A tool-calling layer confirmed to validate
every LLM-supplied argument against the SAME rules a direct, untrusted
user input to that action would face (an allowlist, a scope check, a
parameterized query) closes the tool-argument-injection path regardless
of how susceptible the model itself is to prompt injection — the model's
own susceptibility only matters if something downstream trusts its
output uncritically. A system prompt disclosing only intended-behavior
description with no actual credential or confidential policy is not a
confidentiality finding, even if disclosure itself was unintended.

## Impact

Arbitrary action execution (data exfiltration, unauthorized queries,
destructive operations) via unvalidated LLM-chosen tool arguments;
cross-user/cross-tenant compromise via RAG corpus poisoning or memory-
store isolation gaps; credential/secret exposure via genuine system-
prompt leakage.

## Summary

The tool-calling validation boundary is the single highest-leverage
thing to check first — if every LLM-chosen argument is validated as
rigorously as a direct user input would be, most prompt-injection
technique success ([[llm-prompt-injection]]) becomes far less
consequential. Separately, always check who can write to a RAG corpus
relative to who queries it.
