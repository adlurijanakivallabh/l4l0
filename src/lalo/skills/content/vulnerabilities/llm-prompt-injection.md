---
name: llm-prompt-injection
category: vulnerability
description: Prompt injection in a target's own LLM/RAG/agentic features — direct and indirect injection, tool-call abuse, and insecure output handling, with a per-class proof ladder
keywords: [prompt injection, jailbreak, llm security, rag poisoning, indirect prompt injection, insecure output handling]
---

# LLM Prompt Injection (Target-Side AI Features)

This skill covers testing a TARGET application's own LLM-backed feature —
a chatbot, a document assistant, an AI search box, an autonomous
tool-using agent embedded in the product being assessed. Passing untrusted
text to a model is an attack surface, not proof of a vulnerability: define
the concrete data/action/output invariant the injection violates, and
validate the effect outside the model's own transcript, in a real sink.
When the target's AI feature can itself call tools, plugins, or other
services, read this alongside [[agentic-system-security]]'s effective-
authority framing — instruction confusion and effective-authority abuse
are two different failure modes that often chain together.

## Attack Surface

- Direct injection surfaces: chatbots, "summarize/translate/rewrite this"
  features, AI search, support agents — anywhere a user's own message
  reaches the model directly.
- Indirect injection surfaces: any content the model ingests that the
  ATTACKER controls but the VICTIM triggers — a web page, PDF, email, RAG
  document, filename, image alt-text, or a prior tool result fed back into
  context. This is the higher-severity, more commonly under-tested vector.
- The tool/agent layer: function calling, code execution, SQL/HTTP tools,
  file access, email/send actions reachable from model output.
- Output sinks: model text rendered as HTML without encoding (stored XSS),
  used in a SQL/shell/redirect sink, or emitted as a Markdown image URL
  that a browser fetches on render (exfiltration channel).

## Recon

- Map where user input enters the prompt (direct chat vs. ingested
  content), what the model can access (a RAG corpus, tool schemas, prior
  conversation memory), and where its output goes (rendered HTML, a
  downstream API, another agent).
- Determine whether a moderation/guardrail layer exists and whether it
  runs IN-BAND (the same model judging its own output — bypassable by the
  same injection technique that works on the main model) or genuinely
  out-of-band.
- For a RAG system, identify who can write to the retrievable corpus and
  who can retrieve it — a corpus writable by any user and retrievable by
  ANY OTHER user's query is the precondition for cross-tenant RAG
  poisoning.
- For a tool-using feature, enumerate exactly which tools the model can
  invoke and whether tool arguments are validated server-side at the tool
  boundary, or trusted as already-sanitized because "the model chose
  them."

## Techniques (start quiet, escalate only as needed)

1. **Direct instruction override.** Submit an inline override ("ignore
   previous instructions," a fake system-role marker, a delimiter
   breakout closing the application's own prompt-template fence) and
   observe whether the model's subsequent behavior actually changes in a
   way that violates a real application rule — not just whether it
   produces unusual text.
2. **Indirect injection via ingested content.** Plant an instruction in
   content the model will later be asked to process (a web page, document,
   or filename it will summarize/analyze) and trigger it through the
   NORMAL user action ("summarize this URL") rather than injecting
   directly — this is what actually proves the cross-domain trust
   violation.
3. **System-prompt/context extraction.** Attempt to extract the system
   prompt, tool schemas, or other users' context present in the same
   conversation — but do not report the extracted text alone as a
   finding; either it discloses a genuine secret (report as disclosure)
   or it reveals a security rule that exists ONLY in prompt text with no
   enforcement elsewhere (report as the underlying authorization gap).
4. **Tool-call argument steering.** Where the feature can invoke tools,
   attempt to steer it — via direct or indirect injection — into calling a
   privileged tool with attacker-chosen arguments (a different recipient,
   a different file path, a different record ID), and confirm the tool
   boundary itself validates arguments rather than trusting whatever the
   model supplied.
5. **Insecure-output-handling probe.** Coax the model into emitting
   HTML/script content, a SQL fragment, or a Markdown image tag pointing
   at an attacker-controlled URL with a secret value embedded in the query
   string, then confirm the actual rendering/execution context (the DOM,
   a SQL sink, a browser fetch) rather than treating the model's text
   output alone as proof.
6. **Guardrail bypass.** If an in-band moderation layer exists, test
   whether the same encoding/role-play/instruction-laundering technique
   that works against the main model also defeats the guard, and whether
   the guard actually inspects the FINAL merged prompt (including
   retrieved/ingested content) rather than only the raw user message.

## Proof Ladder

- **L1 — injection reaches the model.** The crafted instruction is
  confirmed to reach the model's effective context (via a visible
  behavioral change or an extracted echo), but no protected data, action,
  or output sink has been affected yet.
- **L2 — model behavior changed against intent.** The model's output or
  behavior demonstrably deviates from the application's own stated rules
  (via direct or indirect injection) — but the deviation has not yet
  reached a real sink or triggered a real action.
- **L3 — real sink or action reached.** A tool call actually executes with
  attacker-influenced arguments, model output actually renders as
  executable HTML/script, or a genuine data exfiltration channel (a
  fetched Markdown image URL, a leaked secret) is demonstrated end to end.
  This is the threshold for a reportable finding.
- **L4 — cross-tenant or systemic compromise.** The injection is proven
  reproducible through indirect/RAG-poisoning content that affects OTHER
  users' sessions (not just the tester's own), or chains into a
  privileged tool action with real, confirmed external effect (data sent,
  a record modified, a purchase made).

Calibrate severity separately per [[severity-calibration]] — a model
merely "saying" it would do something with no privileged tool actually
reachable is not a finding at any severity; a proven tool-triggered
privileged action is high or critical depending on what that action does.

## Validation and False-Positive Discipline

Apply [[closure-discipline]] before recording anything. Class-specific
traps to check before calling something confirmed:

- The model SAYING it will perform an action, with no privileged sink or
  tool actually available to it, is not evidence of anything — confirm a
  real tool call or a real rendered sink, not model narration.
- A "leaked system prompt" that does not match the actual deployed prompt
  (or contains no genuine secret) may be a hallucination, not a real
  disclosure — cross-check against a unique marker or known fact before
  reporting extraction as confirmed.
- Output that IS properly encoded/escaped before reaching HTML/SQL/shell
  is not vulnerable, regardless of how "dangerous-looking" the model's raw
  text output is — confirm the actual rendered/executed sink, not the raw
  model transcript.
- A single anomalous response with no repeated trial and no matched
  baseline is not sufficient — prompt injection is often stochastic; run
  the same probe more than once and record both attempts and successes.

## Impact

Exfiltration of secrets, private context, or other users'/tenants' data
via RAG poisoning or indirect injection, unauthorized privileged actions
(send, delete, modify, purchase) via steered tool calls, stored or
reflected XSS through unescaped model output, and bypass of the
application's own content policy or business rules that exist only as
prompt-level guidance.

## Summary

Prompt injection is a trust-boundary failure between instructions and
data, not a contest of clever wording. Test both direct and indirect
paths, chase every finding to a real sink (a tool call, a rendered DOM, an
outbound request), and never report model chatter alone as a finding.
