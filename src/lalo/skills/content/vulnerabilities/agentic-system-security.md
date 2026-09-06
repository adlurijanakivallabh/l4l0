---
name: agentic-system-security
category: vulnerability
description: Security testing for a target's own AI-agent and MCP-style tool ecosystem — effective authority, confused-deputy tool abuse, and cross-tenant isolation, with a per-class proof ladder
keywords: [mcp security, agentic security, confused deputy, tool authorization, ai agent pentest, model context protocol]
---

# Agentic System Security (Target-Side Agent/MCP Ecosystems)

Use this skill when the ENGAGEMENT TARGET itself is (or embeds) an AI
system that selects tools, retrieves resources, invokes other services,
or delegates to other agents — an MCP server, an autonomous coding/support
agent, or an internal tool-calling pipeline. This is a distinct failure
mode from [[llm-prompt-injection]]'s instruction/data confusion: here the
question is what real-world AUTHORITY the agent runtime carries, and
whether that authority is checked at the point it's actually used. Prompt
text is never an authorization boundary — treat the target's agent runtime
as a confused deputy whose effective authority is the union of its
credentials, tools, and network/filesystem reach, then narrow that to what
is actually reachable given real scopes, routing, and approval flow.

## Attack Surface

- Any tool, resource, or delegated-agent capability the target's agent can
  invoke — read, write, execute, communicate (send/publish/purchase), or
  identity/admin actions.
- MCP-style tool servers specifically: stdio, HTTP, and SSE transports each
  with their own authentication/authorization model, often assumed but
  never actually verified per-transport.
- Any point where untrusted user or document content can influence WHICH
  tool runs, on WHAT target, or WITH WHICH arguments — this is the
  confused-deputy core of the class.
- The executable supply chain behind every tool/plugin/skill the agent can
  load: package source, pinned vs. mutable version, and what happens on a
  missing/misspelled name (a public-registry fallback is a real code-
  execution boundary, not a naming inconvenience).

## Recon

- Draw the effective-authority path for the specific capability under
  test: user/content input → the agent's planning/tool-selection step →
  the invoked tool or delegated agent → the credential it uses against the
  real target system → the resulting side effect or returned data.
- For each tool the agent can call, determine: is the argument validated
  independently AT THE TOOL BOUNDARY, or only trusted because "the model
  chose it"? A tool description or system-prompt instruction is never
  itself an authorization check.
- Enumerate advertised tools/resources via the protocol itself (where
  reachable) and compare against what the UI/product surface actually
  exposes — a tool reachable directly through the protocol but hidden from
  the UI is still live attack surface.
- For a consequential (state-changing) tool action, check whether an
  approval step — if one exists — actually re-validates the EXACT
  arguments, target, and credential at execution time, or only approves a
  generic "continue?" that arguments can still change after.

## Techniques (start quiet, escalate only as needed)

1. **Read-to-write escalation via untrusted content.** Feed the agent
   content (a document, a tool result, a web page) it will process in a
   read-only-seeming task ("summarize this") that instructs it to instead
   perform a WRITE or consequential action (send, delete, modify,
   purchase) — confirm whether the agent actually executes the escalated
   action or merely narrates it.
2. **Tool-argument boundary probe.** Supply missing, extra, duplicate, or
   cross-tenant identifiers as tool arguments (directly if the protocol is
   reachable, or via injected content if only the agent can reach the
   tool) and confirm whether the tool's OWN validation — not the model's
   judgment — rejects an out-of-scope value.
3. **Approval re-validation probe.** Where a human-in-the-loop approval
   step exists, get the tool call approved for one set of arguments, then
   attempt to have the ACTUAL executed arguments differ (a different
   recipient, amount, or target) from what was shown at approval time.
4. **Cross-tenant/identity isolation probe.** Vary user, workspace, or
   session identity independently and test whether the agent's tool
   results, cached context, or memory leak across that boundary — a
   retrieval tool returning another tenant's data because a filter is
   applied by the MODEL rather than the tool's own query is a common gap.
5. **Transport-specific authorization probe.** For an MCP-style server
   reachable over more than one transport (stdio locally, HTTP/SSE
   remotely), confirm the SAME authorization and argument checks apply on
   every transport — a check enforced only in one code path is a real,
   separate gap per [[closure-discipline]]'s "control on a different
   path" trap.
6. **Executable-component supply-chain probe.** Where the agent can load a
   skill/plugin/tool-server by name, test whether a missing or
   misspelled name falls back to fetching from a public registry/search
   path under the agent's own runtime authority — this is a real code-
   execution boundary if the fallback is automatic and unauthenticated.

## Proof Ladder

- **L1 — authority mapped, gap suspected.** The effective-authority path
  is drawn and a specific missing check (argument validation, approval
  re-validation, transport-specific authorization) is identified, but no
  actual escalated action has been triggered yet.
- **L2 — escalation reaches the tool boundary.** The crafted content or
  argument is confirmed reaching the tool/delegated-agent call with the
  attacker-influenced value intact — but the tool's own execution and side
  effect have not yet been independently confirmed.
- **L3 — real side effect proven at the target.** The tool call actually
  executes against the real target system with attacker-influenced
  arguments (a message actually sent, a record actually modified, data
  actually returned across a tenant boundary), confirmed at the target
  and/or its audit log, not from the model's own narration. This is the
  threshold for a reportable finding.
- **L4 — systemic or high-value compromise.** The gap is shown reachable
  across multiple transports/identities (not a one-off), or the
  confused-deputy chain reaches an identity/admin-level action, a
  cross-tenant credential, or arbitrary code execution via the supply-
  chain fallback path.

Calibrate severity separately per [[severity-calibration]] — a read-only
cross-tenant leak via a mis-scoped retrieval tool is high; a confused-
deputy chain reaching a consequential write/purchase/delete action or
arbitrary tool-server code execution is critical.

## Validation and False-Positive Discipline

Apply [[closure-discipline]] before recording anything. Class-specific
traps to check before calling something confirmed:

- The model claiming a tool ran, with no corresponding effect at the real
  target or in its audit log, is not evidence — always confirm the actual
  target-side state or a genuine audit entry, never the agent's own
  narrated summary.
- A tool that is LISTED as available to an identity is not proof it can be
  successfully INVOKED by that identity — confirm the call itself
  succeeds with attacker-controlled arguments, not just that discovery
  enumerated it.
- A safety refusal that changes the model's wording but leaves the
  underlying tool call blocked by a real server-side check is not a
  bypass — confirm the actual capability was exercised, not just that the
  model's refusal language changed.
- Cross-session or cross-tenant "leaked" content that turns out to be
  synthetic, cached public data, or a hallucinated fabrication rather than
  genuinely another identity's real data is not a finding — verify the
  disclosed content against a known, distinguishing marker belonging to
  the other identity.

## Impact

Unauthorized privileged actions performed by a confused-deputy agent
(sending, publishing, deleting, purchasing) on the attacker's behalf,
cross-tenant data exposure through under-scoped tool queries or shared
memory/cache, and — via the executable-component supply chain — arbitrary
code execution under the agent runtime's own authority.

## Summary

Agentic-system security is capability security: map the agent's real
effective authority through its credentials and tools, validate
authorization and approval AT THE TARGET-SIDE EFFECT rather than in
prompt text or model judgment, and treat every loadable tool/plugin as
executable supply chain.
