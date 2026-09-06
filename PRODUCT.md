# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Stack

Existing codebase: FastAPI backend (`src/lalo/gui/app.py`) serving a static single-page app
(`src/lalo/gui/static/index.html`/`app.css`/`app.js`) with no build step, no framework, no
bundler. Staying dependency-free for this redesign (delegated: kept the incumbent's own
"minimal SPA" approach per the project's own stated design — plain HTML/CSS/vanilla JS).

## Users

A single authorized security-testing operator (a pentester or security engineer) running L4L0,
an autonomous offensive-security agent, against a scope they have already declared. This GUI is
their live console for exactly one running scan at a time — there is no multi-tenant or
multi-user concept anywhere in this surface. The operator's job while watching: understand what
the autonomous agent(s) are doing right now (which agent, what task), see findings as they land
(severity + confidence), see attack-chain relationships between findings, watch raw tool output
for detail/debugging, and optionally nudge the run via a read-only steering message — all while
a real engagement is actively running against a real target.

## Product Purpose

L4L0 is a mission-prompt-driven autonomous agent that finds, exploits, and proves vulnerabilities
against an authorized target, running a free-shell think→act→observe loop inside a disposable,
isolated container, with multi-agent spawning for parallel/specialized work. This GUI is the
operator's only real-time window into that autonomous process: launch a scan, watch it work,
see what it finds, stop it if needed. Success for this surface means the operator can, at a
glance, trust what's happening and never miss a finding or a stalled/failed run.

## Positioning

Unlike a conventional vulnerability scanner's static report UI, this console is a live window
into an *autonomous agent's* reasoning and actions — it renders a categorized event stream
(status/log/agent/finding/steering/chain) from a cursor-resumable WebSocket, not a periodically-
refreshed report. The read-only steering channel (the operator can message the run, but that
channel has no code path to writing a finding or affecting confirmation) is a deliberate,
load-bearing product decision, not a placeholder — see Capabilities and Constraints.

## Operating Context

- One scan runs at a time; the operator launches it here with a target list and a mission
  statement, then watches it run, potentially for a long time (autonomous agents can run for
  many steps).
- The raw-output scrollback carries real tool output from inside the disposable scan container
  (command output, HTTP responses, etc.) — this is genuinely technical, often dense content, and
  it must stay fast to scan and easy to distinguish from the higher-level agent/finding/chain
  events, even after this redesign gives it real visual treatment (an earlier project convention
  kept it deliberately plain; that convention is explicitly overridden for this redesign, but the
  content itself is still a technical log an operator needs to scan quickly, not prose to read
  leisurely).
- The operator may be watching this for extended, unattended stretches (a long autonomous scan) as
  well as actively monitoring it moment-to-moment — both usage patterns are real.

## Capabilities and Constraints

- Confirmed functionality this surface must keep working exactly as today (backend contract is
  out of scope for this redesign, do not change `app.py`'s API/WebSocket surface): connection
  status indicator; a scan-launch form (target list + mission text, submit/stop); a live
  agent-status list; a live findings list (severity + confidence); a live attack-chain list; a
  live raw-output scrollback; a read-only steering chat (send a message, see the log — it cannot
  record a finding or affect confirmation, and the UI should not imply otherwise).
- Every dynamic value rendered (agent status, finding titles, chain node ids, event payload text,
  steering log lines) is potentially attacker- or target-influenced content and must never be
  parsed as HTML — text-only rendering (`textContent`/equivalent), no `innerHTML`, is a security
  constraint carried into this redesign, not just an incumbent style choice.
- Single connection token, generated per launch, gates the WebSocket and the steering endpoint —
  no login/account system, nothing to design there.

## Brand Commitments

Name: "L4L0". No existing logo/wordmark asset, no existing color identity — free to design a
wordmark treatment and visual identity from scratch for this redesign.

## Evidence on Hand

No user research, testimonials, or usage data exist for this internal operator tool. Do not
fabricate any.

## Product Principles

1. Never let the operator mistake technical/target-derived content for trusted UI chrome or an
   instruction — text-only rendering of all dynamic content is non-negotiable.
2. Legibility and fast scanning under long, information-dense sessions outrank decorative
   flourish — this is a tool an expert uses for hours, not a page someone visits once.
3. The steering channel's read-only nature must be visually obvious, not just documented in a
   tooltip — an operator should never wonder whether a steering message did more than it did.
4. A single-scan, single-operator surface: no need to design for multi-tenant, teams, or
   account management anywhere in this redesign.

## Accessibility & Inclusion

No specific standard was established for this internal tool; keep reasonable baseline
accessibility (sufficient color contrast, especially for severity-coded findings which must not
rely on color alone) since this may be used for long sessions and by more than one team member
over time.
