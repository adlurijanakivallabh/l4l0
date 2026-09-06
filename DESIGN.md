---
name: L4L0 Operator Console
description: A single scrolling conversation with a running autonomous pentest, on deep slate with a run-green accent.
colors:
  bg: "#0f172a"
  bg-rail: "#0b1220"
  surface: "#1b2336"
  surface-muted: "#242d44"
  border: "#334155"
  border-soft: "#263042"
  text: "#f8fafc"
  text-muted: "#94a3b8"
  text-faint: "#8291ab"
  accent: "#22c55e"
  accent-hover: "#1ea550"
  accent-ink: "#06210f"
  danger: "#ef4444"
  warning: "#f5a623"
  caution: "#e6c34a"
  focus: "#4ade80"
typography:
  brand:
    fontFamily: "ui-monospace, 'SF Mono', 'Cascadia Code', Menlo, Consolas, monospace"
    fontWeight: 700
    fontSize: "1.05rem"
    letterSpacing: "0.02em"
  body:
    fontFamily: "system-ui, -apple-system, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif"
    fontSize: "15px"
    lineHeight: 1.55
  agent-line:
    fontFamily: "system-ui, -apple-system, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif"
    fontSize: "0.92rem"
  label:
    fontFamily: "system-ui, -apple-system, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif"
    fontSize: "0.78rem"
    fontWeight: 600
  log:
    fontFamily: "ui-monospace, 'SF Mono', 'Cascadia Code', Menlo, Consolas, monospace"
    fontSize: "0.82rem"
    lineHeight: 1.55
rounded:
  sm: "7px"
  md: "10px"
  lg: "16px"
  pill: "999px"
spacing:
  xs: "6px"
  sm: "8px"
  md: "12px"
  lg: "18px"
  xl: "24px"
components:
  button-send:
    backgroundColor: "{colors.accent}"
    textColor: "{colors.accent-ink}"
    rounded: "999px"
    size: "36px"
  button-send-hover:
    backgroundColor: "{colors.accent-hover}"
  button-ghost:
    backgroundColor: "transparent"
    textColor: "{colors.text-muted}"
    rounded: "999px"
    padding: "9px 18px"
  composer-input:
    backgroundColor: "transparent"
    textColor: "{colors.text}"
    typography: "{typography.body}"
  finding-card:
    backgroundColor: "{colors.surface}"
    rounded: "{rounded.md}"
    padding: "10px 12px"
  chain-card:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.text-muted}"
    rounded: "{rounded.md}"
    padding: "10px 12px"
---

# Design System: L4L0 Operator Console

## Overview

**Creative North Star: "The Live Terminal Conversation"**

The console is a chat surface wearing a developer tool's palette: one scrolling thread, one composer, no dashboard of panels and no launch form. The operator's own sentence — a target plus an objective, typed in their own words — becomes the first chat bubble, and everything the running scan does (agent status, findings, chains, raw log output) narrates back as turns from "L4L0" in that same thread. This was a pinned override, twice over: away from a starship-terminal aesthetic toward "clean, like ChatGPT," and away from a two-field launch form toward "just a prompt, like a real conversation." The build honors both: there is no `<form>` with separate target/mission fields anywhere, and the terminal register survives only inside the raw-output log blocks, where it belongs (real tool output from inside the scan container), not as a decorative shell around the whole page.

Density is calm, not cramped: a slim 200px rail carries identity and live counters; the thread is centered and capped at 760px so long narration stays readable. The one deliberate visual departure from a pure chat app is the raw-output block, which groups consecutive log lines into a single monospace, scrollable readout rather than one bubble per line — the volume of tool output would otherwise drown the conversation.

**Key Characteristics:**
- One thread, one composer, no separate launch form or panel dashboard
- Deep slate base with a single vivid green accent, reused for both brand and "healthy/running" state
- No logo or icon; the wordmark is doing all identity work
- Severity is never color-alone: every finding pairs a colored pill with its own text label
- All dynamic, potentially target-influenced content renders via `textContent`/template cloning only — never `innerHTML`, `outerHTML`, `insertAdjacentHTML`, or `document.write` (verified: zero occurrences on any dynamic path)

## Colors

A near-monochrome dark slate field with exactly one saturated accent; severity colors are the only other hues admitted, and only on finding pills.

### Primary
- **Run Green** (`#22c55e`): the single accent. Used for the brand wordmark, the connected-state indicator dot and pill text, the focus/selection color pairing, message bubbles the operator sends, the send button, and hover states on interactive chrome (borders, links). It reads as "healthy / actively running," matching the product's live, unattended-monitoring use case.
- **Run Green Hover** (`#1ea550`): darker step for `:hover` on the accent-filled send button only.
- **Run Green Ink** (`#06210f`): the near-black text color used *on top of* the accent fill (user bubble text, send-button icon), never as a standalone token elsewhere.

### Neutral
- **Void Slate** (`#0f172a`): page background.
- **Rail Slate** (`#0b1220`): the rail's slightly darker background, separating it from the thread column without a heavy border.
- **Surface** (`#1b2336`): raised content — finding cards, chain cards, the composer bar, the connection pill.
- **Surface Muted** (`#242d44`): secondary raised surface — message avatars, disabled button fill, hover fill on ghost icon buttons.
- **Border** (`#334155`) / **Border Soft** (`#263042`): hairline dividers and default input/card borders; soft is used where the separation should be nearly invisible (rail/thread split, log block outline).
- **Text** (`#f8fafc`), **Text Muted** (`#94a3b8`), **Text Faint** (`#8291ab`): a three-step reading hierarchy — primary content, secondary labels (stat labels, timestamps), and tertiary/disabled content respectively.

### Named Rules
**The Severity-Never-Alone Rule.** Every severity pill (`sev-critical`/`sev-high`/`sev-medium`/`sev-low`/`sev-info`) pairs a distinct background color with its own text label rendered inside the pill — color is reinforcement, never the sole signal, per the operator's stated need to trust findings without relying on hue perception.

**The One Accent Rule.** Green is the only saturated brand color in the system. Warning (`#f5a623`), caution (`#e6c34a`), and danger (`#ef4444`) exist solely as severity-pill fills and never appear as decorative or brand color elsewhere in the UI.

## Typography

**UI Font:** `system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif`
**Log/Mono Font:** `ui-monospace, "SF Mono", "Cascadia Code", Menlo, Consolas, monospace`

**Character:** Plain and functional throughout — a system-font stack for every conversational and chrome element, reserving the monospace stack for two purposes only: the brand wordmark (a developer-tool signal) and genuine raw tool-output content (where monospace legibility for command/response text actually matters). This is a disclosed, deliberate substitution: the project's own stylesheet header records that it stays dependency-free (no build step, no external font fetch) and swaps the originally-considered Google-hosted pairing (JetBrains Mono / IBM Plex Sans) for equivalent system stacks. Treat the system-stack choice as the shipped, normative one — not a placeholder awaiting a webfont.

### Hierarchy
- **Brand** (700, 1.05rem, mono, 0.02em tracking): the "L4L0" wordmark in the rail. The only branded, monospace, colored (accent) text label in the chrome.
- **Body / Agent-line** (400–600, 0.92rem, sans): conversational content — the opening prompt, agent narration lines, message bubble text.
- **Label** (600, 0.78rem, sans): rail stat labels (`dt`), connection-pill text.
- **Stat value** (700, 0.86rem, sans, tabular-nums): the live Agents/Findings/Chains/Elapsed counters — tabular figures so digits don't jitter the layout as they update.
- **Status tag** (700, 0.68rem, sans, uppercase, 0.03em tracking): the agent-status badge (e.g. "RUNNING") inside a narration line.
- **Log** (400, 0.82rem, mono, 1.55 line-height): raw tool-output content inside a `.log-block`.

### Named Rules
**The Mono-Means-Machine Rule.** Monospace is reserved for two things only — the brand wordmark and real tool output — never used for conversational text, labels, or UI chrome, so its appearance always signals "this came from the running tool," not decoration.

## Layout

A fixed two-column shell: a 200px left rail and a flexible main column (`grid-template-columns: 200px 1fr`), both at minimum full viewport height. The main column centers a single `.thread-wrap` capped at 760px, so the conversation reads as a column even on wide screens. The thread itself is the scrollable region (`flex: 1; overflow-y: auto`); the composer bar sits pinned at its bottom, non-scrolling.

Spacing is a loose 6–24px rhythm: 18px padding around rail content with 18px gaps between rail groups, 24px page padding around the thread on desktop, 16px gaps between messages in the thread, and 8–12px internal padding inside cards and pills. There is no dense/compact mode — the system assumes one operator reading one long-running session, not a data-grid density.

At ≤900px the rail collapses from a vertical column to a horizontal wrapping bar above the thread, and the thread height is computed against a hardcoded rail height. This mobile breakpoint exists in the shipped CSS but was not polished in this pass — see Do's and Don'ts.

## Elevation & Depth

Flat by default: almost the entire UI (rail, thread, cards, pills) uses tonal layering — successive lighter slate steps (`--bg` → `--surface` → `--surface-muted`) — rather than shadows to indicate raised content. The one shadow in the system is a barely-there `0 1px 2px rgba(0,0,0,0.25)` on the composer bar, just enough to lift it off the thread behind it as it sits pinned at the bottom; nothing else in the build casts a shadow.

### Shadow Vocabulary
- **Composer lift** (`box-shadow: 0 1px 2px rgba(0, 0, 0, 0.25)`): the only shadow in the system; marks the composer as the one fixed, always-interactive surface.

### Named Rules
**The Tonal-Not-Cast Rule.** Depth between the rail, thread, cards, and page background is conveyed by stepping through the slate scale (`--bg`/`--bg-rail`/`--surface`/`--surface-muted`), not by shadow. Reach for the next tonal step before reaching for a shadow.

## Shapes

Two radius registers, used consistently by role: **pill** (`border-radius: 999px`) for anything interactive and self-contained — buttons, the connection status pill, the jump-to-latest pill, severity pills — and **soft-rectangle** (`--radius-sm` 7px / `--radius-md` 10px / `--radius-lg` 16px) for containers — finding cards, chain cards, log blocks, message avatars. The one asymmetric shape in the system is the user's chat bubble, which rounds three corners at `--radius-md` and sharpens the bottom-right corner to 4px — the standard "tail" cue that this bubble belongs to the sender on the right. Borders throughout are 1px hairlines in `--border`/`--border-soft`; no heavier strokes appear anywhere.

## Components

### Buttons
- **Shape:** pill (`border-radius: 999px`) for every button in the system; no square or soft-rectangle button exists.
- **Send (primary):** circular 36×36px accent-filled icon button (`--accent` fill, `--accent-ink` icon), used only in the composer.
- **Ghost (secondary):** transparent fill, `--border` outline, `--text-muted` label; used for "Stop scan." Hover shifts border and text to `--danger` — the only place danger-red appears outside severity pills, signaling a destructive action.
- **Disabled:** ghost buttons drop to `--text-faint` text and `--border-soft` outline with `not-allowed` cursor; the send button drops to `--surface-muted` fill.

### Cards / Containers
- **Corner Style:** `--radius-md` (10px) on finding cards and chain cards.
- **Background:** `--surface`, one step lighter than the page.
- **Shadow Strategy:** none — depth from tonal contrast against the page background (see Elevation & Depth).
- **Border:** none on finding/chain cards; the log block is the exception, with a `--border-soft` hairline.
- **Internal Padding:** 10px 12px.

### Inputs / Fields
- **Style:** the composer input has no border or fill of its own — it sits transparent inside `.composer-bar`, a pill-shaped 1px-bordered container (`--surface` fill, `--border-soft` outline). The pill, not the input, carries the visible field chrome.
- **Focus:** the composer bar's border shifts to `--accent` on `:focus-within`; the input itself suppresses its own focus ring (`outline: none`) since the parent pill already signals focus.
- **Disabled:** input text drops to `--text-faint` when the field is disabled (mid-request).

### Navigation
There is no traditional nav; the rail functions as persistent status chrome rather than a navigable menu: wordmark (plain text, no icon), a connection-status pill (dot + label, green when connected, amber/`--warning` when disconnected), a "Stop scan" ghost button (hidden until a scan starts), and four live stat counters (Agents/Findings/Chains/Elapsed) laid out as a definition list. On mobile it reflows from a vertical column to a horizontal wrapping bar; there is no separate mobile nav pattern.

### The Composer (signature component)
The single input the whole product turns on. Pre-scan, submitting it regex-extracts a target (URL or IPv4/CIDR) from the typed sentence and POSTs `/scan` with the full text as the mission — there is no separate target field. Once a scan is live, the identical box POSTs to `/steer` instead; a `.composer-note` beneath it states in plain text that this mode is read-only and cannot record a finding or affect confirmation, keeping the read-only boundary visible rather than merely documented. The composer never changes shape or position between these two modes — only its wiring and the note beneath it change.

### Agent Turn (signature pattern)
Findings, chains, agent-status updates, and raw log lines are not four different UI treatments — they all render into the thread via one shared `newAgentTurn()`-style helper as a turn from "L4L0," using the same avatar and message-body slot. Only the *content* inside the turn varies (a `.finding-card`, a `.chain-card`, an `.agent-line`, or a `.log-block`). Consecutive log lines coalesce into one growing `.log-block` per contiguous run rather than one message per line, keeping the thread scannable under high-volume tool output.

## Do's and Don'ts

### Do:
- **Do** render every dynamic, target- or agent-influenced value via `textContent` or cloned `<template>` content only. No `innerHTML`, `outerHTML`, `insertAdjacentHTML`, or `document.write` on any dynamic path — this is a security invariant, not a style preference.
- **Do** pair every severity indicator with a visible text label; never encode severity by color alone.
- **Do** route every new operator-facing surface (findings, chains, status, logs) through the shared "L4L0 turn in the thread" pattern rather than inventing a separate panel or modal.
- **Do** keep the accent (`#22c55e`) singular — reserve it for brand, "connected/healthy," and the user's own sent messages; don't introduce a second brand hue.
- **Do** use the pill radius (999px) for anything clickable/self-contained and the soft-rectangle radii for containers, per the existing split.

### Don't:
- **Don't** add a second input field, a launch form, or a dashboard of panels — the single composer and single thread are the pinned, load-bearing decision for this surface, confirmed twice over user course-correction (away from a form, away from a starship-terminal look).
- **Don't** add a logo mark or icon next to the wordmark — the identity is deliberately text-only ("L4L0" in mono, accent-colored); this is confirmed, not a placeholder awaiting an asset.
- **Don't** treat the composer's steering mode as a full chat channel — its note must always state plainly that it is read-only and cannot record findings, matching the product's non-negotiable read-only steering constraint.
- **Don't** carry the ≤900px mobile layout forward as a validated pattern: the mobile media query computes thread height against a hardcoded rail height and was explicitly deprioritized in favor of desktop for this pass ("who needs for mobile") — treat mobile as unpolished, not as an example to extend, until it gets its own pass.
