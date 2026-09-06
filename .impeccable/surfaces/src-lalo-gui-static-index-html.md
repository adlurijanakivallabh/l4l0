---
version: 1
slug: "src-lalo-gui-static-index-html"
primary_target: "src/lalo/gui/static/index.html"
related_targets: ["src/lalo/gui/static/app.css","src/lalo/gui/static/app.js"]
---

## Scope and visitor mode

Operate. Single authorized operator monitoring exactly one live L4L0 scan. Backend
API/WebSocket contract (`src/lalo/gui/app.py`) is unchanged.

## Audience, job, action/task, proof/content, constraints

Security operator watching a real, authorized engagement run autonomously. Job: trust what
is happening, never miss a finding or a stalled run, launch and steer by talking to it.
Constraint: every dynamic value is potentially target-influenced content and must render as
text only, never parsed as HTML. Severity must read without relying on color alone.

## Direction contract

THESIS: The whole console IS the conversation — not a dashboard with a chat bolted on, and
not a form sitting above a thread. One scrolling thread; one composer box does everything.
OWN-WORLD: Deep slate surface, vivid green accent, plain wordmark (no icon/logo). Findings,
chains, agent status, and log runs each render as a turn from "L4L0" in the same thread a
real conversation would use.
STORY: The agent asks what to test. The operator types one line — a target plus an
objective, in their own words. That line becomes their first message. Everything after is
L4L0 narrating, in the same thread, as it works. The same box later carries read-only
steering once a scan is live.
FIRST VIEWPOINT: A slim left rail (wordmark, connection pill, Stop, live Agents/Findings/
Chains/Elapsed counters) beside a centered message thread, composer pinned at the bottom.
FORM: User-pinned twice over: first away from a starship-terminal roll toward "clean, like
ChatGPT"; then explicitly away from a two-field launch form toward "just a prompt, like a
real conversation" — both stand as pinned overrides of whatever came before them.
FINISH: unreviewed and undocumented is unfinished.

## Chosen direction and memorable moment

Starting a scan is not filling out a form — it is sending the first message. The operator's
own sentence becomes a real chat bubble, and L4L0's reply is the scan itself, unfolding live.

## Unresolved decisions

None outstanding — accent, layout, and composer behavior are all settled and shipped.
