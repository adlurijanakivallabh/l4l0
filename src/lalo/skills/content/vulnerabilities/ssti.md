---
name: ssti
category: vulnerability
description: Server-side template injection — engine fingerprinting, sandbox escape, and a per-class proof ladder toward RCE
keywords: [ssti, server side template injection, template injection, jinja, twig, freemarker, velocity]
---

# Server-Side Template Injection

SSTI happens when user input reaches a template engine as syntax to
evaluate rather than as a data value bound into an already-fixed template.
Because template engines exist to evaluate expressions, and most expose the
host language's own runtime one way or another, the discovery cost is low
(a simple math expression) but the path from discovery to code execution
differs sharply per engine — engine fingerprinting is the load-bearing
step, not an afterthought.

## Attack Surface

- Anywhere user input plausibly becomes *part of the template itself*
  rather than a value substituted into an existing template: a "template
  editor" feature for tenants or admins, a string concatenated into a
  render call before rendering, or a notification/email/report template
  users can customize.
- Preview panes ("your message will look like…") are high-signal: they
  render user content live and are exactly where a template-injection
  probe is cheap to test.
- Do not confuse this with ordinary model-variable binding — a value bound
  as `context["x"]` and referenced as `{{ x }}` in an already-fixed
  template is normal, safe usage; the vulnerable pattern is the *template
  source itself* being built from user input.

## Recon

- Fingerprint the engine before crafting anything more than a minimal
  probe: different engines evaluate different expression syntaxes, so a
  single well-chosen arithmetic expression (rendering as its numeric
  result rather than being reflected literally) both confirms evaluation
  and narrows which engine family you are dealing with.
- Confirm with a *second*, different arithmetic expression before trusting
  the first result — a single coincidental-looking numeric reflection is
  not strong evidence on its own.
- Note whether output is reflected directly or only observable indirectly
  (response length/timing) — this determines whether you need a blind
  confirmation technique from the start.

## Techniques (start quiet, escalate only as needed)

1. **Engine fingerprint.** A minimal arithmetic probe in each major
   syntax family, confirmed by a second, different arithmetic probe. Do
   not proceed to gadget-chain payloads before you know which engine you
   are actually targeting — an engine-mismatched payload is wasted noise.
2. **Confirm evaluation, not just reflection.** The line between this
   class and a plain scripting-injection finding is whether the expression
   is *evaluated* (renders its computed result) versus merely reflected
   literally back at you — verify this distinction explicitly before
   treating anything as SSTI.
3. **Probe reachable context objects.** Once evaluation is confirmed,
   check which framework globals or context objects are reachable from
   inside the template (a request object, a configuration object, or
   similar) — what is reachable determines what gadget chain is even
   possible, and this differs per application, not just per engine.
4. **Walk to a code-execution primitive appropriate to the host
   language.** Every mainstream server-side templating language ultimately
   exposes some path from "expression evaluation" to "run an OS command"
   through its own reflection or introspection facilities — the exact
   chain is engine- and configuration-specific, so treat this as
   investigation, not payload lookup, once you know the engine.
5. **Blind confirmation, when output is not reflected.** A time-based
   delay or an out-of-band callback triggered from inside the template
   proves execution just as well as reflected output does, and is
   available in essentially every engine that has any reflection/runtime
   access at all.
6. **Sandbox-escape techniques, only against a confirmed sandboxed
   environment.** Attribute-lookup indirection, class/type-walk
   enumeration, and string-construction tricks to avoid a denylisted
   literal token exist specifically to get past a sandboxing layer you
   have already identified — do not reach for these before confirming a
   sandbox is actually present and blocking the direct approach.

## Proof Ladder

- **L1 — reflection observed, evaluation unconfirmed.** Your probe
  reflects, but you cannot yet tell whether it was evaluated or merely
  echoed back literally.
- **L2 — evaluation confirmed.** Two distinct arithmetic probes both
  render their computed results, proving the engine evaluated your input
  as template syntax rather than treating it as inert text.
- **L3 — runtime object access or code-execution primitive reached.** You
  reached a reachable framework/runtime object through the template, or
  achieved code execution via a time-based or out-of-band side effect.
  This is the threshold for a reportable finding.
- **L4 — command output captured or durable control demonstrated.** You
  captured the output of an executed command directly, or proved a
  durable effect (a file written, credentials read) beyond a single
  side-effect probe.

Calibrate severity separately per [[severity-calibration]] — SSTI reaching
confirmed code execution on an internet-exposed, unauthenticated surface is
typically critical; the same primitive gated behind a privileged
"template editor" feature intended for trusted admins is usually high
rather than critical, since the attacker position required is smaller.

## Validation and False-Positive Discipline

Apply [[closure-discipline]] before recording anything. Class-specific
traps:

- Template syntax reflected *literally* (your probe comes back unchanged,
  characters and all) is not SSTI — it is at most a scripting-injection
  concern in the surrounding HTML context, a different class entirely.
- A sandboxed environment where your probe evaluates but no reachable
  object exposes anything beyond arithmetic is a real, narrower finding
  (or arguably no finding at all) — do not claim code execution you have
  not actually demonstrated just because evaluation itself succeeded.
- A client-side templating library (one that runs in the browser, not on
  the server) evaluating your input is a different class with different
  impact — confirm the evaluation genuinely happens server-side before
  treating it as this class.
- Output that is HTML-escaped before display can make a real evaluation
  look like inert reflection — verify with a probe whose result is
  unambiguous even after HTML-escaping (a plain number), not one that
  could be confused with escaped markup.

## Impact

Remote code execution on the rendering host in the vast majority of real
cases, since most template engines expose some path to the host runtime;
server-side data exfiltration (filesystem, environment variables, internal
network access) via the same reflection capability; cloud credential theft
when the rendering host has cloud metadata access; and persistence via a
planted web shell or scheduled task once code execution is achieved.

## Summary

SSTI is a different failure mode from a scripting injection at the same
syntactic-looking location: the payload runs on the server, in the host
language, with whatever objects the engine happens to expose. Fingerprint
the engine before crafting a payload, confirm evaluation with two
independent probes, and treat any input that becomes template source
(never just a bound context variable) as code-execution-shaped until
proven otherwise.
