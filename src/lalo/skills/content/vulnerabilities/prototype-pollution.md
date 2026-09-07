---
name: prototype-pollution
category: vulnerability
description: Prototype pollution — __proto__/constructor.prototype injection via merge, deep-clone, and query-string sinks, and a per-class proof ladder
keywords: [prototype pollution, proto, constructor.prototype, object.prototype, merge, deep clone, gadget, json pollution]
---

# Prototype Pollution

JavaScript objects inherit from a shared prototype chain, and a merge, deep
clone, or query-string parser that walks attacker-controlled keys without
excluding `__proto__`, `constructor`, and `prototype` will happily write
through to `Object.prototype` itself. Once that write lands, *every* object
in the runtime that does not already define the polluted property inherits
the attacker's value — turning one unguarded recursive-assignment sink into
a runtime-wide fault injection. The technique is entirely about finding the
write primitive first, and only afterward finding a gadget in the
application's own logic that turns "a property exists that shouldn't" into
real impact.

## Attack Surface

- Any recursive merge, extend, or deep-clone utility (hand-rolled or a
  library helper) that copies keys from an attacker-controlled object onto
  a target without an explicit denylist for `__proto__`, `constructor`, and
  `prototype`.
- Query-string and form-body parsers that expand bracket/dot notation into
  nested objects (`a[__proto__][x]=y`, `a.constructor.prototype.x=y`) — the
  vulnerable code path is often several layers removed from anything that
  looks like "merge" in its own name.
- `JSON.parse`-based config loaders and settings importers that then merge
  the parsed object into a live application-config object — `JSON.parse`
  itself is not exploitable in isolation (a bare `__proto__` key in JSON
  becomes an *own* property, not a prototype write) but the merge step
  immediately after it usually is.
- Both client-side (browser JS, a frontend framework's state/store merge)
  and server-side (Node.js request-body merge into config or session
  objects) instances exist and must be tested as distinct surfaces — the
  write primitive is identical, but the reachable gadgets and resulting
  impact differ completely between the two.

## Recon

- Identify every place attacker input reaches a recursive merge/clone/
  extend operation: request-body parsing into a config object, a
  "deep-merge user preferences" step, a templating engine's data-binding
  layer, or a query-string library's own object-expansion logic — read the
  actual merge implementation rather than assuming a named library is safe
  by reputation; several widely-used libraries had exactly this class of
  bug before patching, and an unpinned or outdated version is a concrete,
  checkable fact, not a guess.
- Note the runtime and hosting context, since it determines the payload
  path: a Node.js backend gives access to `require`/`child_process`-shaped
  gadgets not present in a browser sandbox; a browser client gives access
  to DOM sinks (`innerHTML`, a templating library's `srcdoc`/`src`
  attributes) not present server-side.
- Enumerate what application logic later reads properties off arbitrary
  objects without checking `hasOwnProperty` — every one of these is a
  candidate gadget, since it will read the polluted value on the prototype
  chain as if it were a legitimate own property of whatever object it was
  called on.
- Look specifically for config/options objects consumed by security-
  relevant logic downstream (an `isAdmin` flag, a `disableAuth` flag, a
  template-engine option toggle, a child-process spawn option) — these are
  the highest-value gadgets because pollution alone flips their effective
  value everywhere the object is read.

## Techniques (start quiet, escalate only as needed)

1. **Write-primitive confirmation, side-effect-free.** Submit a body or
   query string that attempts to set an inert, easily-observed property
   (`__proto__[pollutedMarker]=true` or the equivalent bracket/dot
   variant for the sink in question) and check, via any endpoint or
   behavior that would reflect an unexpected property on a plain object,
   whether the marker now appears — this proves the write primitive exists
   without touching anything that could affect other users or the
   application's real behavior.
2. **Sink-shape enumeration, once the write primitive is confirmed.** Try
   the three common syntaxes in turn — `__proto__.key`, `__proto__[key]`,
   and `constructor.prototype.key` — since which one the specific
   parser/merge implementation accepts (or nested-array variants of the
   same) is implementation-specific and not worth guessing; use whichever
   is confirmed and drop the others rather than testing all three on every
   subsequent step.
3. **Gadget search on already-identified downstream reads, only after the
   write primitive is confirmed.** With a working write primitive in hand,
   walk the application's own logic (not a generic public gadget list
   copied blind) for a property read that changes behavior — a template
   engine's `escape`/`allowUnsafe`-style option, an auth-check `isAdmin`/
   `role` default, a request-handling `debug`/`trustProxy` flag — and
   confirm each candidate individually rather than polluting broadly and
   hoping something breaks, since a broad pollution can also degrade
   the application for every other user of the same process.
4. **Client-side DOM-sink escalation, when the target is browser-side.**
   If a confirmed gadget feeds a DOM sink (a client-side router or
   templating library reading a polluted default that ends up in
   `innerHTML`/`srcdoc`/an event-handler attribute), demonstrate the
   resulting DOM XSS with a benign, clearly-marked payload — treat this as
   its own proof of a chained XSS, not merely "prototype pollution found."
5. **Server-side RCE/auth-bypass escalation, when a genuine security-relevant
   gadget is confirmed.** Only after a specific gadget is shown to read the
   polluted property and act on it, attempt the minimal proof for that
   specific impact — a config flag that disables an auth check demonstrated
   by then reaching an endpoint that should have required authentication;
   a template-engine option that enables unsafe evaluation demonstrated by
   a single benign expression evaluation, never an unbounded RCE payload
   on a shared or production process.

## Proof Ladder

- **L1 — write primitive confirmed on Object.prototype.** An inert marker
  property is shown to land on the shared prototype via the merge/clone/
  parse sink, observable on an unrelated plain object elsewhere in the
  application, but no downstream read (gadget) has been identified yet.
- **L2 — a gadget is identified but its effect is not yet demonstrated.**
  A specific line of application logic is shown to read the polluted
  property without an own-property check, and the code path that would be
  affected is understood, but the actual behavioral change has not yet
  been triggered end to end.
- **L3 — a genuine behavioral or security impact is demonstrated.** The
  gadget's effect is triggered for real: a DOM sink executes attacker
  content, an auth check is bypassed, or a downstream option meaningfully
  changes server behavior in a security-relevant way, reproducible on a
  second attempt. This is the threshold for a reportable finding.
- **L4 — durable or systemic exploitation.** The gadget yields remote code
  execution, a full authentication bypass reachable by any user, or the
  pollution persists across requests/sessions on a shared server process
  (rather than being scoped to the triggering request), affecting other
  users without their own action.

Calibrate severity separately per [[severity-calibration]] — a demonstrated
RCE or full auth-bypass gadget is typically critical; a confirmed write
primitive with an identified but only partially-demonstrated gadget is
usually medium, reflecting the genuine open proof gap on impact.

## Validation and False-Positive Discipline

Apply [[closure-discipline]] before recording anything. Class-specific
traps:

- A merge/clone utility that explicitly denies `__proto__`, `constructor`,
  and `prototype` keys (confirmed by reading its actual implementation, not
  assumed from its name or popularity) is a control working correctly —
  test the exact denylist for gaps (case variants, a Unicode homoglyph, a
  key reachable via a different bracket-notation encoding) before ruling it
  out entirely.
- A confirmed write primitive with no identified gadget is a real but
  incomplete finding — record it as `open_proof_gap` on impact rather than
  either dropping it or inflating it to a severity the missing gadget does
  not justify; do not claim RCE or auth bypass without triggering the
  specific gadget.
- `JSON.parse` alone never causes prototype pollution in modern engines — a
  bare `"__proto__"` key parsed from JSON becomes an ordinary own property
  of the resulting object, not a prototype write; the vulnerability is
  always in a *subsequent* merge/assign step, so confirm that step exists
  and is actually reached before claiming a `JSON.parse`-adjacent finding.
- Node.js versions and library versions patched against a specific known
  CVE for the exact merge function in use are the control working as
  intended — confirm the actual running version and the actual code path
  taken, not just the presence of the library's name in a dependency
  manifest.
- A gadget that only affects the polluting request's own execution context
  (a pollution that is reset per-request in a framework using a fresh
  object graph per request) has materially lower impact than one that
  persists on the long-lived process-wide prototype — confirm which case
  applies before rating severity.

## Impact

Client-side: DOM-based cross-site scripting via a polluted default that
feeds a rendering or templating sink. Server-side: authentication and
authorization bypass via a polluted config flag, denial of service via a
polluted property that breaks unrelated request handling process-wide, and
remote code execution when a polluted option reaches an unsafe evaluation,
templating, or child-process code path.

## Summary

Prototype pollution is a two-stage bug: a write primitive onto a shared
object, and a gadget elsewhere in the application that reads from that same
shared object without an own-property check. Confirm the write primitive
first with an inert marker, then search the application's *own* logic for
a specific, security-relevant gadget before claiming any impact beyond the
write itself — an unexploited write primitive is a real but incomplete
finding, not RCE.
