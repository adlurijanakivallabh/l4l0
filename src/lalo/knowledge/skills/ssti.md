---
name: ssti
class: ssti
summary: Find and prove server-side template injection (eval → often RCE).
---
# Server-Side Template Injection

User input is rendered as a template, letting you evaluate expressions and often
reach RCE.

## Attack surface
- Anything echoed via a template engine: name/greeting personalization, email/PDF
  templates, error pages, CMS blocks, subject lines, notification bodies.

## Recon / detect
- Send a polyglot arithmetic probe: `${7*7}`, `{{7*7}}`, `<%= 7*7 %>`, `#{7*7}`,
  `${{7*7}}`, `*{7*7}`. If the response contains `49` (and NOT the literal `7*7`),
  the template evaluated it — engine-fingerprint from which syntax worked.

## Techniques by engine (escalate to RCE, carefully)
- Jinja2/Twig: `{{7*7}}` → object traversal to `os`/`subprocess` for RCE.
- Freemarker/Velocity (Java): `${...}` → `Runtime.exec`.
- ERB (Ruby): `<%= system('id') %>`. Smarty/Mako/Handlebars variants.
- Prove RCE with a benign command (`id`) or an OOB callback; delegate crafting to
  the `task` sub-agent / free shell.

## Proof ladder
- L1: probe accepted. L2: partial (some math evaluated). L3: expression evaluated
  (49) — SSTI confirmed. L4: RCE proven (command output / OOB) via the engine.

## Validation / false positives
- The literal `7*7` echoed back is NOT SSTI (no evaluation). Require the computed
  product to appear while the literal does not.
- Client-side template frameworks are DOM/XSS, not server-side — confirm the
  evaluation happens server-side (present in the raw HTTP response).
