---
name: counterevidence
class: coordination
summary: The adversarial-honesty pass every finding must go through before recording.
---
# Counterevidence — Argue Against Your Own Finding

Before calling `record_finding`, argue the STRONGEST case AGAINST it:

- What non-vulnerability explanation could produce the same observation
  (generic error handling, a WAF, caching, an unrelated bug)?
- What would you need to see to be WRONG about this?
- Is your evidence actually grounded in something you fired and captured, or are
  you inferring/assuming?

Record this honestly in `counterevidence`, and in `severity_change_conditions`
state the ONE concrete thing that would raise or lower the severity (e.g. "if
this reaches a table with PII, raise to critical"; "if the app validates this
server-side elsewhere, lower to informational").

This is not busywork — a real INDEPENDENT adversarial review will run against
your evidence afterward and try to disprove it using only what was actually
captured (see the confirmation pipeline). A finding with honest, specific
counterevidence survives that review better than a self-congratulatory one:
"missing information is NOT proof of safety" applies to your finding just as
much as to your skepticism of it.
