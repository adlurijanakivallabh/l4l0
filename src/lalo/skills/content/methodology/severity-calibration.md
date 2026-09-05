---
name: severity-calibration
category: methodology
description: A rubric for what genuinely deserves high or critical severity, applied after closure discipline, before computing a CVSS vector
keywords: [severity, cvss, critical, high, medium, low, calibration, rating]
---

# Severity Calibration

CVSS gives you a number once the metrics are chosen. This skill is about
choosing those metrics honestly — deciding what class of finding genuinely
belongs at each severity level before filling in the vector.

Calibrate severity **after** you have established reachability and run the
closure-discipline pass on the finding, never before. Severity is a
conclusion drawn from evidence, not an opening position you work backward
from.

## The Test That Matters

Before rating anything high or critical, ask:

> Would this be accepted as high or critical in a serious security review,
> by a team putting its reputation on the assessment?

If the honest answer is "only if you accept a chain of unproven
assumptions," it is not high. Rate the weakness you actually proved, not the
worst case you can imagine chaining it into.

## Critical

Reserve for findings where a realistic attacker gets decisive control or
mass data access, with real evidence:

- Unauthenticated remote code execution, or code execution reachable by any
  user on an internet-exposed surface.
- Full authentication bypass, or trivially forgeable authentication (an
  unsigned or algorithm-confused token accepted, a signature never checked).
- Mass extraction of other users' or other tenants' sensitive data.
- Compromise of signing keys, control-plane credentials, or credentials
  granting broad infrastructure access.
- A complete cross-tenant isolation failure in a multi-tenant system.

Factors that push a high up to critical: no authentication required,
internet-reachable, zero user interaction required, self-propagating, or
impact spanning every tenant rather than one.

## High

- Authenticated remote code execution, or execution requiring only a common,
  non-privileged role.
- Privilege escalation crossing a real trust boundary (user to admin, one
  tenant to another, read to write on protected objects).
- Object-level authorization failures exposing or modifying other users'
  sensitive data at scale.
- Injection reaching real data, not just a proof-of-concept sleep or error.
- Server-side request forgery that demonstrably reaches internal services,
  cloud metadata, or credentials.
- Sensitive credential or personal-data exposure an attacker can actually
  reach, not merely a field that theoretically contains one.

## Medium

- Stored cross-site scripting in a limited context, or reflected scripting
  requiring victim interaction.
- Cross-site request forgery on a meaningful state-changing action.
- Authorization gaps on lower-value objects.
- Information disclosure that materially aids a further attack step.
- A finding whose high-impact version is blocked by a real, confirmed
  constraint (internal-only exposure, a required privileged role, a narrow
  precondition you verified).

## Low / Informational

- Missing security headers, cookie-flag issues, verbose error messages.
- Self-inflicted scripting issues, or scripting that requires the victim to
  paste the payload themselves.
- Open redirect with no credential or token leakage alongside it.
- Rate-limiting or enumeration issues with no demonstrated further impact.
- A defense-in-depth gap with no reachable exploitation path behind it.

## Usually NOT High or Critical

These get over-rated constantly. Each needs unusual, demonstrated
circumstances to exceed medium:

- Self-inflicted scripting and clickjacking on non-sensitive actions.
- Missing headers, cookie attributes, or TLS configuration nits alone.
- An open redirect on its own, with nothing chained to it.
- A theoretical memory-safety issue with no reachable attacker input.
- "Could matter if chained with several unproven assumptions."
- Anything already requiring admin, shell, or physical access — if the
  attacker already has that, the finding adds little on top.
- A session weakness that requires the attacker to already hold a victim's
  secret (a stolen cookie, an intercepted link) — unless this same finding
  is what gets them that secret, acquiring it is not free.
- Enumeration that only confirms an account, domain, or version exists.

## Downgrade, Don't Delete

A finding that turns out to be more constrained than it first looked gets a
lower severity, not a silent drop. Internal-only reachability, a required
privileged role, or a narrow precondition are reasons to reduce severity and
say so — never reasons to withhold the finding.

Separately: missing evidence about deployment or exposure lowers your
*confidence*, not the severity floor. Do not treat "I could not confirm
this is internet-facing" as if it meant "this is internal-only" — those are
different claims with different evidence requirements.

## Acceptance Checklist for High / Critical

All of these must hold. If any does not, drop a level:

- The attack path is realistic and in scope — not a lab-only condition, not
  dependent on an unproven prior compromise.
- The attacker position required is one an attacker can actually obtain.
- The impact is demonstrated, not asserted — proven broad or systemic
  read/write access, not a single record you happened to reach.
- The closure-discipline pass found no constraint that meaningfully limits
  exploitation, or you can explain why the constraint does not actually
  hold on the real path.
- You have concrete evidence of reachability, not an assumption about how
  the system is deployed.
- You would defend this exact rating if someone else re-tested it.

## Output

Severity still comes from a computed CVSS vector — this rubric decides
which vector is honest. When your intuitive rating and the computed
severity disagree, re-examine the metrics first: usually the privileges-
required, attack-complexity, or impact-triad component was set
optimistically. Fix the metric that is wrong; do not override the computed
result to match your gut feeling.
