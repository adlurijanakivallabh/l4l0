---
name: information-disclosure
category: vulnerability
description: Information disclosure — error/debug leakage, DVCS and backup artifacts, source maps, and differential oracles, with severity triage and a per-class proof ladder
keywords: [information disclosure, stack trace, git exposure, source map, debug endpoint, sensitive data exposure]
---

# Information Disclosure

Information disclosure is an **amplifier**, not an endpoint in itself: a
leaked stack trace, config file, or source map rarely does damage on its
own, but it accelerates every other class by revealing exact versions,
internal paths, credentials, or schema shape. Treat every response byte,
header, and reachable artifact as potential intelligence, and hold this
class to a stricter severity discipline than most — see the triage rubric
below, since not every leak is a reportable finding.

## Attack Surface

- Error and exception output: stack traces, SQL/ORM error fragments,
  framework version banners, internal file paths, developer contact
  information.
- Debug/dev tooling left reachable in production: framework debuggers
  (Werkzeug, Rails error pages), profiler endpoints, feature-flag
  introspection.
- Version-control and backup artifacts: an exposed `.git`/`.svn`
  directory (reconstructable source and history), `.bak`/`.old`/`~`/`.swp`
  files, database dumps, zipped deployment archives.
- Configuration and secrets: `.env`, `phpinfo()`, `appsettings.json`,
  Docker/Kubernetes manifests — anywhere connection strings or credentials
  might be written to a path served directly.
- API schemas and introspection: OpenAPI/Swagger docs, GraphQL
  introspection, gRPC server reflection — each can enumerate hidden or
  privileged operations never referenced by the visible client.
- Client bundles and source maps: a `.map` file reveals original source,
  comments, and any secret embedded at build time (`NEXT_PUBLIC_*`,
  `VITE_*`, `REACT_APP_*` variables are meant to be public — check whether
  anything ELSE also ended up in the same bundle).
- Observability/admin surfaces reachable without auth: `/metrics`,
  `/actuator`, `/health`, tracing UIs (internal hostnames, process
  arguments), and public object-storage buckets or over-scoped signed
  URLs.

## Recon

- Build a channel map first — web, API, GraphQL, WebSocket, gRPC, mobile,
  exports, CDN — since hardening is frequently inconsistent ACROSS
  channels even when one is solid (a field hidden from the REST response
  can still appear in the GraphQL one).
- Establish a differential-oracle harness: compare the SAME resource as
  owner vs. non-owner vs. anonymous, normalizing on status code, body
  length, `ETag`, and `Last-Modified` — a byte-for-byte identical response
  regardless of identity is the baseline; any divergence is a signal worth
  chasing.
- Trigger controlled failures (malformed types, boundary values, missing
  required parameters, an unexpected content-type) specifically to surface
  error-handler output, which is often far more verbose than the happy
  path.
- Enumerate artifacts directly before trying payloads at all — DVCS
  folders, backup extensions, known config filenames, source maps, API
  docs endpoints — this class of check is cheap and frequently the fastest
  real win.

## Techniques (start quiet, escalate only as needed)

1. **Artifact enumeration.** Request `/.git/HEAD`, `/.git/config`, common
   backup suffixes against known source filenames, and standard config
   paths (`.env`, `web.config`, `appsettings.json`) — a 200 with real
   content, not just a non-404, is the actual signal.
2. **Error-triggering.** Submit malformed types, out-of-range values, and
   unexpected content-types specifically to provoke a stack trace or
   ORM/SQL error fragment; a template-engine probe (`{{7*7}}`) can
   separately fingerprint the templating stack via its own error output.
3. **Schema/introspection enumeration.** Fetch `/swagger`, `/openapi.json`,
   `/api-docs`; if GraphQL, attempt introspection (`__schema`/`__type`) —
   compare what's enumerated against what the actual client ever calls, to
   find operations with no UI path at all.
4. **Source-map and bundle mining.** Fetch `.map` files referenced by
   `//# sourceMappingURL=` comments and grep the reconstructed source and
   any embedded JSON blob (`__NEXT_DATA__`-style) for secrets, internal
   hostnames, or fields never rendered in the UI.
5. **Differential-oracle probing.** For a resource reachable at multiple
   identity levels, diff the exact response (status, length, headers) as
   owner vs. non-owner vs. anonymous, and check `HEAD` vs. `GET` and
   conditional-request (`If-None-Match`/`If-Modified-Since`) behavior for
   existence leaks that never return a body at all.
6. **Cache/CDN identity-key probing.** Check whether a CDN or reverse
   proxy caches a response WITHOUT varying on `Authorization` or a
   tenant header — a cache hit serving one identity's data to another is a
   severe variant of this class, not a cosmetic one.

## Proof Ladder

- **L1 — artifact or leak reachable.** The artifact, error output, or
  schema endpoint is confirmed reachable and returns real content — but
  its actual sensitivity has not yet been assessed against the triage
  rubric below.
- **L2 — genuinely restricted content confirmed.** The specific data
  disclosed is confirmed non-public (not documented, not intended client
  data) via the differential-oracle comparison — distinguishing it from
  the common false positive of "technically new, practically harmless."
- **L3 — chained to a concrete next step.** The disclosed information is
  actually used to reach a distinct outcome: a version mapped to a
  specific reachable CVE, a path used to attempt LFI, a credential tested
  against a live service, a schema-revealed hidden field tested for
  missing authorization. This is the threshold for a reportable finding
  at anything above Low — see the rubric.
- **L4 — the chain is completed.** The next step in L3 is not just
  attempted but SUCCEEDS: the CVE is actually exploited, the LFI actually
  reads a sensitive file, the credential actually authenticates, the
  hidden field actually bypasses authorization — at which point record the
  finding under that downstream class as well, per [[closure-discipline]].

## Triage Rubric

Severity here is unusually front-loaded — decide it deliberately, not by
default:

- **Critical/High** — direct disclosure of secrets or highly sensitive/
  cross-tenant data, with real access demonstrated where it's safe to do so.
- **Medium** — unauthorized access to a genuinely restricted but narrow
  data set, or a fully validated chain from the disclosure to a concrete
  consequence.
- **Low** — a real but modest unauthorized disclosure with no serious
  direct consequence.
- **Informational / do not report as a standalone finding** — public or
  already-intended client data, generic headers, internal hostnames or
  private IP addresses with no reachable exploit, and a version banner or
  source map that exposes no secret and chains to nothing. A path,
  version, or schema value that only *suggests* a possible second
  vulnerability must have that full chain validated (per the proof ladder
  above) before it is reported at all — do not report the suggestion
  itself.

## Validation and False-Positive Discipline

Apply [[closure-discipline]] before recording anything. Class-specific
traps to check before calling something confirmed:

- Do not report a finding on suggestion alone — "this looks like it could
  lead to X" is not evidence; either complete the chain to X per the
  ladder above, or hold the finding at Informational/no-report.
- A generic error message with no path, version, query fragment, or
  internal identifier in it does not qualify, regardless of how alarming
  the HTTP status code looks.
- A redacted or masked field that does not change the differential-oracle
  result (identical across owner/non-owner/anonymous once redacted) closes
  this specific instance — confirm the redaction is applied consistently,
  not just present in the one response you happened to check.
- An owner-visible-only detail that never crosses an identity or tenant
  boundary is expected behavior, not disclosure — the boundary crossing
  itself is what must be demonstrated.

## Impact

Accelerated exploitation of other vulnerability classes (RCE/LFI/SSRF) via
precise version and path intelligence, direct credential/secret exposure
leading to persistent external compromise, cross-tenant data exposure
through caches or mis-scoped exports/signed URLs, and privacy/regulatory
exposure from aggregated PII leakage.

## Summary

Information disclosure findings are only as good as the chain behind
them — mine artifacts and differential oracles aggressively, but report by
the triage rubric, not by how many bytes were exposed; an unchained leak is
architectural risk to note, not a vulnerability to score high.
