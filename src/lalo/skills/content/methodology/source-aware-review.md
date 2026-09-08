---
name: source-aware-review
category: methodology
description: How to work when a target's source repository is available — mapping attack surface from real code instead of only observed behavior, and grepping for dangerous sinks as leads to verify, never facts to report
keywords: [source code, source-aware, static, attack surface, routes, handlers, ORM, models, middleware, dangerous sink, grep, sql injection, deserialize, eval, template injection, authorization decorator, source_location, white-box, static analysis]
---

# Source-Aware Review

Most of this project's methodology assumes black-box access: you only know
what a target does from the outside, by firing requests and reading
responses. When an operator's mission text names or links a source
repository — a GitHub URL, a local path, "here's the repo" — you have
something stronger available, and you already have every tool you need to
use it: the free shell can `git clone` it, `grep` it, and read any file in
it. This skill is how to spend that access well. It does not replace
dynamic proof — it replaces *guessing where to look* with *reading where the
code actually goes*.

## When This Applies

The mission text names a repository (a URL, an org/repo pair, a local path)
or the operator otherwise hands you source access. If no source was
offered, do not go looking for one on your own initiative — clone only what
the operator actually pointed you at, the same in-engagement discipline
that governs every other target. Source access is additive to black-box
testing, not a replacement for it: everything you find here still needs the
same dynamic proof this project's other skills require before it becomes a
`confirmed` finding (see `closure-discipline`).

## Step One: Map Attack Surface From the Code, Not Just From Observed Traffic

Black-box recon finds the routes a crawler can reach. Source access finds
every route the framework actually registers, including the ones nothing
links to yet: admin aliases, feature-flagged endpoints, internal-only APIs,
batch/cron entry points, and deserialization or file-upload handlers that
never appear in a rendered page.

Look for, by framework family:

- **Route/handler files** — a router table, `@app.route`/`@router.get`-style
  decorators, a `urls.py`/`routes.rb`/`*Controller` convention, or a
  generated OpenAPI/GraphQL schema checked into the repo. Every entry is a
  candidate surface, reachable or not from what you've already crawled.
- **ORM/model definitions** — field types and constraints tell you what the
  application *thinks* is safe (a field typed as an integer id, a foreign
  key relationship implying an authorization check ought to exist at every
  read of it) versus what a handler actually enforces at request time. A
  mismatch between the two is exactly the kind of authorization gap that's
  invisible from the outside.
- **Middleware/filter chains** — where authentication and authorization are
  supposed to run globally. Read the actual registration order, not the
  framework's documented intent: a middleware registered after the routes
  it was meant to guard, or opted out of by a specific route's own
  decorator, is a real, common gap.

Every surface you find this way still needs a live request against the
running target to prove reachability — a route existing in source code that
a build strips, a feature flag disables, or a reverse proxy blocks is not
itself a finding.

## Step Two: Dangerous-Sink Patterns Are Leads, Never Verdicts

Grepping for a pattern tells you where to look next, not what to report.
Treat every hit below as a candidate to trace and verify against real
input handling — not as evidence on its own. This is the same discipline
`closure-discipline` already states generically ("generic trust in a
library... is not counterevidence until you confirm that specific call");
here it runs in the other direction — a scary-looking grep hit is not
evidence of a real bug until you confirm the specific call, with real
input, in context.

Starting patterns, by category (adapt exact syntax to the actual language/
framework — these are shapes, not literal strings to `grep -F`):

- **SQL injection** — raw string concatenation or f-string/format
  interpolation building a query string, especially anywhere user input
  reaches it before a parameterized query API is used. An ORM call is not
  automatically safe: a `.raw()`/`.execute(f"...")` escape hatch inside an
  otherwise-parameterized ORM is the exact place operators forget to verify.
- **Insecure deserialization** — `eval`/`exec`, a language's native
  unpickling/deserialize call (Python `pickle.loads`, Java
  `ObjectInputStream`, PHP `unserialize`, Ruby `Marshal.load`, .NET
  `BinaryFormatter`) fed anything that traces back to request data, a
  cookie, or a queue message.
- **Template injection** — a template string built from user input before
  being handed to the render call, rather than passed as template
  *context*. Distinguish server-side template engines (Jinja2, Twig,
  Freemarker, ERB) — where this is often full RCE — from a client-rendered
  template, where the same pattern is usually "only" reflected content.
- **Missing or misapplied authorization** — a handler with no
  authorization decorator/guard where sibling handlers in the same file
  have one; a decorator present but checking authentication only, not
  the specific object-level ownership the handler then fetches by id
  (a classic broken-object-level-authorization shape — the ORM/model
  read from Step One is often where the missing check should have been).

A hit that doesn't hold up under tracing is not a finding and is not worth
recording as a caveat either — `closure-discipline`'s guidance on
`open_proof_gap` applies here exactly as it does to any other candidate:
say what you checked and why it didn't confirm, don't leave a vague "looked
suspicious" note.

## Step Three: File It the Same Way Everything Else Gets Filed

A source-aware finding is not a different kind of finding. It goes through
the exact same `record_finding` tool, with the exact same required fields
(`title`, `description`, `vuln_class`, `target`, `evidence`,
`evidence_excerpt`, `counterevidence`, `severity_change_conditions`,
`remediation`, `cvss_breakdown`) as anything discovered black-box — there is
no separate source-findings pipeline, no separate reconciliation step, and
nothing about this skill changes what counts as sufficient proof.

The one thing source access adds is the optional `source_location` field:
set it to `"path/to/file.py:123"` when your evidence traces to a specific
line you actually read — the exact line building the dangerous query, the
exact decorator (or its absence) you checked, the exact deserialize call.
Leave it unset rather than guess at a line number; a wrong location is
worse than no location, since a reader (or the SARIF `physicalLocation` it
renders into) will trust it. `target` still names the reachable endpoint or
network location the way every other finding does — `source_location` is
additional provenance, not a replacement for it.

## What This Skill Does Not Do

It does not turn this project into a static-analysis pipeline. There is no
separate "source findings" report section, no fixed rule set that decides
severity on its own, and no code path that files a finding without the
same evidence and closure discipline every other candidate goes through.
The patterns above are starting points for *you* to verify — never a
substitute for actually tracing the input, actually running the request,
and actually recording what you found.
