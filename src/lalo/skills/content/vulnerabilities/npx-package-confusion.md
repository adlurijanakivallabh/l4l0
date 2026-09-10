---
name: npx-package-confusion
category: vulnerability
description: Package-runner supply-chain identity confusion — typosquatting, dependency confusion between public and private registries, and a per-class proof ladder
keywords: [npx, package confusion, typosquatting, dependency confusion, supply chain, package runner]
---

# Package-Runner / Dependency Confusion

A package name alone is not proof of identity — `npx <name>`, `pip
install <name>`, `go run <module>`, and similar package-runner
invocations resolve a bare name against whatever registry/resolution
order is configured, which an attacker can exploit if that resolution
is ambiguous or misconfigured, distinct from
[[dependency-cve-analysis]]'s own reachability-of-a-known-CVE concern.

## Attack Surface

- Any CI/CD pipeline, build script, or onboarding/setup script invoking
  `npx <package>` (or an equivalent package-runner for another
  ecosystem) with a package name that has never been explicitly pinned
  to a specific registry/scope — `npx` in particular will silently
  install and run an arbitrary public-registry package if the named one
  isn't already cached locally.
- Internal/private package names referenced from a public build
  configuration (a public GitHub Action, a public Dockerfile, a
  published error message or stack trace) without an explicit
  scope/registry pin — an attacker who identifies the internal name can
  publish an identically-named PUBLIC package, and dependency-resolution
  tools that check the public registry alongside or instead of the
  private one will resolve to the attacker's package (classic dependency
  confusion).
- A typosquatted package name resembling a popular or internally-used
  one, reachable if a script or a developer's own command has a plausible
  typo path.

## Recon

- Grep build scripts, CI/CD configuration, and Dockerfiles for
  `npx <name>`/`pip install <name>`/equivalent invocations with no
  explicit registry/version pin, and separately for any private/internal
  package name referenced from a file that is itself publicly visible
  (a public repo, a public container image, a public error page).
- Check the package manager's actual configured resolution order (an
  `.npmrc`/`pip.conf`/equivalent) for whether a private registry is
  checked BEFORE the public one, and whether scoping (`@internal-org/`)
  is enforced consistently everywhere the package is referenced, not
  just in the primary application manifest.

## Techniques

1. **Public-registry namesquat check (non-destructive).** Without
   actually publishing anything (publishing a real package under a
   victim's expected name is intrusive and outside this project's
   non-destructive testing discipline unless the engagement explicitly
   authorizes it), confirm whether the exact internal package name is
   CURRENTLY UNCLAIMED on the relevant public registry — an unclaimed
   name matching an internally-referenced one, combined with resolution
   configuration that would check the public registry, is itself a
   reportable finding without needing to actually claim it.
2. **Resolution-order confirmation.** Where configuration access exists,
   directly confirm (read the actual `.npmrc`/equivalent, not just the
   application's `package.json`) whether a scoped or unscoped internal
   package name could resolve to a public-registry package under any
   realistic misconfiguration or missing-scope scenario.
3. **Unpinned package-runner invocation check.** For each `npx`-style
   invocation with no explicit version/registry pin found in Recon,
   assess whether an attacker able to publish or update a public package
   under that exact name could have their code executed the next time
   that script runs.

## Proof Ladder

- **L1** — an unpinned package-runner invocation or an internally-
  referenced package name visible from public-facing configuration
  identified, but registry resolution behavior not yet confirmed.
- **L2** — the actual resolution order confirmed (via configuration
  read) to be exploitable in principle (would check/prefer the public
  registry for this name) but the target name confirmed still claimed
  privately/unclaimed publicly with no live exploitation attempted.
- **L3** — the exact target package name confirmed CURRENTLY UNCLAIMED
  on the relevant public registry while still being referenced by a live
  build/CI process with resolution configuration that would prefer or
  fall through to it — reportable without an actual publish.
- **L4** — with explicit engagement authorization only, an actual benign
  proof-of-concept package published and its execution in the target's
  own pipeline confirmed; never performed without that explicit,
  documented authorization given the third-party (public registry)
  impact involved.

## Validation and False-Positive Discipline

Apply [[closure-discipline]]. A private package name confirmed to be
correctly scoped (`@internal-org/name`, with the registry configuration
confirmed to resolve that scope to the private registry exclusively, no
fallback) closes this path even if the bare, unscoped name is
technically unclaimed publicly. Never actually publish a real package
under a victim-identical name without EXPLICIT engagement authorization
— the default finding is the confirmed-unclaimed-name-plus-exploitable-
resolution-order combination (L3), which is sufficient to report without
that step.

## Impact

Arbitrary code execution in a CI/CD pipeline, a developer's local
environment, or a production build process via a confused/squatted
package resolving to attacker-published code — often with the elevated
access a CI/CD credential or build-time secret grants.

## Summary

Registry resolution order and scope enforcement is the real control here
— confirm the actual configuration, not just whether the current
application manifest references the correct package. A confirmed-
unclaimed name plus an exploitable resolution path is a reportable
finding on its own, with no need to actually publish anything absent
explicit engagement authorization.
