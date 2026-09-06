---
name: active-directory-ldap-mapping
category: vulnerability
description: Read-only Active Directory and LDAP privilege-graph mapping — anonymous disclosure, ACL-based escalation paths, delegation and SPN enumeration, with a per-class proof ladder. Mapping only — never DCSync, ticket forgery, or kerberoast-then-lateral.
keywords: [active directory, ldap, bloodhound, acl, kerberos, spn, delegation, domain admin, privilege graph]
---

# Active Directory and LDAP Mapping (Read-Only)

**This skill is scoped to mapping, not exploitation, by this project's own
standing design.** The deliverable is a clearly documented
privilege-escalation *path* through the domain's real ACL and group-
membership graph — never DCSync, golden/silver ticket forgery, or a live
kerberoast-then-crack-then-lateral-move sequence. A fully mapped path,
precisely enough specified that the operator can see exactly how an
adversary would traverse it, is the complete proof — walking it live is
explicitly out of scope, always.

## Attack Surface

- Anonymous or null-session LDAP binds that many misconfigured domains
  still permit, disclosing user, group, and computer objects with zero
  credentials.
- The full domain object graph (users, groups, computers, organizational
  units, trusts, and Group Policy Objects) once any valid credential —
  even a single low-privilege domain user — is available.
- Access-control-list misconfigurations on AD objects: a principal
  granted the right to reset another principal's password, add themselves
  to a group, or otherwise gain effective control over an object more
  privileged than themselves.
- Service Principal Names revealing service accounts and the hosts they
  run on, and computer objects flagged for unconstrained or otherwise
  high-risk delegation configurations.
- Cross-domain and cross-forest trust relationships, their direction, and
  whether they are transitive.

## Recon

- Attempt an anonymous/null LDAP bind first — this needs no credentials at
  all and, in a genuinely misconfigured environment, discloses far more
  than its cost would suggest.
- Once any credential is available, collect the full domain object graph
  in one pass with a graph-mapping ingestor (this project's runtime
  arsenal ships BloodHound's own community-edition collector for exactly
  this) — collection and analysis only; never invoke any of that tooling's
  live attack modules against a discovered path.
- Enumerate privileged-group membership (Domain Admins, Enterprise Admins,
  and any custom group carrying equivalent effective rights through nested
  membership or ACL grants) as its own explicit step — nested membership
  frequently hides the real scope of a "small" group.
- Identify computer objects with unconstrained delegation or other
  high-risk delegation flags, and record their configuration — this is
  reconnaissance for the report, not a step toward abusing them.

## Techniques (start quiet, escalate only as needed)

1. **Anonymous bind and base enumeration.** The cheapest, always-safe first
   step, and worth attempting even when credentials are already available
   — it establishes the baseline of what the domain discloses to a
   completely unauthenticated party.
2. **Authenticated full-graph collection.** Any available low-privilege
   domain credential is sufficient to collect the complete object and ACL
   graph — this single pass typically reveals the whole realistic
   escalation surface an adversary would actually use, with no further
   live testing against the domain required.
3. **ACL-based attack-path analysis.** Analyze the already-collected graph
   offline for concrete escalation paths (who effectively controls whom,
   accounting for nested groups and nonobvious ACL rights) — this is pure
   read-only analysis of data already gathered, not a further live action
   against the domain.
4. **SPN and delegation enumeration for reporting.** List every discovered
   service account and delegation-configured computer as its own specific
   finding entry. Do not request a service ticket for offline cracking
   (kerberoasting), and do not attempt to abuse any discovered delegation
   configuration.
5. **Present the mapped path as the finding.** A concrete statement such
   as "user X can reset user Y's password; Y is a member of group Z, which
   holds DCSync rights over the domain" is itself the complete proof of a
   privilege-escalation path — walking that path live, requesting a
   forged ticket, or performing a real credential-theft action to
   "confirm further" is explicitly out of this project's scope regardless
   of how straightforward the path looks.

## Proof Ladder

- **L1 — anonymous disclosure confirmed.** Some domain information (object
  names, group membership, or configuration) was obtained via a null or
  anonymous bind with zero credentials.
- **L2 — a specific misconfiguration confirmed.** Authenticated
  enumeration confirms a concrete misconfiguration exists (an
  overly-permissive ACL grant, an unconstrained-delegation computer), but
  no complete path to a highly-privileged principal is mapped yet.
- **L3 — a complete escalation path mapped.** A concrete, fully specified
  path from the tested identity to a highly-privileged principal (Domain
  Admin or equivalent) is mapped end to end via the collected graph — the
  path itself, precisely documented, is the proof. This is the threshold
  for a reportable finding.
- **L4 — systemic privilege-model failure.** Multiple independent paths to
  privileged principals exist, or the misconfiguration is structural (for
  example, the broad "Domain Users" group itself has a path to Domain
  Admin), indicating the domain's whole privilege model is broken rather
  than one isolated misconfigured object.

Calibrate severity separately per [[severity-calibration]] — a single
narrow, hard-to-reach escalation path is a different severity from a
structural flaw reachable by any authenticated domain user, even though
both can clear L3.

## Validation and False-Positive Discipline

Apply [[closure-discipline]] before recording anything. Class-specific
traps:

- A long-looking chain of group memberships is not automatically a real
  escalation path — confirm each hop's ACL grants the *specific* effective
  right the path depends on (for example, `GenericAll` versus a narrower
  right that looks similar in a casual graph read).
- AD's own built-in, expected structure (Domain Admins being a member of
  the local Administrators group on every domain-joined machine, by
  design) is not a finding on its own — the finding is an unexpected or
  excessive path, never the mere existence of AD's normal architecture.
- A computer object flagged for unconstrained delegation that is a
  legitimate, tightly access-controlled domain controller or an
  intentionally designated resource server may be an accepted, already
  understood risk — note its configuration, but do not treat every
  delegation flag as automatically severe without checking who can
  actually reach that computer.
- Never conflate "I found a path in the graph" with "I have exploited it."
  Per this project's own read-only-mapping boundary, the precisely
  documented path is the complete deliverable — do not attempt DCSync,
  golden/silver ticket forgery, or a live kerberoast-then-crack-then-
  lateral-move sequence to "confirm further," no matter how confident the
  mapped path looks.

## Impact

Presented entirely as mapped privilege-escalation paths: exactly how an
adversary with a given starting foothold would traverse the domain's real
ACL and group-membership graph to reach domain or forest compromise. The
mapping itself is the complete deliverable — this project does not
weaponize AD paths into actual credential theft or lateral movement.

## Summary

Map the domain's real privilege graph from the cheapest available vantage
point — an anonymous bind first, then any low-privilege credential for a
full collection pass — and present the concrete escalation path as the
finding. This is read-only mapping, not offensive AD tradecraft: never
DCSync, forge a ticket, or kerberoast-then-crack-then-move, regardless of
how clear the path appears in the graph.
