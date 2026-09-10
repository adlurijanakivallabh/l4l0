---
name: asset-discovery
category: methodology
description: Passive and semi-passive asset/subdomain discovery methodology — expanding the declared attack surface honestly, without exceeding the operator-declared engagement scope
keywords: [asset discovery, subdomain enumeration, attack surface mapping, passive recon, osint]
---

# Asset Discovery

Before testing anything, establish what actually exists across the
declared engagement's scope — a subdomain or service the operator never
explicitly named but which resolves within an already-authorized wildcard
scope rule is legitimately in scope; one that resolves to a genuinely
different, undeclared host is not, no matter how it was found.

## Method, Cheapest First

1. **Certificate-transparency lookups** for every declared root domain —
   the cheapest, fully passive source of subdomain names, requiring no
   traffic to the target at all.
2. **DNS enumeration** via the `dns_query` tool against likely naming
   patterns and any names surfaced by certificate transparency — resolve
   each candidate and confirm it actually falls within an authorized
   scope rule (per the engagement's own wildcard/host rules) before
   treating it as in scope.
3. **Passive third-party datasets** the free shell can query (a
   reverse-DNS/IP-history lookup, a search-engine-indexed subdomain
   listing) where reachable without violating the engagement's own
   no-third-party-service constraints, if any are stated.
4. **Active service fingerprinting**, only once a candidate host is
   confirmed in scope — this is where `recon`'s existing port/service
   scanning methodology takes over; asset discovery's own job ends at
   "this host is in scope and exists," not at characterizing it.

## Scope Discipline

A discovered asset is tested ONLY if it genuinely falls within an
already-authorized engagement rule (an exact host match, or a subdomain
matching an authorized wildcard) — discovery never expands scope on its
own. A discovered host that looks related (a shared naming convention, a
shared certificate) but does not actually match an authorized rule is
reported as a NOTE for the operator's own awareness, never tested.

## Validation and False-Positive Discipline

A hostname appearing in certificate-transparency logs does not mean it
currently resolves or is currently in production use — confirm active
DNS resolution before spending further effort on a candidate. A resolved
host returning a generic parking-page/default-vhost response is a real,
existing asset worth noting as low-priority, not a false positive to
discard silently.

## Summary

Passive sources first, active fingerprinting only after scope
confirmation — and scope confirmation is never optional regardless of
how a candidate was discovered.
