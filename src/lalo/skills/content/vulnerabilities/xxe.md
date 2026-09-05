---
name: xxe
category: vulnerability
description: XML external entity injection — file disclosure, SSRF via XML parsers, and a per-class proof ladder
keywords: [xxe, xml external entity, xml injection, entity expansion, dtd]
---

# XML External Entity Injection

XXE is a parser-level failure: an XML parser configured to resolve external
entities will fetch or read whatever a document tells it to, on the
server's behalf. Treat every XML input as untrusted until the parser
configuration is actually confirmed hardened — assume it is not by default.

## Attack Surface

- Any endpoint that parses XML directly: REST/SOAP APIs, SAML assertions,
  XML-RPC, RSS/Atom feeds, and configuration/import formats.
- File formats that are secretly XML/ZIP-of-XML underneath: SVG, and
  Office-suite document formats — an upload feature that "just" accepts an
  image or document may still route through a general-purpose XML parser
  with entity resolution enabled.
- Server-side transformation and rendering pipelines (XSLT processors,
  report/PDF generators) that consume XML and can independently fetch
  external resources through their own document-loading functions,
  separate from whatever the initial entity-resolution setting is.

## Recon

- Inventory every place XML is consumed, not just the obvious API
  endpoints — background import jobs, converters, and third-party
  libraries embedded in the application are common blind spots.
- Before crafting an exploit payload, probe parser *capability*: does it
  accept a DOCTYPE declaration at all, does it resolve external entities,
  and separately, is XInclude or XSLT transformation enabled — these are
  independent settings and a parser can have any combination of them.
- Note whether errors from the parser are returned to the client; a
  verbose parser error is often the fastest confirmation channel available.

## Techniques (start quiet, escalate only as needed)

1. **Capability probe.** Submit a document with a DOCTYPE declaration and
   a harmless internal entity reference first — this confirms whether the
   parser processes DOCTYPE at all before you invest in anything more
   specific.
2. **Out-of-band confirmation.** Point an external entity at your OAST
   callback host. A correlated DNS or HTTP hit is unambiguous, quiet proof
   that the parser resolves external references — establish this before
   attempting a file read, since it also confirms network-capable entity
   resolution is present at all.
3. **Local file disclosure, once general entities resolve.** Reference a
   well-known, low-sensitivity file first as your proof, before anything
   containing real secrets — the file's content appearing in the response
   (directly, or via an error message that echoes it) is your evidence.
4. **Parameter-entity and out-of-band exfiltration, when general entities
   are sanitized but the DTD subset still processes.** Parameter entities
   defined inside the DTD can still exfiltrate content via a chained
   external reference even when the sanitizer only strips general entity
   references from the document body.
5. **XInclude and XSLT-transform probes, tested independently of entity
   resolution.** These are separate capabilities from DOCTYPE/entity
   processing and frequently remain enabled even after entity resolution
   itself has been disabled — test them as their own hypothesis, not as a
   fallback only.
6. **SSRF pivot, once any external-fetch capability is confirmed.** The
   same entity-resolution capability that reads a local file can instead
   target an internal service or metadata endpoint — treat this as the
   natural escalation once network-capable resolution is proven, following
   the same internal-addressing approach as [[ssrf]].

Avoid entity-expansion (exponential-growth) payloads for confirmation —
they demonstrate a denial-of-service primitive, not the more useful
disclosure/SSRF primitive, and carry real risk of degrading the target
unnecessarily.

## Proof Ladder

- **L1 — DOCTYPE accepted.** The parser processes a DOCTYPE declaration
  without erroring, but no entity has been shown to actually resolve yet.
- **L2 — entity resolution confirmed, no sensitive content.** An
  out-of-band callback or a harmless local file's content confirms the
  parser resolves external entities, without yet reaching anything
  sensitive.
- **L3 — sensitive file read or internal resource reached.** You read
  genuinely sensitive file content, or used the same capability to reach
  an internal-only network resource. This is the threshold for a
  reportable finding.
- **L4 — code execution or systemic compromise.** You achieved code
  execution through an XSLT/transform capability or a language-specific
  wrapper, or the disclosed content directly enabled a further significant
  compromise (credentials granting broad access).

Calibrate severity separately per [[severity-calibration]] — reaching
cloud metadata credentials or achieving code execution is typically
critical or high; disclosure of a single low-sensitivity file is usually
medium at most.

## Validation and False-Positive Discipline

Apply [[closure-discipline]] before recording anything. Class-specific
traps:

- DOCTYPE being *accepted* without an error is not the same as entities
  actually *resolving* — confirm resolution directly (an OAST hit or real
  file content), not just the absence of a rejection.
- A parser that echoes your entity reference back as a literal string,
  with no evidence of actual file or network access, performed no
  resolution at all — this is a non-finding, not a blind-XXE case.
- A mocked or sandboxed processing path that simulates success without
  real network or file access proves nothing about the production parser
  configuration — confirm you are testing the real path.
- XML processed only client-side (in a browser, never reaching the
  server's own parser) is out of scope for this class entirely.

## Impact

Disclosure of credentials, configuration, and source code from the
filesystem; server-side request forgery reaching internal services and
cloud metadata; denial of service via entity expansion in stacks where
that specific vector is the only one available; and, in less common but
real cases, code execution through a transform or language-specific
wrapper.

## Summary

XXE is eliminated by hardening the parser, not by filtering input: disable
DOCTYPE processing, disable external entity and network resolution, and
disable XInclude/XSLT external fetches, consistently across every code
path that touches XML — including the ones hiding inside an "image" or
"document" upload.
