---
name: insecure-deserialization
category: vulnerability
description: Insecure deserialization — gadget chains, type confusion, and safe-oracle-first confirmation with a per-class proof ladder
keywords: [deserialization, insecure deserialization, gadget chain, pickle, unserialize, marshal]
---

# Insecure Deserialization

Deserialization becomes dangerous the moment a language's native
unmarshal function runs on attacker-influenced bytes — many
languages' native serialization formats can reconstruct arbitrary object
graphs, invoking constructors, setters, and magic methods along the way,
which is exactly the mechanism gadget chains exploit.

## Attack Surface

- Cookies, session tokens, and hidden form fields carrying an opaque
  encoded blob are the classic surface, but API parameters accepting a
  base64 blob, message-queue payloads, and database columns storing a
  serialized object are equally in scope.
- Every mainstream language has at least one native or commonly-used
  format capable of this failure mode (native object serialization,
  unsafe YAML loading, PHP's object serialization, pickle-family
  formats) — the specific magic bytes or textual prefix differ per
  format, which is useful for fingerprinting before you commit to a
  gadget-chain approach.
- A signed or encrypted wrapper around the serialized blob changes the
  attack surface rather than eliminating it — if the signing key or
  algorithm is weak, or if an unsigned/alternate code path exists, the
  wrapper is not actually a control.

## Recon

- Identify the serialization format from its structure before doing
  anything else — attempting a gadget chain built for the wrong language
  or framework version is pure noise and reveals nothing.
- Fingerprint the library and version where possible (error messages,
  bundled library files, framework version disclosure) — a gadget chain is
  tied to specific classes/libraries present on the target's classpath or
  equivalent, not to the format in general.
- Note whether the blob is signed or encrypted, and if so, with what —
  this determines whether you are testing the deserialization itself or
  first need to break the wrapper.

## Techniques (start quiet, escalate only as needed)

1. **Safe, no-execution oracle first.** Before attempting any
   command-execution gadget chain, use a chain (or format feature) that
   only proves the object graph was constructed — an out-of-band network
   lookup gadget is ideal, since it confirms the sink is reachable without
   running an arbitrary command.
2. **Fingerprint before selecting a gadget chain.** Match the exact
   library and version to an available chain rather than trying chains
   speculatively — an unmatched attempt just produces noise and gives away
   that testing is happening, for no signal in return.
3. **Command-execution chain, only once the safe oracle confirms
   reachability.** Escalate to a real code-execution gadget only after the
   no-exec oracle has already proven the sink exists — this keeps the
   number of "loud" attempts to the minimum needed for proof.
4. **Signed/encrypted wrapper testing, when present.** Test whether the
   signing key is weak or guessable, whether an unsigned code path exists,
   or whether the algorithm itself has a known confusion — treat this as a
   prerequisite step, not a separate vulnerability, when the underlying
   deserialization would otherwise be exploitable.
5. **Second-order triggers, when direct deserialization is not reachable
   from the initial input point.** A serialized blob stored via one
   feature (a profile field, an import) may only be deserialized later, by
   an entirely different feature (an export, a scheduled job, an admin
   action) — trace where a stored blob is eventually read back, not just
   where it is written.

## Proof Ladder

- **L1 — format and sink identified.** You have identified the
  serialization format and located a plausible unmarshal call reachable
  from user input, but have not demonstrated the object graph is actually
  constructed from attacker-controlled bytes.
- **L2 — object construction confirmed, no execution.** A safe, no-
  execution oracle (an out-of-band network lookup gadget or equivalent)
  confirms the sink deserializes your crafted object graph.
- **L3 — code execution or a critical logic bypass achieved.** You
  achieved code execution via a matched gadget chain, or used object-graph
  manipulation to bypass an authentication or authorization check. This is
  the threshold for a reportable finding.
- **L4 — durable or full compromise.** You demonstrated persistent access,
  broad credential exposure, or full application compromise stemming from
  the deserialization primitive, not just a single proof-of-concept
  command.

Calibrate severity separately per [[severity-calibration]] — unauthenticated
deserialization reaching code execution is typically critical; the same
primitive gated behind strong authentication and a narrow, trusted-input
path is usually still high given how directly it tends to lead to full
compromise once reachable at all.

## Validation and False-Positive Discipline

Apply [[closure-discipline]] before recording anything. Class-specific
traps:

- The blob being cryptographically signed or encrypted with a properly
  verified key is a real control — confirm you actually tested breaking
  it (a weak key, an unsigned fallback path) rather than assuming a
  signature check is present but broken.
- Only primitive types being deserialized (a strict schema with no
  polymorphic type resolution) means the dangerous primitive — arbitrary
  class instantiation — is not actually present, even if the format
  itself is technically a serialization format.
- An error message that merely *mentions* a serialization class name,
  where the actual code path never passes attacker input to the unmarshal
  call, is a dead end, not a finding — trace the real data flow, don't
  infer it from an error string.
- A deserialization sink that is provably unreachable except in an
  isolated environment with no network or execution primitives available
  is a real, narrower finding at most — confirm the isolation directly
  rather than assuming impact from the primitive alone.

## Impact

Remote code execution on the application host, authentication bypass via a
forged session or credential object, privilege escalation through
manipulated role or permission fields in a deserialized object, and full
application compromise once a working gadget chain is confirmed against
the deployed library version.

## Summary

Treat every deserialization of data that crossed a trust boundary as
dangerous by default. Fingerprint the format and library version before
selecting a gadget chain, prove reachability with a safe out-of-band
oracle before any execution attempt, and trace stored blobs forward to
wherever they are eventually read back, not just their entry point.
