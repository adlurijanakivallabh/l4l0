---
name: binary-memory-corruption
category: vulnerability
description: Binary/pwn memory-corruption assessment — crash discovery and classification, controlled-PC proof, and code execution proof, with a per-class proof ladder
keywords: [binary, pwn, memory corruption, buffer overflow, exploit development, rop, aslr, checksec, fuzzing]
---

# Binary Memory Corruption

Most crashes are not vulnerabilities. This class exists to draw a precise
line between "it crashed" and "I have a genuine memory-corruption
primitive," and then between that and "I ran a command" — the same
canonical-evidence discipline this project applies everywhere else, applied
to raw memory. A crash alone is never sufficient evidence; classify before
you claim anything.

## Attack Surface

- Any network-reachable service implemented in a memory-unsafe language
  (C/C++, unsafe Rust, hand-rolled parsing in any language) processing
  attacker-controlled input.
- File-format parsers fed attacker-controlled files: image, document, or
  archive formats, and custom protocol/serialization parsers.
- Custom binary network protocols on raw TCP/UDP — not HTTP, which the
  web-application skills already cover.
- Local `setuid`/`setgid` binaries reachable from an already-obtained
  low-privilege shell (a genuine local privilege-escalation surface, not a
  remote one).
- Firmware and embedded services, where mitigations (ASLR, stack canaries,
  NX) are frequently disabled or absent entirely.

## Recon

- Triage the binary's protections before anything else: whether ASLR/PIE,
  NX, stack canaries, and RELRO are present (the arsenal's `checksec`-style
  tooling reports all of these in one pass) — this determines the realistic
  proof ceiling before you spend any time on exploitation.
- Map which inputs actually reach unsafe parsing code (specific protocol
  fields, file-header structures) before blind fuzzing — targeted testing
  against the real parsing surface finds crashes far faster than untargeted
  input mutation.
- Fingerprint the binary or service version and check for a known public
  CVE first — a documented, already-understood crash primitive is far
  cheaper to weaponize than discovering one from scratch, and tells you the
  realistic proof ceiling before you start.
- Determine what's actually available: source code, debug symbols, or a
  pure black-box binary — this changes which analysis tools (disassembly
  via radare2, live debugging via gdb) are useful and how far static
  analysis alone can take you before you need a live crash.

## Techniques (start quiet, escalate only as needed)

1. **Non-destructive crash discovery first.** Malformed, oversized, or
   boundary-value input against the mapped parsing surface, run against a
   scoped, non-production instance wherever the engagement allows it —
   the goal is the simplest reliable crash, not the most severe one yet.
2. **Classify every crash before proceeding.** Inspect the crash location
   and register/memory state: is this a null-pointer dereference with zero
   attacker control (a DoS-only crash, still worth recording honestly at
   that level), or does the state show a genuine corruption primitive — an
   overwritten return address, corrupted heap metadata, a controlled
   write? This classification step is not optional; it is the difference
   between an honest finding and an overclaimed one.
3. **Prove controlled program counter.** Once a corruption primitive is
   confirmed, the real proof threshold is a crash at a fully
   attacker-chosen address — not "it crashed differently," but the
   instruction pointer landing exactly where you specified.
4. **Build the minimal proof-of-concept.** Once controlled-PC is
   demonstrated, the target is running a single benign command (an
   `id`/`whoami`-equivalent) on the target — matching this project's own
   RCE proof standard used everywhere else, never a destructive payload,
   and never more than the minimum needed to prove code execution.
5. **Mitigation bypass, only when scope and time genuinely call for it.**
   Where ASLR/NX/canaries are present and intact, an info-leak-then-ROP
   chain is real, additional work with its own time cost — a proven crash
   with a clear corruption primitive but no completed bypass is itself a
   legitimate, honestly-reported finding at a lower proof level; do not
   force a bypass the engagement does not have budget for.

## Proof Ladder

- **L1 — crash reproduced, unclassified.** A reliable crash is reproduced
  but not yet inspected closely enough to know whether it reflects real
  memory corruption or a benign fault.
- **L2 — corruption primitive classified.** The crash is confirmed to
  reflect genuine memory corruption (a controlled write, corrupted
  control-flow data) via direct inspection of the crash state, but the
  program counter is not yet attacker-controlled.
- **L3 — controlled program counter demonstrated.** The crash occurs with
  the instruction pointer at a fully attacker-chosen value — a real,
  specific exploitation primitive, though not yet executed code. This is
  the threshold for a reportable memory-corruption finding.
- **L4 — code execution proven.** A benign command runs on the target via
  the built exploit, or a reliable, repeatable end-to-end exploit chain is
  demonstrated — the same terminal proof bar CLAUDE.md sets for every
  other RCE class.

Calibrate severity separately per [[severity-calibration]] — a DoS-only
crash with no corruption primitive is a materially different severity from
demonstrated code execution, even when both started from the same input.

## Validation and False-Positive Discipline

Apply [[closure-discipline]] before recording anything. Class-specific
traps:

- A crash (`SIGSEGV` or equivalent) is never sufficient on its own to
  report as memory corruption, let alone RCE — most crashes are simple
  null-pointer dereferences with zero attacker control. Classify first,
  every time.
- A crash that only reproduces under a debugger, with debug symbols, or
  against a locally rebuilt copy is not yet proof against the real,
  deployed target — confirm reproduction against the actual
  production-equivalent binary before relying on it.
- ASLR/PIE being enabled neither rules out exploitability (an information
  leak can defeat it) nor confirms it — never claim an exploitability
  level you have not actually demonstrated against the real protection
  configuration in place.
- A crash in a shared multi-tenant component you do not have authorization
  to exploit to completion should be reported honestly at the proof level
  actually reached — never escalated further than the engagement's scope
  and safety posture allow, and never on a live target when a scoped or
  offline copy would prove the same primitive safely.

## Impact

Remote code execution with the privileges of the crashed process, denial
of service against the affected service, and — chained with an existing
local foothold — full host compromise from a single memory-corruption
primitive, or local privilege escalation via a vulnerable setuid binary.

## Summary

Classify every crash before calling it a vulnerability — the real work is
the ladder from "it crashed" to "the program counter is mine" to "I ran a
command," not the initial crash itself. Prove controlled-PC before
claiming impact beyond denial of service, and report honestly at whatever
level the evidence and engagement scope actually support.
