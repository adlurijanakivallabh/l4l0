---
name: command-injection
category: vulnerability
description: OS command injection — shell metacharacter and argument injection, quiet oracles, and a per-class proof ladder
keywords: [command injection, cmdi, os command injection, shell injection, rce]
---

# OS Command Injection

Command injection happens when user input reaches a shell or a process
launcher in a way that lets the attacker add operators the developer did
not intend — not just extra arguments to the intended command, but
additional commands entirely.

## Attack Surface

- Any feature that shells out to an OS utility on the caller's behalf:
  file conversion, network diagnostics (ping/traceroute-style tools),
  archive/image/media processing wrappers, PDF generators, and
  "run this report" or "sync this integration" background jobs.
- Two distinct injection shapes worth telling apart early: **shell
  metacharacter injection** (the input reaches a real shell, so operators
  like a semicolon or pipe change what runs) versus **argument injection**
  (the process is launched without a shell — `execve`-style — but the
  attacker can still control which flags or filenames the target binary
  receives, which is a narrower but still real primitive).
- Command-line tools invoked with a version, filename, or URL parameter the
  application forwards close to verbatim are a recurring, easy-to-miss
  surface — the parameter looks like ordinary data, not code, right up
  until it reaches the shell.

## Recon

- Identify which parameters plausibly reach an OS-level call at all before
  spending payloads — features named after a real system utility (convert,
  compress, ping, lookup, sync) are the highest-signal candidates.
- Note the platform (Unix vs. Windows) from other fingerprinting, since the
  operator syntax and available fallback binaries differ meaningfully
  between the two.
- Check whether the value is already being validated as one specific shape
  (an IP address, a filename with an extension check) — this tells you
  whether to test smuggling an operator past that validation, or whether
  the value reaches the shell unvalidated.

## Techniques (start quiet, escalate only as needed)

1. **Time-based confirmation first.** Append a short, self-contained delay
   using a shell operator appropriate to the platform (a chained command on
   Unix, the equivalent chain on Windows) and confirm the response time
   moves by roughly that amount — then confirm a control request without
   the delay operator does *not* show the same shift, before trusting the
   result.
2. **Out-of-band confirmation, for equal or better confidence with less
   noise.** Have the injected command resolve a DNS name or make an HTTP
   request to your OAST callback. A single correlated hit is unambiguous
   and does not depend on timing variance the way the delay technique does.
3. **Output-based confirmation, only if the response actually reflects
   command output.** A benign identity-revealing command is enough to
   confirm execution; there is no need to run anything destructive or
   far-reaching to prove the primitive exists.
4. **Argument injection, when the target is a shell-free process launcher.**
   Test whether the input can inject an additional flag or a second
   positional argument to the invoked binary — this is a real, distinct
   primitive from full shell injection and deserves its own confirmation
   rather than being dismissed just because a semicolon did nothing. Check
   specifically whether the binary supports an end-of-options marker
   (`--`) and whether the application actually places it before the
   untrusted value — its absence, or wrong placement, is what makes flag
   injection reachable at all. Where the target itself reparses an
   argument as a second language (an `@response-file`, a `--config` path,
   an included/authentication file), a value that only ever looked like a
   filename can carry its own injected directives once that second file is
   read — trace both who controls the *path* and who controls its
   *content* before ruling this out.
5. **Filter evasion, only once you know a filter exists.** Alternate
   whitespace/field-separator forms, quoting/escaping tricks, and
   alternate binary paths exist to get past a specific denylist you have
   already observed — treat them as tools for confirming the underlying
   primitive still exists behind the filter, not as the goal.

Do not escalate to a reverse shell or any persistent access mechanism
before you have already proven the primitive with a quiet oracle — a
single targeted command that proves execution is sufficient evidence; a
standing shell is a materially larger, unnecessary footprint on the target
for a finding that is already provable more narrowly.

## Proof Ladder

- **L1 — behavioral anomaly.** A crash, unexpected error, or a response
  shape change follows an injected operator, but you have not yet proven
  the operator itself was interpreted.
- **L2 — timing or OAST oracle confirmed.** A delay or out-of-band
  callback correlates specifically to the injected operator (and a control
  request without it does not reproduce the effect), proving command
  interpretation without yet capturing output.
- **L3 — command output captured or a concrete side effect proven.** You
  captured the output of an injected command in the response, or otherwise
  proved a concrete effect (a file written, a process started) tied to
  your input. This is the threshold for a reportable finding.
- **L4 — durable control demonstrated.** You proved the primitive
  generalizes to arbitrary commands under the process's privileges (not
  just the one command you tried), or chained it into a further compromise
  (credential access, lateral reach) — proven, not merely asserted as
  possible.

Calibrate severity separately per [[severity-calibration]] — unauthenticated
command injection reachable on an internet-exposed surface is typically
critical; the same primitive behind strong authentication and a narrow role
requirement is usually still high, not automatically critical.

## Validation and False-Positive Discipline

Apply [[closure-discipline]] before recording anything. Class-specific
traps:

- A slow response alone is not proof — reproduce the timing difference at
  least twice and confirm a matched control request (same request, delay
  operator removed) does not show the same shift.
- A crash or generic error from unusual input is not proof of command
  interpretation — confirm the *specific* operator you injected is what
  changed the behavior, not that the input was merely malformed.
- A parameter passed to a shell-free launcher that appears to accept
  metacharacters harmlessly may still be vulnerable to argument injection —
  do not rule the surface out until you have specifically tested that
  narrower primitive too.
- "The framework escapes shell arguments" is exactly the kind of generic
  trust [[closure-discipline]] rejects — confirm the specific call
  actually uses a shell-free launcher with an argument array, not string
  concatenation into a shell command line.

## Impact

Remote code execution under the application's process privileges, with
potential escalation to full host control depending on those privileges;
data theft, credential exposure, and lateral movement from that foothold;
and persistent compromise if the primitive allows writing to a location the
system later executes or loads from.

## Summary

Command injection is a property of how a process is launched, not of any
one payload. Confirm quietly (timing or out-of-band) before anything
louder, distinguish shell injection from argument injection, and prove the
primitive with the smallest command that demonstrates it.
