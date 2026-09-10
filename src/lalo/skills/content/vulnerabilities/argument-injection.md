---
name: argument-injection
category: vulnerability
description: Command-line argument/flag injection into an execve-style argv array — a distinct technique from shell metacharacter injection, exploitable even with no shell involved at all
keywords: [argument injection, flag injection, argv injection, cli injection, wildcard injection]
---

# Argument Injection

Argument injection targets applications that (correctly) avoid a shell
entirely — user input goes straight into an `argv` array passed to
`execve`/`subprocess.run([...])` with no shell metacharacter interpretation
possible. The gap here is different: if user input becomes one or more
WHOLE ARGUMENTS (not just a value inside one), an attacker can inject an
additional flag the target program itself interprets, regardless of shell
involvement. This is [[command-injection]]'s sibling class, not a subset
of it — a target hardened against shell metacharacters is often still
wide open to this.

## Attack Surface

- Any feature that builds an `argv` list where user input controls a
  whole positional argument or is concatenated in a way that can produce
  one (a filename the user names, a URL, a search term passed unquoted
  into an array position).
- Wrappers around `git`, `ssh`/`scp`, `curl`/`wget`, `tar`, `zip`/`unzip`,
  `rsync`, `ffmpeg`, and any CLI tool with a `-oOption=value`-style or
  long-flag configuration surface.
- A filename/path an attacker controls that is passed to a tool
  supporting a leading-hyphen-as-flag convention — `find`, `rm`, `chmod`,
  `tar` all treat a filename beginning with `-` as an option, not a name.

## Recon

- Identify the EXACT invocation shape: is user input placed as one
  complete array element, or interpolated inside a larger fixed string
  that becomes one element? Only the former is directly exploitable this
  way; the latter needs a value that, once split by the program's own
  argument parser (rare, but check), still produces a separate flag.
- Check whether the wrapped tool documents a dangerous flag reachable
  this way before testing blind: `git`'s `--upload-pack=`/`-c
  core.sshCommand=` (arbitrary command execution via a crafted remote
  URL/branch name), `ssh`/`scp`'s `-oProxyCommand=` (arbitrary command
  execution via a crafted hostname), `curl`'s `-o`/`--output` (arbitrary
  file write via a crafted URL argument position), `tar`'s
  `--checkpoint=1 --checkpoint-action=exec=` (arbitrary command execution
  via a crafted archive member name), `wget`'s `--post-file=`.

## Techniques

1. **Leading-hyphen probe.** Supply a value beginning with `-` or `--` in
   the position user input reaches and observe whether the tool's own
   help/error output or behavior changes — confirms the value reaches an
   argument-parsing position, not just a string used as data.
2. **`--` end-of-options bypass check (defense probe).** If the wrapper
   already prepends a literal `--` before user-controlled arguments (the
   standard, correct defense), confirm it is actually effective: some
   tools interpret a SECOND `--` as data rather than a repeated
   terminator, and a few tools (rare, but check the specific one in play)
   don't honor `--` for every subcommand consistently.
3. **Known-dangerous-flag injection.** Once the leading-hyphen probe
   confirms argument-position control, attempt the specific dangerous
   flag identified in Recon for that exact tool — e.g. for a Git
   URL/branch field reaching `git clone <value>`, attempt a value like
   `--upload-pack=touch /tmp/proof;` (adjust to the wrapper's actual
   invocation shape) and confirm via a benign, observable side effect on
   the target (a file created, an OAST callback), never a destructive
   command.
4. **Multi-argument injection via embedded delimiter.** If the value is
   split on whitespace or another delimiter before reaching `argv`
   (confirm this from the invocation code, not assumed), a single input
   value can inject MULTIPLE argv elements — worth testing when the
   single-flag technique alone doesn't reach a dangerous flag but a
   flag-plus-its-value pair would.

## Proof Ladder

- **L1 — argument-position control identified.** User input reaches a
  position that becomes one full argv element, confirmed via a
  leading-hyphen probe changing observable behavior, but no specific
  dangerous flag has been tried yet.
- **L2 — a non-dangerous flag injection confirmed.** A harmless flag
  (e.g. `--version`, `--help`) injected via user input visibly changes
  the program's behavior, confirming argument injection works in
  principle for this specific wrapper.
- **L3 — a dangerous flag's effect demonstrated via a benign side
  effect.** A flag with real consequence (file write/read, command
  execution, credential/config exfiltration) is triggered and its effect
  is directly observed (a file created at an attacker-chosen path, an
  OAST callback, a benign command's output captured) — reportable.
- **L4 — chained to full RCE or a durable compromise.** The injected flag
  itself achieves command execution (e.g. `git`'s `-c
  core.sshCommand=`/`tar`'s checkpoint-action) with a real, benign proof
  command run and its output captured.

## Validation and False-Positive Discipline

Apply [[closure-discipline]] before recording anything.

- A leading `-`/`--` in user input being REJECTED outright (a validation
  error, not a behavior change) is the control working correctly — not a
  finding, and worth a `record_safe` if you specifically confirmed the
  rejection is unconditional across every reachable invocation, not just
  the one you happened to test.
- The wrapper prepending a real, effective `--` terminator before every
  user-controlled argument closes this class for that specific
  invocation — confirm it is present in the ACTUAL invocation code
  (source-aware review) rather than assumed from the tool's general
  documentation, since a wrapper can add `--` in one call site and miss
  it in a sibling one.
- A behavior change from the leading-hyphen probe alone (L1) is not
  itself a finding — many tools simply print "unknown option" and exit
  cleanly, which is the safe, expected behavior for a hardened wrapper;
  only a confirmed dangerous-flag EFFECT (L3+) is reportable.

## Impact

Arbitrary command execution (via a tool's own command-invocation flags:
`ssh -oProxyCommand`, `tar --checkpoint-action`, `git -c
core.sshCommand`), arbitrary file read/write (via `-o`/`--output`-style
flags), and credential/config exfiltration (via a flag that dumps
internal state or reads an attacker-chosen config file) — often reaching
full RCE with no shell metacharacter ever needed, on a target explicitly
hardened against [[command-injection]]'s own shell-based variant.

## Summary

Confirm the invocation shape places user input as a whole argv element
first, then probe with a leading hyphen before trying anything dangerous.
A wrapper hardened against shell metacharacters can still be wide open to
this — never assume the shell-injection control also covers it without
checking the argument-parsing boundary specifically.
