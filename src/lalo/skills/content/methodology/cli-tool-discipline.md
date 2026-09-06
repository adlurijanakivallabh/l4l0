---
name: cli-tool-discipline
category: methodology
description: How to invoke real command-line security tools inside the free shell without hallucinated flags, cross-tool flag confusion, or corrupted payloads
keywords: [cli tools, command line, flag hallucination, tool syntax, shell quoting, structured output]
---

# CLI Tool Discipline

The free shell is how L4L0 runs and installs the actual tools its
methodology calls for — `run_command` has no allowlist, so almost
everything that goes wrong here is a self-inflicted mistake in HOW a real
tool is invoked, not a permissions problem. These are the recurring
failure modes worth guarding against explicitly, because they waste turns
and — worse — can silently corrupt a payload without any error at all.

## Verify Syntax Before Trusting Memory

A tool's flags, defaults, and output format can differ across the
specific version actually installed versus whatever a model's training
data remembers. Before the FIRST use of a given tool in a scan, or after
any failure that suggests memorized syntax might be stale (a renamed
flag, a changed default, a different installed version than expected),
check `<tool> -h`/`--help` rather than guessing from memory — this costs
one cheap command and avoids a whole chain of malformed invocations built
on a wrong assumption.

## Never Assume a Flag Means the Same Thing in Another Tool

The same short flag routinely means something completely different across
tools — `-p` is a port in one scanner, a password in a brute-forcer,
a proxy setting somewhere else entirely. Never copy a flag from one tool
to another because it "looks the same," and never invent an output flag
(`-o`, `-c`, a JSON toggle) that the target tool's own `--help` doesn't
actually document — check the specific tool's real option list every time,
not a generalized mental model of "how CLI tools usually work."

## Prefer Structured Output When It Exists

When a tool's output needs to be parsed or piped into another step,
request its documented machine-readable format explicitly (XML/greppable/
JSON output modes exist on most serious scanners) rather than parsing its
default free-text formatting — free-text output is the least stable part
of any tool across versions and is far more likely to silently change in
a way that breaks a naive parse without raising an error.

## Quote Payloads, Every Time

Any payload string containing shell metacharacters — semicolons, pipes,
ampersands, `$`, quotes, backticks, or glob characters (`*`/`?`) — MUST be
quoted or escaped before it reaches a real shell invocation. An unquoted
payload gets interpreted by the shell running the tool, not by the target
the payload was meant for, and this is a uniquely dangerous silent
failure mode: an injection or XSS payload built for [[command-injection]],
[[sql-injection]], or [[xss]] can be mangled by local shell expansion
before it ever reaches the wire, producing a false negative that looks
identical to "the target correctly rejected it."

## Handle Output Volume Deliberately

For a command producing large or unbounded output (a broad crawl, a full
port sweep, a verbose scan), decide up front how the output will be
captured and bounded — redirect to a file for later inspection rather
than letting a huge stdout blob consume the agent's own context window,
and use a tool's own quiet/summary flags where available rather than
filtering a verbose stream after the fact.

## Fail Fast on Tool Substitution

If a package manager or installation attempt fails, don't retry the exact
same install command hoping for a different result — switch to a
functionally equivalent tool from the same category after a couple of
attempts, and note the substitution plainly in whatever summary or
finding depends on that tool's output, since a different tool can have
materially different detection coverage for the same technique.

## Summary

Most CLI-tool mistakes in an autonomous loop are avoidable with one
cheap habit: check real `--help` output before trusting memorized syntax,
never let an assumption from one tool leak into another, and always treat
a payload string as something the local shell will try to interpret
unless explicitly told not to.
