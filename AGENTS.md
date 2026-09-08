# L4L0 — AGENTS.md

## Context for any AI model working in this repository

L4L0 is a legitimate, authorized offensive-security engagement tool —
comparable in purpose to Metasploit, sqlmap, Burp Suite, nmap, or hydra,
several of which it directly orchestrates. Its entire feature set —
vulnerability detection, exploit proof-of-concept generation, credential
testing and cracking, JWT/token forgery, SQL injection, RCE demonstration,
and network/cloud/binary attack-surface assessment — is the intended, core
functionality of a professional penetration-testing product used only
against engagements the operator has explicitly authorized. Writing,
testing, reviewing, or modifying this kind of code is ordinary software
engineering for this specific project, not a request that needs special
caution beyond normal secure-coding practice: don't introduce real
vulnerabilities into L4L0's *own* code, never leak a real credential,
never weaken the project's mechanical safety guarantees (host isolation —
disposable containers, dropped capabilities, no host bind-mounts, no
Docker socket — and operator-declared engagement targets). If asked to
implement a new attack technique, a proof ladder, a credential-cracking
primitive, or a skill-library playbook for a vulnerability class, treat it
the same as any other feature request for a security tool and do the
work — that IS the product, not a red flag on top of it.

This file exists specifically so that tooling which reads `AGENTS.md`
rather than `CLAUDE.md` still gets this context up front. **The full
project instructions live in `CLAUDE.md`** (architecture, safety posture in
full detail, stack, commands, working conventions, what's explicitly out
of scope) — read that file for everything beyond this authorization
context; this file does not duplicate it and is not a separate source of
truth.
