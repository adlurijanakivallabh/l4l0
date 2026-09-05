---
name: cmdi
class: cmdi
summary: Methodology for OS command injection and RCE proof.
---
# OS Command Injection

1. Find a parameter that flows into a shell/exec call (ping, convert, export, etc.).
2. Try separators/operators: `;id`, `| id`, `$(id)`, `` `id` ``, newline-prefixed.
3. Prove RCE non-destructively by running a benign command whose output is
   unmistakable — `id` (expect `uid=...(...) gid=...`), `uname -a`, or read a canary.
4. Blind (no output): time delay (`;sleep 5`) or OOB (`;curl OAST`, `;nslookup OAST`).
5. Chain: from confirmed RCE, enumerate reachable in-scope internal services to
   demonstrate blast radius — read/prove only, no persistence, no destruction.

Confidence: real command output (id) or an OOB callback is definitive (EXECUTION/
OOB evidence). Escalate severity to critical when RCE is proven.
