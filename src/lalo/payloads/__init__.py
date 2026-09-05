"""Payload intelligence — deliberately narrow (Phase 10, optional/reference material).

Reference reads for this phase (all five, via each project's own
REACHAGENT_COMPARISON.md) converged on a finding that reshaped this phase's
scope: **no reference maintains a self-owned, structured payload corpus.**
A reference agent's real payload content lives as prose inside its ~68
per-vulnerability-class skill markdown files (confirmed via its own skills
index, read across many batches) — the correct pattern for L4L0 to mirror in
Phase 11's skill library, not duplicate here as a separate "corpus" module.
A second reference embeds payload examples the same way, directly inside its
exploitation prompts (e.g. literal cloud-metadata SSRF strings), not as a
separate module. Two references have no payload-adjacent material at all:
one relies entirely on ad hoc LLM composition of shell commands, gated only
by an opt-in, off-by-default dangerous-pattern blocklist (confirmed directly
in its own tool source and test suite); one has no domain-specific payload
tooling anywhere in its agent framework — its own comparison notes state its
LLM roles are "expected to just run arbitrary shell commands (nmap, curl,
etc.) itself, guided only by prompt instructions" with no typed payload API
at all.

Building a deterministic payload-selection/dispatch module here would
reintroduce exactly the fixed-code-instead-of-agent-judgment pattern this
project's operator explicitly and forcefully rejected earlier in its
history (see [[feedback-prefer-better-tools]] / the methodology-correction
section of CLAUDE.md). So this phase stays deliberately narrow: only the
slice of "payload intelligence" that involves zero vulnerability judgment —
mechanical string mutation and OAST placeholder substitution a skill file
or the agent itself can call once it has already decided what to try.
"""

from .mutate import double_url_encode, html_entity_encode, unicode_escape, url_encode
from .oast_template import OAST_PLACEHOLDER, substitute_oast

__all__ = [
    "OAST_PLACEHOLDER",
    "double_url_encode",
    "html_entity_encode",
    "substitute_oast",
    "unicode_escape",
    "url_encode",
]
