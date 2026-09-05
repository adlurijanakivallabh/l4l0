"""The shared ``{{oast}}`` placeholder convention for out-of-band payload templates.

A skill file (Phase 11) can write a payload template once — e.g. an OOB SSRF
probe shaped like ``"http://{{oast}}/x"`` — without knowing the actual
token/URL a given probe's :class:`~lalo.oast.OASTServer` callback issues;
that binding happens here, at fire time, from the real per-probe value. This
module exists specifically to keep every skill using the SAME placeholder
string rather than each one inventing its own marker.
"""

from __future__ import annotations

OAST_PLACEHOLDER = "{{oast}}"


def substitute_oast(template: str, value: str) -> str:
    """Replace every ``{{oast}}`` occurrence in ``template`` with a real callback value."""
    return template.replace(OAST_PLACEHOLDER, value)
