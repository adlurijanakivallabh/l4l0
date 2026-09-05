"""Detectors — pure, zero-I/O vulnerability analyzers + a coverage ledger.

Each detector reasons over already-captured data (bodies, headers, timings, OAST
interactions) and returns typed :class:`~lalo.models.Evidence` (or ``None``). They
never fire requests themselves — the agent/exploit engine captures traffic and
calls these to turn it into scored evidence. The coverage ledger records which
classes were actually assessed per target so unassessed surfaces read "not
assessed", never "clean".
"""

from .ledger import CoverageLedger
from .web import (
    cmdi_output,
    nosqli_error,
    oob_interaction,
    open_redirect,
    path_traversal_read,
    sqli_boolean,
    sqli_error,
    sqli_time,
    ssrf_metadata,
    ssti_eval,
    xss_reflection,
)

__all__ = [
    "CoverageLedger",
    "cmdi_output",
    "nosqli_error",
    "oob_interaction",
    "open_redirect",
    "path_traversal_read",
    "sqli_boolean",
    "sqli_error",
    "sqli_time",
    "ssrf_metadata",
    "ssti_eval",
    "xss_reflection",
]
