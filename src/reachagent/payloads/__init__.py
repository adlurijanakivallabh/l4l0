"""Tagged payload library (plan §9).

Custom, tagged payloads are a core strength — the system of record for what
counts as a confirmed finding is ReachAgent's own payloads + deterministic
oracles, never an external scanner (§9). Value is in the tagging, sink-matching,
and oracle wiring, not in reinventing payload strings.

Storage: YAML for Phase 1; SQLite once ``(vuln_class, inferred_sink_type)``
lookups need indexing (§12).
"""

from __future__ import annotations

from reachagent.payloads.library import (
    PayloadEntry,
    PayloadLibrary,
    PayloadLibraryError,
)

__all__ = [
    "PayloadEntry",
    "PayloadLibrary",
    "PayloadLibraryError",
]
