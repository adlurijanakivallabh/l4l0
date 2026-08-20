"""Tagged payload library (plan §9).

Custom, tagged payloads are a core strength — the system of record for what
counts as a confirmed finding is ReachAgent's own payloads + deterministic
oracles, never an external scanner (§9). Value is in the tagging, sink-matching,
and oracle wiring, not in reinventing payload strings.

Storage: YAML for Phase 1; SQLite once ``(vuln_class, inferred_sink_type)``
lookups need indexing (§12).
"""

from __future__ import annotations

from reachagent.payloads.corpus import (
    CorpusIngestReport,
    build_library,
    load_corpus_entries,
    load_corpus_report,
)
from reachagent.payloads.library import (
    PayloadEntry,
    PayloadLibrary,
    PayloadLibraryError,
)
from reachagent.payloads.payload_resolver import (
    MissingSlotError,
    UnknownPayloadRefError,
    expected_execution_output,
    mint_fire_kit,
    required_slots,
    resolve,
    resolve_entry,
    resolves,
    template_refs,
)

__all__ = [
    "CorpusIngestReport",
    "MissingSlotError",
    "PayloadEntry",
    "PayloadLibrary",
    "PayloadLibraryError",
    "UnknownPayloadRefError",
    "build_library",
    "expected_execution_output",
    "load_corpus_entries",
    "load_corpus_report",
    "mint_fire_kit",
    "required_slots",
    "resolve",
    "resolve_entry",
    "resolves",
    "template_refs",
]
