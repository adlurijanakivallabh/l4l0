"""Payload library loader and sink-matched lookup (plan §9; Task 4).

Backs the Explorer's ``get_payloads(vuln_class, sink_type)`` tool (§13): given a
vuln class and the sink type ``fingerprint_parameter`` inferred, return only the
entries relevant to that sink, ordered by oracle confidence (§7) — so a
parameter fingerprinted as ``html_reflection`` is never handed a SQLi payload,
and vice versa.

Entry schema (§9), exactly six fields::

    {vuln_class, context, inferred_sink_type, oracle_type, payload_ref,
     graph_edge_on_success}

Storage is YAML for Phase 1 (``data/library.yaml``); migrates to SQLite once the
``(vuln_class, inferred_sink_type)`` index needs to scale (§12). The value is in
the tagging and oracle wiring, not the payload strings — entries carry a
``payload_ref`` handle, never an inlined exploit string (§9).
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path

import yaml

from reachagent.graph.nodes import SinkType
from reachagent.oracles import OracleMechanism

# Default library location — the tagged VAmPI slice shipped with the package.
_DEFAULT_DATA = Path(__file__).parent / "data" / "library.yaml"

# Oracle confidence ranking (§7, §9): the order get_payloads sorts results by.
# Lower rank = higher confidence = tried first. The plan's explicit constraint is
# "OOB-capable entries before pure-timing ones" — timing is noisy (its blind-only
# ceiling matches the published 0% naive-detection baseline, §5), so it sorts
# last. Definitive mechanisms (a forged token works or it doesn't; a script ran
# or it didn't; a callback fired or it didn't) rank above statistical ones.
_ORACLE_CONFIDENCE: dict[OracleMechanism, int] = {
    OracleMechanism.STRUCTURAL: 0,
    OracleMechanism.EXECUTION_CONFIRMATION: 1,
    OracleMechanism.OOB_CALLBACK: 2,
    OracleMechanism.DIFFERENTIAL: 3,
    OracleMechanism.BUSINESS_RULE_INVARIANT: 4,
    OracleMechanism.TIMING_STATISTICAL: 5,
}


class PayloadLibraryError(RuntimeError):
    """Raised when a library entry is malformed or references an unknown tag.

    Fails loudly at load time: a payload tagged with a sink or oracle the system
    doesn't know would silently never match (or misroute to the wrong oracle), so
    a typo must surface as an error, not a quietly empty result.
    """


def _coerce_sink(value: object) -> SinkType | None:
    """Parse an ``inferred_sink_type`` cell into a ``SinkType`` (or ``None``).

    ``null``/absent means the class has no injection sink (BOLA/IDOR/
    mass-assignment are authorization classes, not sink-driven) — a legitimate
    value, distinct from an unknown string, which is an error.
    """
    if value is None:
        return None
    try:
        return SinkType(str(value))
    except ValueError as exc:
        raise PayloadLibraryError(f"unknown inferred_sink_type {value!r}") from exc


def _coerce_oracle(value: object) -> OracleMechanism:
    try:
        return OracleMechanism(str(value))
    except ValueError as exc:
        raise PayloadLibraryError(f"unknown oracle_type {value!r}") from exc


@dataclass(frozen=True)
class PayloadEntry:
    """One tagged payload — the full §9 schema, exactly six fields.

    Frozen so an entry handed to the Explorer can't be mutated out from under the
    library's ``(vuln_class, sink)`` index.
    """

    vuln_class: str
    context: str
    inferred_sink_type: SinkType | None
    oracle_type: OracleMechanism
    payload_ref: str
    graph_edge_on_success: str

    @property
    def confidence_rank(self) -> int:
        """Sort key for oracle-confidence ordering (lower = more confident)."""
        return _ORACLE_CONFIDENCE[self.oracle_type]

    @classmethod
    def from_mapping(cls, raw: Mapping[str, object]) -> PayloadEntry:
        """Build one entry from a parsed YAML mapping, validating every field."""
        required = {
            "vuln_class",
            "context",
            "inferred_sink_type",
            "oracle_type",
            "payload_ref",
            "graph_edge_on_success",
        }
        missing = required - raw.keys()
        if missing:
            raise PayloadLibraryError(f"payload entry missing field(s) {sorted(missing)}: {raw!r}")
        return cls(
            vuln_class=str(raw["vuln_class"]),
            context=str(raw["context"]),
            inferred_sink_type=_coerce_sink(raw["inferred_sink_type"]),
            oracle_type=_coerce_oracle(raw["oracle_type"]),
            payload_ref=str(raw["payload_ref"]),
            graph_edge_on_success=str(raw["graph_edge_on_success"]),
        )


class PayloadLibrary:
    """Sink-matched, oracle-confidence-ordered payload lookup (§9).

    Business-logic templates and race conditions are request-sequencing/timing
    tests — they skip this library entirely and are not represented here (§9).
    """

    def __init__(self, entries: Iterable[PayloadEntry]) -> None:
        self._entries: tuple[PayloadEntry, ...] = tuple(entries)

    @classmethod
    def from_file(cls, path: str | Path | None = None) -> PayloadLibrary:
        """Load and validate the tagged library from YAML (defaults to the slice)."""
        data_path = Path(path) if path is not None else _DEFAULT_DATA
        raw = yaml.safe_load(data_path.read_text(encoding="utf-8"))
        if not isinstance(raw, Mapping) or "payloads" not in raw:
            raise PayloadLibraryError("library file must have a top-level 'payloads' list")
        rows = raw["payloads"] or []
        if not isinstance(rows, list):
            raise PayloadLibraryError("'payloads' must be a list")
        entries = [PayloadEntry.from_mapping(row) for row in rows]
        return cls(entries)

    def __len__(self) -> int:
        return len(self._entries)

    def all_entries(self) -> tuple[PayloadEntry, ...]:
        """Every entry, unfiltered — for coverage checks and reporting."""
        return self._entries

    def get_payloads(
        self, vuln_class: str, sink_type: SinkType | None = None
    ) -> list[PayloadEntry]:
        """Return sink-matched entries for a vuln class, ordered by confidence (§9).

        Filtering is the safety-relevant part: an entry is returned only if its
        ``inferred_sink_type`` matches ``sink_type`` exactly. So an
        ``html_reflection`` sink never yields a SQL entry, and a ``sql`` sink
        never yields an ``html_reflection`` one — the §9 sink-isolation invariant.

        ``sink_type=None`` matches the sink-less authorization classes
        (BOLA/IDOR/mass-assignment), whose entries carry no injection sink; it
        does *not* mean "any sink". Results are ordered by oracle confidence,
        highest first (OOB before pure timing), with ``payload_ref`` as a stable
        tie-breaker so ordering is deterministic run to run.
        """
        matched = [
            e
            for e in self._entries
            if e.vuln_class == vuln_class and e.inferred_sink_type == sink_type
        ]
        matched.sort(key=lambda e: (e.confidence_rank, e.payload_ref))
        return matched
