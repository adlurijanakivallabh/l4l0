"""Tagged corpus ingest — PayloadsAllTheThings / SecLists (plan §9/§12).

Source shape — **vendored, curated, pre-tagged subset**, not a live mirror.
Each corpus file under ``data/corpus/`` pairs a stable ``payload_ref`` handle
(naming the upstream corpus + technique) with the full six-field ReachAgent tag
schema. We vendor a curated subset rather than clone/download the upstream
repositories at runtime for three reasons:

  * **No network dependency in detection** (CLAUDE.md, §9): a detection run must
    never reach out to GitHub to know its payloads.
  * **Reproducible tests**: the ingested set is fixed and reviewable in-tree, so
    ``get_payloads`` results don't drift with an upstream force-push.
  * **Tag integrity**: upstream corpora are untagged payload text; the value
    ReachAgent adds is the ``(vuln_class, inferred_sink_type, oracle_type,
    graph_edge_on_success)`` tagging + oracle wiring, which must be authored and
    reviewed, not scraped. Raw exploit strings stay behind the ``payload_ref``
    handle exactly as the base slice does — nothing inlined (§9).

Corpora expand the payload *set* only; they never expand what counts as
confirmed. Every ingested entry still routes through ``run_oracle`` via its
tagged ``oracle_type`` — one of the six §7 families, never a seventh.

An entry that cannot be mapped to a known sink, a known §7 oracle, or a real §6
graph edge is **unloadable**: ingest raises ``PayloadLibraryError`` rather than
admit a mis-tagged payload that would silently misroute or never match.

Storage stays YAML: base slice + both corpus subsets total ~31 entries, well
below the point where the ``(vuln_class, inferred_sink_type)`` index needs
SQLite (§12). SQLite is deferred as unwarranted until the corpus grows an order
of magnitude; ``PayloadLibrary.from_file`` (YAML) is unchanged.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from pathlib import Path

import yaml

from reachagent.graph.edges import FindingEdge, StructuralEdge
from reachagent.payloads.library import (
    PayloadEntry,
    PayloadLibrary,
    PayloadLibraryError,
)

# Corpus subsets shipped with the package, keyed by upstream source name.
_CORPUS_DIR = Path(__file__).parent / "data" / "corpus"
_CORPUS_FILES: dict[str, Path] = {
    "PayloadsAllTheThings": _CORPUS_DIR / "payloadsallthethings.yaml",
    "SecLists": _CORPUS_DIR / "seclists.yaml",
}

# Real §6 graph edges an entry may declare for graph_edge_on_success. Corpus
# ingest validates against this set — a handle whose success edge isn't a real
# edge is un-mappable, so it fails loudly instead of writing a phantom edge.
_KNOWN_EDGES: frozenset[str] = frozenset(
    {*(e.value for e in StructuralEdge), *(e.value for e in FindingEdge)}
)


def _validate_edge(raw: Mapping[str, object]) -> None:
    """Reject a corpus row whose success edge isn't a real §6 edge (un-mappable)."""
    edge = str(raw.get("graph_edge_on_success", ""))
    if edge not in _KNOWN_EDGES:
        raise PayloadLibraryError(
            f"corpus entry {raw.get('payload_ref')!r} declares unknown "
            f"graph_edge_on_success {edge!r}; not a §6 edge {sorted(_KNOWN_EDGES)}"
        )


def _entries_from_corpus_file(path: Path) -> list[PayloadEntry]:
    """Parse and fully tag one corpus file; every row validated or it's unloadable."""
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(raw, Mapping) or "payloads" not in raw:
        raise PayloadLibraryError(f"corpus file {path.name} must have a top-level 'payloads' list")
    rows = raw["payloads"] or []
    if not isinstance(rows, list):
        raise PayloadLibraryError(f"corpus file {path.name}: 'payloads' must be a list")
    entries: list[PayloadEntry] = []
    for row in rows:
        if not isinstance(row, Mapping):
            raise PayloadLibraryError(f"corpus file {path.name}: each payload must be a mapping")
        # from_mapping validates the six fields + coerces sink/oracle (raising on
        # unknown ones); _validate_edge adds the stricter §6-edge check on top.
        _validate_edge(row)
        entries.append(PayloadEntry.from_mapping(row))
    return entries


def load_corpus_entries(sources: Iterable[str] | None = None) -> list[PayloadEntry]:
    """Ingest tagged entries from the named corpus subsets (default: all).

    ``sources`` names a subset of ``_CORPUS_FILES`` keys; an unknown source name
    is an error (a typo must not silently ingest nothing).
    """
    names = list(sources) if sources is not None else list(_CORPUS_FILES)
    entries: list[PayloadEntry] = []
    for name in names:
        path = _CORPUS_FILES.get(name)
        if path is None:
            raise PayloadLibraryError(
                f"unknown corpus source {name!r}; known: {sorted(_CORPUS_FILES)}"
            )
        entries.extend(_entries_from_corpus_file(path))
    return entries


def build_library(
    base_path: str | Path | None = None,
    *,
    corpus_sources: Iterable[str] | None = None,
    include_corpus: bool = True,
) -> PayloadLibrary:
    """Build a library from the base slice plus (optionally) the tagged corpora.

    The base hand slice (``from_file``) is loaded unchanged, then corpus entries
    are appended. Lookup semantics are identical — corpus entries are ordinary
    ``PayloadEntry`` rows sharing the same sink-matched, confidence-ordered
    ``get_payloads`` contract. ``include_corpus=False`` reproduces the bare slice.
    """
    entries = list(PayloadLibrary.from_file(base_path).all_entries())
    if include_corpus:
        entries.extend(load_corpus_entries(corpus_sources))
    return PayloadLibrary(entries)
