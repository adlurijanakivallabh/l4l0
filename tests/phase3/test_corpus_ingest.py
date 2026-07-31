"""Tagged corpus ingest — PayloadsAllTheThings / SecLists (plan §9/§12; Task 2).

Asserts the ingest DoD:

  1. Every ingested corpus entry carries the full six-field §9 schema, correctly
     typed (sink coerced to SinkType-or-None, oracle to a §7 family).
  2. An untagged / un-mappable corpus entry is unloadable (PayloadLibraryError):
     unknown sink, unknown oracle, missing field, or a graph_edge_on_success that
     isn't a real §6 edge.
  3. Sink isolation still holds after ingest — an html_reflection sink never
     yields a SQL payload, and vice versa — over the merged library.
  4. Oracle-confidence ordering still holds over the merged library.

Corpora expand the payload SET only; they never expand what counts as confirmed
(every entry still routes through run_oracle via its tagged oracle_type). No live
gate is exercised here — ingest is pure file loading.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from reachagent.graph.edges import FindingEdge, StructuralEdge
from reachagent.graph.nodes import SinkType
from reachagent.oracles import OracleMechanism
from reachagent.payloads import (
    PayloadLibrary,
    PayloadLibraryError,
    build_library,
    load_corpus_entries,
)
from reachagent.payloads.corpus import _entries_from_corpus_file

_KNOWN_EDGES = {*(e.value for e in StructuralEdge), *(e.value for e in FindingEdge)}


# -- Invariant 1: every ingested entry is fully, correctly tagged -------------


def test_corpus_ingests_entries() -> None:
    entries = load_corpus_entries()
    assert len(entries) > 0


def test_every_corpus_entry_carries_full_schema() -> None:
    for e in load_corpus_entries():
        assert e.vuln_class
        assert e.context
        assert isinstance(e.oracle_type, OracleMechanism)
        assert e.inferred_sink_type is None or isinstance(e.inferred_sink_type, SinkType)
        assert e.payload_ref
        assert e.graph_edge_on_success in _KNOWN_EDGES


def test_corpus_payload_refs_are_handles_not_inlined_strings() -> None:
    # payload_ref stays a stable handle (source/technique path), never raw exploit
    # text — the §9 no-inlining rule the base slice also follows.
    for e in load_corpus_entries():
        assert "/" in e.payload_ref
        assert " " not in e.payload_ref


def test_named_source_selection_and_union() -> None:
    patt = load_corpus_entries(["PayloadsAllTheThings"])
    seclists = load_corpus_entries(["SecLists"])
    both = load_corpus_entries()
    assert len(patt) > 0
    assert len(seclists) > 0
    assert len(both) == len(patt) + len(seclists)


def test_unknown_source_name_raises() -> None:
    with pytest.raises(PayloadLibraryError):
        load_corpus_entries(["NotACorpus"])


def test_build_library_merges_base_plus_corpus() -> None:
    base = PayloadLibrary.from_file()
    merged = build_library()
    corpus = load_corpus_entries()
    assert len(merged) == len(base) + len(corpus)


def test_build_library_without_corpus_is_bare_slice() -> None:
    base = PayloadLibrary.from_file()
    assert len(build_library(include_corpus=False)) == len(base)


# -- Invariant 2: untagged / un-mappable entries are unloadable ---------------


def _write_corpus(tmp_path: Path, body: str) -> Path:
    p = tmp_path / "bad_corpus.yaml"
    p.write_text(body, encoding="utf-8")
    return p


def test_unknown_sink_in_corpus_raises(tmp_path: Path) -> None:
    bad = _write_corpus(
        tmp_path,
        "source: X\npayloads:\n"
        "  - vuln_class: sqli\n"
        "    context: c\n"
        "    inferred_sink_type: not_a_real_sink\n"
        "    oracle_type: differential\n"
        "    payload_ref: x/y\n"
        "    graph_edge_on_success: enables\n",
    )
    with pytest.raises(PayloadLibraryError):
        _entries_from_corpus_file(bad)


def test_unknown_oracle_in_corpus_raises(tmp_path: Path) -> None:
    bad = _write_corpus(
        tmp_path,
        "source: X\npayloads:\n"
        "  - vuln_class: sqli\n"
        "    context: c\n"
        "    inferred_sink_type: sql\n"
        "    oracle_type: not_a_real_oracle\n"
        "    payload_ref: x/y\n"
        "    graph_edge_on_success: enables\n",
    )
    with pytest.raises(PayloadLibraryError):
        _entries_from_corpus_file(bad)


def test_missing_field_in_corpus_raises(tmp_path: Path) -> None:
    bad = _write_corpus(
        tmp_path,
        "source: X\npayloads:\n  - vuln_class: sqli\n    context: c\n",
    )
    with pytest.raises(PayloadLibraryError):
        _entries_from_corpus_file(bad)


def test_unknown_graph_edge_in_corpus_raises(tmp_path: Path) -> None:
    # The stricter-than-base check: a well-formed row whose success edge is not a
    # real §6 edge is un-mappable (it would write a phantom edge on confirm).
    bad = _write_corpus(
        tmp_path,
        "source: X\npayloads:\n"
        "  - vuln_class: sqli\n"
        "    context: c\n"
        "    inferred_sink_type: sql\n"
        "    oracle_type: differential\n"
        "    payload_ref: x/y\n"
        "    graph_edge_on_success: not_a_real_edge\n",
    )
    with pytest.raises(PayloadLibraryError):
        _entries_from_corpus_file(bad)


def test_corpus_file_without_payloads_key_raises(tmp_path: Path) -> None:
    bad = _write_corpus(tmp_path, "source: X\n")
    with pytest.raises(PayloadLibraryError):
        _entries_from_corpus_file(bad)


# -- Invariant 3: sink isolation holds over the merged library ----------------


def test_merged_html_reflection_never_yields_sql_entry() -> None:
    lib = build_library()
    sql_classes = {"sqli", "sqli_blind", "nosqli", "ldapi"}
    xss_classes = {"xss_reflected", "xss_stored"}
    for vuln_class in sql_classes | xss_classes:
        for entry in lib.get_payloads(vuln_class, SinkType.HTML_REFLECTION):
            assert entry.inferred_sink_type is SinkType.HTML_REFLECTION
            assert entry.inferred_sink_type is not SinkType.SQL


def test_merged_sql_sink_never_yields_html_reflection_entry() -> None:
    lib = build_library()
    for vuln_class in ("sqli", "sqli_blind", "xss_reflected", "xss_stored"):
        for entry in lib.get_payloads(vuln_class, SinkType.SQL):
            assert entry.inferred_sink_type is SinkType.SQL
            assert entry.inferred_sink_type is not SinkType.HTML_REFLECTION


def test_merged_get_payloads_only_returns_matching_class_and_sink() -> None:
    lib = build_library()
    for entry in lib.get_payloads("sqli", SinkType.SQL):
        assert entry.vuln_class == "sqli"
        assert entry.inferred_sink_type is SinkType.SQL


# -- Invariant 4: oracle-confidence ordering holds over the merged library ----


def test_merged_blind_sqli_orders_oob_before_timing() -> None:
    # The corpus adds both OOB and timing blind-SQLi entries; OOB must still sort
    # before pure timing (§9), and ranks must be non-decreasing.
    results = build_library().get_payloads("sqli_blind", SinkType.SQL)
    oracles = [e.oracle_type for e in results]
    assert OracleMechanism.OOB_CALLBACK in oracles
    assert OracleMechanism.TIMING_STATISTICAL in oracles
    assert oracles.index(OracleMechanism.OOB_CALLBACK) < oracles.index(
        OracleMechanism.TIMING_STATISTICAL
    )
    ranks = [e.confidence_rank for e in results]
    assert ranks == sorted(ranks)


def test_merged_ordering_is_deterministic() -> None:
    lib = build_library()
    first = [e.payload_ref for e in lib.get_payloads("sqli_blind", SinkType.SQL)]
    second = [e.payload_ref for e in lib.get_payloads("sqli_blind", SinkType.SQL)]
    assert first == second
