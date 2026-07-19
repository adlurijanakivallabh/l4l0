"""Tagged payload library — sink-matched, confidence-ordered lookup (plan §9; Task 4).

Asserts the Task 4 DoD invariants:

  1. Entries exist for the classes the VAmPI toggle covers (BOLA / IDOR /
     mass-assignment — JWT deferred per docs/phase1-tasks.md's scope note), each
     carrying the full §9 schema (vuln_class, context, inferred_sink_type,
     oracle_type, payload_ref, graph_edge_on_success).
  2. ``get_payloads(vuln_class, sink_type)`` returns only sink-matched entries,
     ordered by oracle confidence — including the headline invariant that an
     ``html_reflection`` param never receives a SQL entry and vice versa.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from reachagent.graph.nodes import SinkType
from reachagent.oracles import OracleMechanism
from reachagent.payloads import PayloadEntry, PayloadLibrary, PayloadLibraryError

# The classes the Phase 1 VAmPI gate scores (docs/phase1-tasks.md Task 4 / gate).
VAMPI_TOGGLE_CLASSES = {"bola", "idor", "mass_assignment"}


@pytest.fixture
def library() -> PayloadLibrary:
    """The shipped VAmPI-relevant slice (payloads/data/library.yaml)."""
    return PayloadLibrary.from_file()


# -- Invariant 1: coverage + full §9 schema -------------------------------


def test_covers_the_vampi_toggle_classes(library: PayloadLibrary) -> None:
    present = {e.vuln_class for e in library.all_entries()}
    assert VAMPI_TOGGLE_CLASSES <= present


def test_every_entry_carries_the_full_schema(library: PayloadLibrary) -> None:
    # The six §9 fields, each populated and correctly typed. inferred_sink_type
    # may legitimately be None (authz classes), but the field is always present.
    assert len(library) > 0
    for e in library.all_entries():
        assert e.vuln_class
        assert e.context
        assert isinstance(e.oracle_type, OracleMechanism)
        assert e.inferred_sink_type is None or isinstance(e.inferred_sink_type, SinkType)
        assert e.payload_ref
        assert e.graph_edge_on_success


def test_authz_classes_have_no_injection_sink(library: PayloadLibrary) -> None:
    # BOLA/IDOR/mass-assignment are differential authorization classes — they
    # carry no injection sink, and their oracle is the differential family (§7).
    for e in library.all_entries():
        if e.vuln_class in VAMPI_TOGGLE_CLASSES:
            assert e.inferred_sink_type is None
            assert e.oracle_type is OracleMechanism.DIFFERENTIAL


# -- Invariant 2: sink-matched, confidence-ordered lookup -----------------


def test_get_payloads_returns_only_sink_matched_entries(library: PayloadLibrary) -> None:
    for entry in library.get_payloads("sqli", SinkType.SQL):
        assert entry.inferred_sink_type is SinkType.SQL
        assert entry.vuln_class == "sqli"


def test_html_reflection_param_never_receives_a_sql_entry(library: PayloadLibrary) -> None:
    # The headline §9 invariant, one direction: asking for an html_reflection
    # sink must never surface a SQL-tagged payload.
    for vuln_class in ("sqli", "sqli_blind", "xss_reflected"):
        for entry in library.get_payloads(vuln_class, SinkType.HTML_REFLECTION):
            assert entry.inferred_sink_type is not SinkType.SQL
            assert entry.inferred_sink_type is SinkType.HTML_REFLECTION


def test_sql_param_never_receives_an_html_reflection_entry(library: PayloadLibrary) -> None:
    # ...and the reverse: a SQL sink never yields an html_reflection payload.
    for vuln_class in ("sqli", "sqli_blind", "xss_reflected"):
        for entry in library.get_payloads(vuln_class, SinkType.SQL):
            assert entry.inferred_sink_type is not SinkType.HTML_REFLECTION
            assert entry.inferred_sink_type is SinkType.SQL


def test_none_sink_matches_authz_classes_not_sinked_ones(library: PayloadLibrary) -> None:
    # sink_type=None selects the sink-less authz classes, and does NOT act as a
    # wildcard that would leak a sinked (e.g. SQL) entry.
    bola = library.get_payloads("bola", None)
    assert bola
    assert all(e.inferred_sink_type is None for e in bola)
    # A sinked class queried with the wrong (None) sink returns nothing.
    assert library.get_payloads("sqli", None) == []


def test_sinked_class_queried_without_sink_is_empty(library: PayloadLibrary) -> None:
    # Default sink_type is None, so calling get_payloads for a sinked class
    # without naming its sink must not match — no accidental "return everything".
    assert library.get_payloads("sqli") == []


def test_results_are_ordered_by_oracle_confidence(library: PayloadLibrary) -> None:
    # For blind SQLi the library has both an OOB entry and a timing fallback; the
    # plan's explicit rule is OOB-capable before pure-timing (§9).
    results = library.get_payloads("sqli_blind", SinkType.SQL)
    oracles = [e.oracle_type for e in results]
    assert OracleMechanism.OOB_CALLBACK in oracles
    assert OracleMechanism.TIMING_STATISTICAL in oracles
    assert oracles.index(OracleMechanism.OOB_CALLBACK) < oracles.index(
        OracleMechanism.TIMING_STATISTICAL
    )
    # Confidence ranks are non-decreasing across the whole result list.
    ranks = [e.confidence_rank for e in results]
    assert ranks == sorted(ranks)


def test_ordering_is_deterministic(library: PayloadLibrary) -> None:
    # Same query, same order every call — payload_ref tie-breaks within a rank.
    first = [e.payload_ref for e in library.get_payloads("sqli_blind", SinkType.SQL)]
    second = [e.payload_ref for e in library.get_payloads("sqli_blind", SinkType.SQL)]
    assert first == second


def test_unknown_class_returns_empty_not_error(library: PayloadLibrary) -> None:
    assert library.get_payloads("nonexistent_class", SinkType.SQL) == []


# -- Loader validation: malformed tags fail loudly ------------------------


def test_unknown_sink_type_raises(tmp_path: Path) -> None:
    bad = tmp_path / "bad.yaml"
    bad.write_text(
        "payloads:\n"
        "  - vuln_class: x\n"
        "    context: c\n"
        "    inferred_sink_type: not_a_real_sink\n"
        "    oracle_type: differential\n"
        "    payload_ref: r\n"
        "    graph_edge_on_success: can_call\n",
        encoding="utf-8",
    )
    with pytest.raises(PayloadLibraryError):
        PayloadLibrary.from_file(bad)


def test_unknown_oracle_type_raises(tmp_path: Path) -> None:
    bad = tmp_path / "bad.yaml"
    bad.write_text(
        "payloads:\n"
        "  - vuln_class: x\n"
        "    context: c\n"
        "    inferred_sink_type: sql\n"
        "    oracle_type: not_a_real_oracle\n"
        "    payload_ref: r\n"
        "    graph_edge_on_success: enables\n",
        encoding="utf-8",
    )
    with pytest.raises(PayloadLibraryError):
        PayloadLibrary.from_file(bad)


def test_missing_field_raises() -> None:
    # A row missing required §9 fields is rejected at construction.
    with pytest.raises(PayloadLibraryError):
        PayloadEntry.from_mapping({"vuln_class": "x", "context": "c"})
