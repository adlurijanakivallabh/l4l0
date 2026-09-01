"""Hermetic tests for cross-engagement pattern memory ("My additions")."""

from __future__ import annotations

import json
from pathlib import Path

from reachagent.memory.pattern_db import (
    load_patterns,
    patterns_for_technology,
    record_confirmed_pattern,
)


def test_round_trip_write_and_load(tmp_path: Path) -> None:
    path = tmp_path / "patterns.jsonl"
    record_confirmed_pattern("sqli", "WordPress, PHP", "differential", "high", path=path)
    patterns = load_patterns(path=path)
    assert len(patterns) == 1
    assert patterns[0].vuln_class == "sqli"
    assert patterns[0].technology == "WordPress, PHP"


def test_blank_technology_is_never_recorded(tmp_path: Path) -> None:
    path = tmp_path / "patterns.jsonl"
    record_confirmed_pattern("sqli", "", "differential", "high", path=path)
    assert load_patterns(path=path) == []
    assert not path.exists()


def test_load_from_missing_file_is_empty_not_an_error(tmp_path: Path) -> None:
    assert load_patterns(path=tmp_path / "nonexistent.jsonl") == []


def test_corrupt_lines_are_skipped_not_fatal(tmp_path: Path) -> None:
    path = tmp_path / "patterns.jsonl"
    path.write_text(
        "not json at all\n"
        + json.dumps(
            {
                "vuln_class": "xss_reflected",
                "technology": "React",
                "oracle_used": "d",
                "severity": "medium",
                "timestamp": 1.0,
            }
        )
        + "\n"
        + json.dumps({"vuln_class": 123})  # wrong type, invalid record
        + "\n",
        encoding="utf-8",
    )
    patterns = load_patterns(path=path)
    assert len(patterns) == 1
    assert patterns[0].vuln_class == "xss_reflected"


def test_patterns_for_technology_matches_case_insensitive_substring(tmp_path: Path) -> None:
    path = tmp_path / "patterns.jsonl"
    record_confirmed_pattern("sqli", "WordPress, PHP", "differential", "high", path=path)
    record_confirmed_pattern("xss_stored", "React, webpack", "structural", "medium", path=path)
    matches = patterns_for_technology("wordpress", path=path)
    assert len(matches) == 1
    assert matches[0].vuln_class == "sqli"


def test_patterns_for_technology_most_recent_first(tmp_path: Path) -> None:
    path = tmp_path / "patterns.jsonl"
    path.write_text(
        json.dumps(
            {
                "vuln_class": "old",
                "technology": "WordPress",
                "oracle_used": "d",
                "severity": "high",
                "timestamp": 1.0,
            }
        )
        + "\n"
        + json.dumps(
            {
                "vuln_class": "new",
                "technology": "WordPress",
                "oracle_used": "d",
                "severity": "high",
                "timestamp": 2.0,
            }
        )
        + "\n",
        encoding="utf-8",
    )
    matches = patterns_for_technology("WordPress", path=path)
    assert [m.vuln_class for m in matches] == ["new", "old"]


def test_patterns_for_technology_respects_limit(tmp_path: Path) -> None:
    path = tmp_path / "patterns.jsonl"
    for i in range(10):
        record_confirmed_pattern(f"class-{i}", "WordPress", "differential", "high", path=path)
    assert len(patterns_for_technology("WordPress", limit=3, path=path)) == 3


def test_patterns_for_technology_blank_query_returns_empty(tmp_path: Path) -> None:
    path = tmp_path / "patterns.jsonl"
    record_confirmed_pattern("sqli", "WordPress", "differential", "high", path=path)
    assert patterns_for_technology("", path=path) == []


def test_record_never_raises_on_unwritable_path(tmp_path: Path) -> None:
    # A path under a file (not a directory) cannot be mkdir'd into — must fail
    # open, never raise, since this is advisory-only and must never break a scan.
    blocker = tmp_path / "blocker"
    blocker.write_text("x", encoding="utf-8")
    record_confirmed_pattern(
        "sqli", "WordPress", "differential", "high", path=blocker / "patterns.jsonl"
    )


def test_trim_caps_the_file_at_max_records(tmp_path: Path, monkeypatch) -> None:  # noqa: ANN001
    import reachagent.memory.pattern_db as pattern_db_module

    monkeypatch.setattr(pattern_db_module, "_MAX_RECORDS", 5)
    path = tmp_path / "patterns.jsonl"
    for i in range(10):
        record_confirmed_pattern(f"class-{i}", "WordPress", "differential", "high", path=path)
    patterns = load_patterns(path=path)
    assert len(patterns) == 5
    # oldest records dropped first — the last five written survive
    assert {p.vuln_class for p in patterns} == {f"class-{i}" for i in range(5, 10)}
