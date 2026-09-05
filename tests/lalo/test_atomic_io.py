"""Tests for crash-safe atomic writes: round-trip and a simulated mid-write crash."""

from __future__ import annotations

from pathlib import Path

from lalo.core.atomic_io import atomic_write_verified


def test_write_then_read_round_trips(tmp_path: Path) -> None:
    target = tmp_path / "graph.json"
    atomic_write_verified(target, b"hello world")
    assert target.read_bytes() == b"hello world"


def test_overwrite_replaces_old_content(tmp_path: Path) -> None:
    target = tmp_path / "graph.json"
    atomic_write_verified(target, b"first")
    atomic_write_verified(target, b"second")
    assert target.read_bytes() == b"second"


def test_creates_missing_parent_directories(tmp_path: Path) -> None:
    target = tmp_path / "nested" / "dir" / "graph.json"
    atomic_write_verified(target, b"data")
    assert target.read_bytes() == b"data"


def test_leftover_crashed_temp_file_does_not_affect_the_real_file(tmp_path: Path) -> None:
    target = tmp_path / "graph.json"
    atomic_write_verified(target, b"good state")

    # Simulate a crash between the temp-file write and the atomic rename: a
    # torn/garbage temp file is left on disk, but the real path was never
    # touched because os.replace() never ran.
    crashed_tmp = tmp_path / f".{target.name}.tmp-deadbeef"
    crashed_tmp.write_bytes(b"garbage from an interrupted write")

    assert target.read_bytes() == b"good state"

    # A fresh write afterward still succeeds despite the orphaned tmp file.
    atomic_write_verified(target, b"newer state")
    assert target.read_bytes() == b"newer state"
    assert crashed_tmp.exists()  # orphaned crash artifact, never cleaned up automatically


def test_no_leftover_temp_file_after_a_successful_write(tmp_path: Path) -> None:
    target = tmp_path / "graph.json"
    atomic_write_verified(target, b"data")
    leftovers = list(tmp_path.glob(".*.tmp-*"))
    assert leftovers == []
