"""Tests for crash-safe atomic writes: round-trip and a simulated mid-write crash."""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from lalo.core.atomic_io import append_owner_only_line, atomic_write_verified


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


def test_written_file_is_owner_only_regardless_of_a_permissive_umask(tmp_path: Path) -> None:
    target = tmp_path / "usage.json"
    old_umask = os.umask(0o000)
    try:
        atomic_write_verified(target, b"engagement-adjacent state")
    finally:
        os.umask(old_umask)
    assert stat.S_IMODE(target.stat().st_mode) == 0o600


def test_overwrite_tightens_permissions_even_if_the_old_file_was_looser(tmp_path: Path) -> None:
    target = tmp_path / "usage.json"
    target.write_bytes(b"pre-existing, world-readable file from an older run")
    target.chmod(0o644)
    atomic_write_verified(target, b"new state")
    assert stat.S_IMODE(target.stat().st_mode) == 0o600


def test_atomic_write_verified_retries_a_transient_oserror(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "x.json"
    calls = {"n": 0}
    real_replace = os.replace

    def flaky_replace(src: object, dst: object) -> None:
        calls["n"] += 1
        if calls["n"] < 2:
            raise OSError("simulated transient disk error")
        real_replace(src, dst)  # type: ignore[arg-type]

    monkeypatch.setattr(os, "replace", flaky_replace)
    atomic_write_verified(path, b"hello")
    assert path.read_bytes() == b"hello"
    assert calls["n"] == 2


def test_atomic_write_verified_gives_up_after_bounded_retries(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls = {"n": 0}

    def always_fails(src: object, dst: object) -> None:
        calls["n"] += 1
        raise OSError("permanently broken")

    monkeypatch.setattr(os, "replace", always_fails)
    with pytest.raises(OSError, match="permanently broken"):
        atomic_write_verified(tmp_path / "x.json", b"hello")
    assert calls["n"] == 3


def test_append_owner_only_line_retries_a_transient_oserror(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "events.jsonl"
    calls = {"n": 0}
    real_open = os.open

    def flaky_open(path: object, flags: int, mode: int = 0o777) -> int:
        calls["n"] += 1
        if calls["n"] < 2:
            raise OSError("simulated transient disk error")
        return real_open(path, flags, mode)

    monkeypatch.setattr(os, "open", flaky_open)
    append_owner_only_line(target, "line")
    assert target.read_text(encoding="utf-8") == "line\n"
    assert calls["n"] == 2


def test_append_owner_only_line_gives_up_after_bounded_retries(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls = {"n": 0}

    def always_fails(path: object, flags: int, mode: int = 0o777) -> int:
        calls["n"] += 1
        raise OSError("permanently broken")

    monkeypatch.setattr(os, "open", always_fails)
    with pytest.raises(OSError, match="permanently broken"):
        append_owner_only_line(tmp_path / "events.jsonl", "line")
    assert calls["n"] == 3


# --- append_owner_only_line -------------------------------------------------


def test_append_owner_only_line_creates_and_appends(tmp_path: Path) -> None:
    target = tmp_path / "events.jsonl"
    append_owner_only_line(target, "one")
    append_owner_only_line(target, "two")
    assert target.read_text(encoding="utf-8") == "one\ntwo\n"


def test_append_owner_only_line_does_not_double_the_trailing_newline(tmp_path: Path) -> None:
    target = tmp_path / "events.jsonl"
    append_owner_only_line(target, "already has one\n")
    assert target.read_text(encoding="utf-8") == "already has one\n"


def test_append_owner_only_line_creates_missing_parent_directories(tmp_path: Path) -> None:
    target = tmp_path / "nested" / "dir" / "events.jsonl"
    append_owner_only_line(target, "line")
    assert target.read_text(encoding="utf-8") == "line\n"


def test_append_owner_only_line_is_owner_only_regardless_of_a_permissive_umask(
    tmp_path: Path,
) -> None:
    target = tmp_path / "events.jsonl"
    old_umask = os.umask(0o000)
    try:
        append_owner_only_line(target, "line")
    finally:
        os.umask(old_umask)
    assert stat.S_IMODE(target.stat().st_mode) == 0o600


def test_append_owner_only_line_tightens_permissions_on_a_pre_existing_looser_file(
    tmp_path: Path,
) -> None:
    target = tmp_path / "events.jsonl"
    target.write_text("")
    target.chmod(0o644)
    append_owner_only_line(target, "line")
    assert stat.S_IMODE(target.stat().st_mode) == 0o600
