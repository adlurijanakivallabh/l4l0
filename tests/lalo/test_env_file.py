"""Tests for the shared .env merge helper (extracted from lalo.setup so
lalo-setup and the GUI's settings endpoint share one tested implementation)."""

from __future__ import annotations

import stat
from pathlib import Path

from lalo.core.env_file import merge_env_file


def test_merge_env_file_creates_a_fresh_file(tmp_path: Path) -> None:
    path = tmp_path / ".env"
    merge_env_file(path, {"ANTHROPIC_API_KEY": "sk-ant-abc"})
    assert path.read_text(encoding="utf-8") == "ANTHROPIC_API_KEY=sk-ant-abc\n"


def test_merge_env_file_is_owner_only(tmp_path: Path) -> None:
    path = tmp_path / ".env"
    merge_env_file(path, {"ANTHROPIC_API_KEY": "sk-ant-abc"})
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_merge_env_file_preserves_unrelated_existing_lines(tmp_path: Path) -> None:
    path = tmp_path / ".env"
    path.write_text("SOME_OTHER_VAR=unrelated\n# a comment\n", encoding="utf-8")
    merge_env_file(path, {"ANTHROPIC_API_KEY": "sk-ant-abc"})
    content = path.read_text(encoding="utf-8")
    assert "SOME_OTHER_VAR=unrelated" in content
    assert "ANTHROPIC_API_KEY=sk-ant-abc" in content


def test_merge_env_file_replaces_a_matching_key_in_place(tmp_path: Path) -> None:
    path = tmp_path / ".env"
    path.write_text("ANTHROPIC_API_KEY=old\nOTHER=kept\n", encoding="utf-8")
    merge_env_file(path, {"ANTHROPIC_API_KEY": "sk-ant-new"})
    assert path.read_text(encoding="utf-8").splitlines() == [
        "ANTHROPIC_API_KEY=sk-ant-new",
        "OTHER=kept",
    ]
