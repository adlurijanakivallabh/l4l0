"""Tests for lalo-setup: the interactive provider-credential wizard."""

from __future__ import annotations

import stat
from pathlib import Path

import pytest

import lalo.setup as lalo_setup
from lalo.core.config import CURATED_PROVIDERS
from lalo.setup import _collect_env, _merge_env_file, _prompt_provider, main


def test_prompt_provider_accepts_a_valid_choice(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("builtins.input", lambda _prompt="": "2")
    spec = _prompt_provider()
    assert spec is CURATED_PROVIDERS[1]


def test_prompt_provider_rejects_a_non_numeric_choice(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("builtins.input", lambda _prompt="": "anthropic")
    with pytest.raises(ValueError, match="not a valid choice"):
        _prompt_provider()


def test_prompt_provider_rejects_an_out_of_range_choice(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("builtins.input", lambda _prompt="": str(len(CURATED_PROVIDERS) + 1))
    with pytest.raises(ValueError, match="not a valid choice"):
        _prompt_provider()


def test_collect_env_returns_the_api_key_for_a_provider_with_no_extras(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    anthropic = next(s for s in CURATED_PROVIDERS if s.id == "anthropic")
    monkeypatch.setattr(lalo_setup.getpass, "getpass", lambda _prompt="": "sk-ant-real-key")
    env = _collect_env(anthropic)
    assert env == {"ANTHROPIC_API_KEY": "sk-ant-real-key"}


def test_collect_env_rejects_an_empty_api_key(monkeypatch: pytest.MonkeyPatch) -> None:
    anthropic = next(s for s in CURATED_PROVIDERS if s.id == "anthropic")
    monkeypatch.setattr(lalo_setup.getpass, "getpass", lambda _prompt="": "   ")
    with pytest.raises(ValueError, match="empty API key"):
        _collect_env(anthropic)


def test_collect_env_prompts_for_every_extra_required_env(monkeypatch: pytest.MonkeyPatch) -> None:
    custom = next(s for s in CURATED_PROVIDERS if s.id == "custom")
    monkeypatch.setattr(lalo_setup.getpass, "getpass", lambda _prompt="": "sk-custom")
    answers = iter(["https://gateway.example.com", "some-model"])
    monkeypatch.setattr("builtins.input", lambda _prompt="": next(answers))
    env = _collect_env(custom)
    assert env == {
        "LALO_CUSTOM_API_KEY": "sk-custom",
        "LALO_CUSTOM_BASE_URL": "https://gateway.example.com",
        "LALO_CUSTOM_MODEL": "some-model",
    }


def test_collect_env_rejects_an_empty_extra_required_env(monkeypatch: pytest.MonkeyPatch) -> None:
    custom = next(s for s in CURATED_PROVIDERS if s.id == "custom")
    monkeypatch.setattr(lalo_setup.getpass, "getpass", lambda _prompt="": "sk-custom")
    monkeypatch.setattr("builtins.input", lambda _prompt="": "   ")
    with pytest.raises(ValueError, match="LALO_CUSTOM_BASE_URL"):
        _collect_env(custom)


def test_merge_env_file_creates_a_fresh_file(tmp_path: Path) -> None:
    path = tmp_path / ".env"
    _merge_env_file(path, {"ANTHROPIC_API_KEY": "sk-ant-abc"})
    assert path.read_text(encoding="utf-8") == "ANTHROPIC_API_KEY=sk-ant-abc\n"


def test_merge_env_file_is_owner_only(tmp_path: Path) -> None:
    path = tmp_path / ".env"
    _merge_env_file(path, {"ANTHROPIC_API_KEY": "sk-ant-abc"})
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_merge_env_file_preserves_unrelated_existing_lines(tmp_path: Path) -> None:
    path = tmp_path / ".env"
    path.write_text("SOME_OTHER_VAR=unrelated\n# a comment\n", encoding="utf-8")
    _merge_env_file(path, {"ANTHROPIC_API_KEY": "sk-ant-abc"})
    content = path.read_text(encoding="utf-8")
    assert "SOME_OTHER_VAR=unrelated" in content
    assert "# a comment" in content
    assert "ANTHROPIC_API_KEY=sk-ant-abc" in content


def test_merge_env_file_replaces_a_matching_key_in_place(tmp_path: Path) -> None:
    path = tmp_path / ".env"
    path.write_text("ANTHROPIC_API_KEY=old-stale-key\nOTHER=kept\n", encoding="utf-8")
    _merge_env_file(path, {"ANTHROPIC_API_KEY": "sk-ant-new"})
    lines = path.read_text(encoding="utf-8").splitlines()
    assert lines == ["ANTHROPIC_API_KEY=sk-ant-new", "OTHER=kept"]


def test_main_writes_the_env_file_on_a_successful_verification(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    env_path = tmp_path / ".env"
    monkeypatch.setattr(lalo_setup, "_ENV_PATH", env_path)
    monkeypatch.setattr("builtins.input", lambda _prompt="": "2")  # anthropic
    monkeypatch.setattr(lalo_setup.getpass, "getpass", lambda _prompt="": "sk-ant-real-key")
    monkeypatch.setattr(lalo_setup, "build_router", lambda _settings: object())
    monkeypatch.setattr(lalo_setup, "verify_router", lambda _router: {"anthropic": (True, "ok")})

    main()

    assert env_path.exists()
    assert "ANTHROPIC_API_KEY=sk-ant-real-key" in env_path.read_text(encoding="utf-8")


def test_main_writes_nothing_when_verification_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    env_path = tmp_path / ".env"
    monkeypatch.setattr(lalo_setup, "_ENV_PATH", env_path)
    monkeypatch.setattr("builtins.input", lambda _prompt="": "2")  # anthropic
    monkeypatch.setattr(lalo_setup.getpass, "getpass", lambda _prompt="": "sk-ant-bad-key")
    monkeypatch.setattr(lalo_setup, "build_router", lambda _settings: object())
    monkeypatch.setattr(
        lalo_setup, "verify_router", lambda _router: {"anthropic": (False, "401 unauthorized")}
    )

    with pytest.raises(SystemExit):
        main()

    assert not env_path.exists()


def test_main_exits_cleanly_on_an_invalid_choice(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    env_path = tmp_path / ".env"
    monkeypatch.setattr(lalo_setup, "_ENV_PATH", env_path)
    monkeypatch.setattr("builtins.input", lambda _prompt="": "not-a-number")

    with pytest.raises(SystemExit):
        main()

    assert not env_path.exists()
