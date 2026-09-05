"""Tests for the prompt registry (roles, overrides, injection framing)."""

from __future__ import annotations

from lalo.prompts import PromptRegistry, mission_text


def test_builtin_roles_render_with_mission_and_untrusted_framing() -> None:
    reg = PromptRegistry()
    out = reg.render("scorer", "test https://app.example.com")
    assert "test https://app.example.com" in out
    assert "UNTRUSTED DATA" in out  # OWASP LLM01 framing present
    assert set(reg.roles()) >= {"explorer", "coordinator", "scorer", "exploit"}


def test_valid_override_replaces_builtin(tmp_path) -> None:
    (tmp_path / "scorer.txt").write_text("CUSTOM scorer for {mission}")
    reg = PromptRegistry(override_dir=tmp_path)
    assert reg.render("scorer", "M").startswith("CUSTOM scorer for M")


def test_invalid_override_falls_back_to_builtin(tmp_path) -> None:
    # Missing the required {mission} placeholder -> rejected.
    (tmp_path / "exploit.txt").write_text("this override has no placeholder")
    reg = PromptRegistry(override_dir=tmp_path)
    rendered = reg.render("exploit", "M")
    assert "M" in rendered
    assert "no placeholder" not in rendered  # built-in used instead


def test_mission_text() -> None:
    assert "a.example.com, b.example.com" in mission_text(["a.example.com", "b.example.com"], "go")
