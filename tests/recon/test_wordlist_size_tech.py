"""preferred_wordlist size/tech dimensions (v3 V2 follow-up).

Hermetic (no network): only checks resolution logic against real on-disk
paths, never fabricates wordlist content. Skips assertions that depend on a
specific file existing when this environment doesn't have it, so the suite
stays honest across machines with a partial SecLists install.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from reachagent.recon.tools._wordlist import preferred_wordlist

_RAFT_SMALL = "/usr/share/seclists/Discovery/Web-Content/raft-small-directories.txt"
_RAFT_LARGE = "/usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt"
_WORDPRESS = "/usr/share/seclists/Discovery/Web-Content/CMS/wordpress.fuzz.txt"


def test_explicit_env_var_always_wins_over_size_or_tech(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("REACHAGENT_GOBUSTER_WORDLIST", "/tmp/explicit.txt")  # noqa: S108
    monkeypatch.setenv("REACHAGENT_WORDLIST_SIZE", "large")
    monkeypatch.setenv("REACHAGENT_WORDLIST_TECH", "wordpress")
    assert preferred_wordlist("REACHAGENT_GOBUSTER_WORDLIST") == "/tmp/explicit.txt"  # noqa: S108


def test_unset_size_matches_todays_exact_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("REACHAGENT_GOBUSTER_WORDLIST", raising=False)
    monkeypatch.delenv("REACHAGENT_WORDLIST_SIZE", raising=False)
    monkeypatch.delenv("REACHAGENT_WORDLIST_TECH", raising=False)
    with_default = preferred_wordlist("REACHAGENT_GOBUSTER_WORDLIST")
    monkeypatch.setenv("REACHAGENT_WORDLIST_SIZE", "medium")
    with_explicit_medium = preferred_wordlist("REACHAGENT_GOBUSTER_WORDLIST")
    assert with_default == with_explicit_medium


@pytest.mark.skipif(not Path(_RAFT_SMALL).exists(), reason="raft-small not installed here")
def test_small_size_resolves_to_the_small_list(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("REACHAGENT_GOBUSTER_WORDLIST", raising=False)
    monkeypatch.setenv("REACHAGENT_WORDLIST_SIZE", "small")
    assert preferred_wordlist("REACHAGENT_GOBUSTER_WORDLIST") == _RAFT_SMALL


@pytest.mark.skipif(not Path(_RAFT_LARGE).exists(), reason="raft-large not installed here")
def test_large_size_resolves_to_the_large_list(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("REACHAGENT_GOBUSTER_WORDLIST", raising=False)
    monkeypatch.setenv("REACHAGENT_WORDLIST_SIZE", "large")
    assert preferred_wordlist("REACHAGENT_GOBUSTER_WORDLIST") == _RAFT_LARGE


@pytest.mark.skipif(not Path(_WORDPRESS).exists(), reason="wordpress.fuzz.txt not installed here")
def test_tech_hint_wins_over_size(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("REACHAGENT_GOBUSTER_WORDLIST", raising=False)
    monkeypatch.setenv("REACHAGENT_WORDLIST_SIZE", "large")
    monkeypatch.setenv("REACHAGENT_WORDLIST_TECH", "wordpress")
    assert preferred_wordlist("REACHAGENT_GOBUSTER_WORDLIST") == _WORDPRESS


def test_unrecognized_tech_hint_is_ignored_not_an_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("REACHAGENT_GOBUSTER_WORDLIST", raising=False)
    monkeypatch.delenv("REACHAGENT_WORDLIST_SIZE", raising=False)
    monkeypatch.setenv("REACHAGENT_WORDLIST_TECH", "some-made-up-framework")
    # Falls through to the normal size-tier resolution, never raises.
    assert preferred_wordlist("REACHAGENT_GOBUSTER_WORDLIST").endswith(".txt")


def test_size_and_tech_never_apply_to_x8_or_dns_purpose(monkeypatch: pytest.MonkeyPatch) -> None:
    """The size/tech dimensions are directory-purpose only — x8's param list
    and DNS subdomain lists must stay exactly as before, unaffected."""
    monkeypatch.delenv("REACHAGENT_X8_WORDLIST", raising=False)
    monkeypatch.setenv("REACHAGENT_WORDLIST_SIZE", "large")
    monkeypatch.setenv("REACHAGENT_WORDLIST_TECH", "wordpress")
    x8_result = preferred_wordlist("REACHAGENT_X8_WORDLIST", x8=True)
    assert x8_result != _WORDPRESS
    assert "large" not in x8_result
