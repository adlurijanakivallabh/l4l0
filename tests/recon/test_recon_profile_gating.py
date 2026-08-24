"""Hermetic: profile picker flag-gated — OFF zero regression, ON smart for 5 runners."""

from __future__ import annotations

import os
from unittest.mock import patch

from reachagent.execution.audit import AuditLog
from reachagent.graph.store import ReachabilityGraph
from reachagent.recon.live_tuning import RECON_PROFILES, ReconProfile
from reachagent.recon.tools.base import ScopeGuard
from reachagent.recon.tools.dirb import DirbRunner
from reachagent.recon.tools.feroxbuster import FeroxbusterRunner
from reachagent.recon.tools.ffuf import FfufRunner
from reachagent.recon.tools.gobuster import GobusterRunner
from reachagent.recon.tools.x8 import X8Runner


def _runner(cls):  # type: ignore[no-untyped-def]
    g = ReachabilityGraph()
    a = AuditLog()
    scope = ScopeGuard.from_hosts(["example.com"])
    return cls(graph=g, scope=scope, audit=a)  # type: ignore[call-arg]


def test_flag_off_zero_regression_all_runners() -> None:
    with patch.dict(os.environ, {}, clear=False):
        for k in (
            "REACHAGENT_RECON_PROFILE",
            "REACHAGENT_RECON_LIVE_TUNING",
            "REACHAGENT_GOBUSTER_LIVE_TUNING",
        ):
            os.environ.pop(k, None)
        for Cls in (GobusterRunner, FfufRunner, FeroxbusterRunner, DirbRunner, X8Runner):
            r = _runner(Cls)
            argv = r.command("http://example.com")
            # still contains binary name and target, not mocked profile wordlist
            assert argv[0] in ("gobuster", "ffuf", "feroxbuster", "dirb", "x8")
            assert "http://example.com" in argv or "http://example.com/FUZZ" in " ".join(argv)


def test_flag_on_gobuster_uses_profile_wordlist() -> None:
    profile = RECON_PROFILES["api_target"]
    with patch.dict(os.environ, {"REACHAGENT_RECON_PROFILE": "1"}, clear=False):
        with patch("reachagent.recon.live_tuning.propose_recon_profile", return_value=profile):
            r = _runner(GobusterRunner)
            argv = r.command("http://example.com/api")
    assert profile.wordlist in argv
    assert all(f in argv for f in profile.flags)


def test_flag_on_ffuf_uses_profile_status_codes() -> None:
    profile = RECON_PROFILES["cms_target"]
    with patch.dict(os.environ, {"REACHAGENT_RECON_PROFILE": "1"}, clear=False):
        with patch("reachagent.recon.live_tuning.propose_recon_profile", return_value=profile):
            r = _runner(FfufRunner)
            argv = r.command("http://example.com")
    assert profile.wordlist in argv
    assert profile.status_codes in argv


def test_flag_on_feroxbuster_uses_profile() -> None:
    profile = RECON_PROFILES["aggressive_recon"]
    with patch.dict(os.environ, {"REACHAGENT_RECON_PROFILE": "1"}, clear=False):
        with patch("reachagent.recon.live_tuning.propose_recon_profile", return_value=profile):
            r = _runner(FeroxbusterRunner)
            argv = r.command("http://example.com")
    assert profile.wordlist in argv
    assert "-t" in argv


def test_flag_on_dirb_uses_profile_wordlist() -> None:
    profile = RECON_PROFILES["quiet_recon"]
    with patch.dict(os.environ, {"REACHAGENT_RECON_PROFILE": "1"}, clear=False):
        with patch("reachagent.recon.live_tuning.propose_recon_profile", return_value=profile):
            r = _runner(DirbRunner)
            argv = r.command("http://example.com")
    assert profile.wordlist in argv


def test_flag_on_x8_honors_flags_not_wordlist() -> None:
    profile = RECON_PROFILES["api_target"]
    with patch.dict(os.environ, {"REACHAGENT_RECON_PROFILE": "1"}, clear=False):
        with patch("reachagent.recon.live_tuning.propose_recon_profile", return_value=profile):
            r = _runner(X8Runner)
            argv = r.command("http://example.com")
    # x8 keeps its param wordlist, but must contain profile flags
    for f in profile.flags:
        assert f in argv
    assert profile.wordlist not in argv  # dir wordlist not used for x8


def test_flag_on_via_recon_profile_spa() -> None:
    profile = RECON_PROFILES["spa_target"]
    with patch.dict(os.environ, {"REACHAGENT_RECON_PROFILE": "1"}, clear=False):
        with patch("reachagent.recon.live_tuning.propose_recon_profile", return_value=profile):
            r = _runner(GobusterRunner)
            argv = r.command("http://example.com")
    assert profile.wordlist in argv


def test_flag_on_proposer_error_fallback_original() -> None:
    with patch.dict(os.environ, {"REACHAGENT_RECON_PROFILE": "1"}, clear=False):
        with patch(
            "reachagent.recon.live_tuning.propose_recon_profile", side_effect=RuntimeError("boom")
        ):
            r = _runner(GobusterRunner)
            argv = r.command("http://example.com")
    # fallback still produces a valid gobuster argv with target
    assert "gobuster" in argv[0]
    assert "http://example.com" in argv


def test_profile_outside_allowlist_filtered_even_if_validated_bypass_attempt() -> None:
    # Evil profile not in RECON_PROFILES.values() — defense in depth second check.
    evil = ReconProfile(
        wordlist="/evil.txt",  # noqa: S108 — test fixture, not a real tmp use
        flags=(),
        status_codes="200,204,301,302,307",
        tools=("gobuster",),
    )
    with patch.dict(os.environ, {"REACHAGENT_RECON_PROFILE": "1"}, clear=False):
        with patch("reachagent.recon.live_tuning.propose_recon_profile", return_value=evil):
            r = _runner(GobusterRunner)
            argv = r.command("http://example.com")
    assert "/evil.txt" not in argv  # filtered, fallback to safe default path
