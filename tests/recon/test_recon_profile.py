"""Hermetic tests for recon profile picker — LLM picks ONE named profile, allowlist-validated."""

from __future__ import annotations

import logging
import os
from unittest.mock import Mock, patch

from reachagent.recon.live_tuning import (
    _SAFE_DEFAULT_PROFILE,
    RECON_ALLOWLIST,
    RECON_PROFILES,
    ReconProfile,
    propose_recon_profile,
)


def _fake_client(returning: dict[str, str]) -> Mock:
    m = Mock()
    m.propose.return_value = returning
    return m  # type: ignore[no-any-return]


def test_valid_profile_returns_that_profile() -> None:
    for name, profile in RECON_PROFILES.items():
        choice = propose_recon_profile(
            {"target": "http://example.com/api"}, client=_fake_client({"profile_name": name})
        )
        assert choice is profile
        assert choice.wordlist in RECON_ALLOWLIST["wordlists"]
        assert choice.flags in RECON_ALLOWLIST["flag_presets"]  # type: ignore[operator]
        assert choice.status_codes in RECON_ALLOWLIST["status_codes"]


def test_outside_allowlist_fallback_safe_default(caplog) -> None:
    with caplog.at_level(logging.WARNING):
        choice = propose_recon_profile(
            {"target": "http://example.com"}, client=_fake_client({"profile_name": "evil_profile"})
        )
    assert choice is RECON_PROFILES[_SAFE_DEFAULT_PROFILE]
    assert any("not allowlisted" in r.message for r in caplog.records)


def test_empty_name_fallback(caplog) -> None:
    with caplog.at_level(logging.WARNING):
        choice = propose_recon_profile(
            {"target": "http://example.com"}, client=_fake_client({"profile_name": ""})
        )
    assert choice is RECON_PROFILES[_SAFE_DEFAULT_PROFILE]


def test_missing_key_fallback() -> None:
    m = Mock()
    m.propose.return_value = {}
    choice = propose_recon_profile({"target": "http://example.com"}, client=m)
    assert choice is RECON_PROFILES[_SAFE_DEFAULT_PROFILE]


def test_error_fallback_cleanly(caplog) -> None:
    m = Mock()
    m.propose.side_effect = RuntimeError("timeout")
    with caplog.at_level(logging.WARNING):
        choice = propose_recon_profile({"target": "http://example.com"}, client=m)
    assert choice is RECON_PROFILES[_SAFE_DEFAULT_PROFILE]
    assert isinstance(choice, ReconProfile)


def test_timeout_fallback(caplog) -> None:
    m = Mock()
    m.propose.side_effect = TimeoutError("deadline")
    choice = propose_recon_profile({"target": "http://example.com"}, client=m)
    assert choice is RECON_PROFILES[_SAFE_DEFAULT_PROFILE]


def test_no_api_key_fallback_when_client_none() -> None:
    with patch.dict(os.environ, {}, clear=False):
        os.environ.pop("ANTHROPIC_API_KEY", None)
        choice = propose_recon_profile({"target": "http://example.com"}, client=None)
    assert choice is RECON_PROFILES[_SAFE_DEFAULT_PROFILE]


def test_injection_name_outside_fallback() -> None:
    choice = propose_recon_profile(
        {"target": "http://example.com"},
        client=_fake_client({"profile_name": "api_target; rm -rf /"}),
    )
    assert choice is RECON_PROFILES[_SAFE_DEFAULT_PROFILE]


def test_all_profiles_allowlisted_fields() -> None:
    for name, p in RECON_PROFILES.items():
        assert p.wordlist in RECON_ALLOWLIST["wordlists"], name
        assert p.flags in RECON_ALLOWLIST["flag_presets"], name  # type: ignore[operator]
        assert p.status_codes in RECON_ALLOWLIST["status_codes"], name


def test_safe_default_profile_is_allowlisted() -> None:
    assert _SAFE_DEFAULT_PROFILE in RECON_PROFILES
    p = RECON_PROFILES[_SAFE_DEFAULT_PROFILE]
    assert p.wordlist in RECON_ALLOWLIST["wordlists"]
