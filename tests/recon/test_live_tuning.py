"""Hermetic tests for live-reasoning recon tuning — proposal-only, allowlist-gated.

No live Anthropic API is ever hit: every test injects a mock ``ReconTunerClient``
or patches ``AnthropicTunerClient``. Valid allowlisted proposals are returned
verbatim; outside-allowlist proposals, errors and timeouts fall back to the safe
default and log why.
"""

from __future__ import annotations

import logging
import os
from unittest.mock import Mock, patch

from reachagent.recon.live_tuning import (
    _SAFE_DEFAULT_FLAGS,
    _SAFE_DEFAULT_STATUS,
    _SAFE_DEFAULT_WORDLIST,
    RECON_ALLOWLIST,
    ReconTuningChoice,
    RunConfig,
    propose_recon_tuning,
)

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _fake_client(returning: dict[str, str]) -> Mock:
    m = Mock()
    m.propose.return_value = returning
    return m  # type: ignore[no-any-return]


def _allowlisted_raw(
    *,
    wordlist_idx: int = 0,
    flag_idx: int = 1,
    status_idx: int = 0,
) -> dict[str, str]:
    wl = RECON_ALLOWLIST["wordlists"][wordlist_idx]  # type: ignore[index]
    flags = RECON_ALLOWLIST["flag_presets"][flag_idx]  # type: ignore[index]
    code = RECON_ALLOWLIST["status_codes"][status_idx]  # type: ignore[index]
    return {
        "wordlist_path": str(wl),
        "flags": " ".join(flags),  # type: ignore[arg-type]
        "filter_codes": str(code),
    }


# ---------------------------------------------------------------------------
# valid allowlisted -> returns that choice
# ---------------------------------------------------------------------------


def test_propose_mocked_valid_allowlisted_returns_that_choice() -> None:
    raw = _allowlisted_raw(wordlist_idx=0, flag_idx=1, status_idx=0)
    choice = propose_recon_tuning({"target": "http://example.com"}, client=_fake_client(raw))
    assert choice.wordlist_path == raw["wordlist_path"]
    assert choice.flags == tuple(raw["flags"].split())
    assert choice.filter_codes == raw["filter_codes"]
    assert isinstance(choice, ReconTuningChoice)


def test_propose_mocked_valid_empty_flags_returns_empty_tuple() -> None:
    raw = _allowlisted_raw(wordlist_idx=0, flag_idx=0, status_idx=0)
    assert raw["flags"] == ""
    choice = propose_recon_tuning({"target": "http://example.com"}, client=_fake_client(raw))
    assert choice.flags == ()
    assert choice.wordlist_path == raw["wordlist_path"]


def test_propose_mocked_valid_each_flag_preset() -> None:
    for idx, preset in enumerate(RECON_ALLOWLIST["flag_presets"]):  # type: ignore[attr-defined]
        raw = _allowlisted_raw(wordlist_idx=0, flag_idx=idx, status_idx=0)
        choice = propose_recon_tuning({"target": "http://example.com"}, client=_fake_client(raw))
        assert choice.flags == tuple(preset)  # type: ignore[arg-type]


def test_propose_mocked_valid_each_wordlist() -> None:
    for idx in range(len(RECON_ALLOWLIST["wordlists"])):  # type: ignore[arg-type]
        raw = _allowlisted_raw(wordlist_idx=idx, flag_idx=0, status_idx=0)
        choice = propose_recon_tuning({"target": "http://example.com"}, client=_fake_client(raw))
        assert choice.wordlist_path == raw["wordlist_path"]


def test_propose_mocked_valid_each_status_code() -> None:
    for idx in range(len(RECON_ALLOWLIST["status_codes"])):  # type: ignore[arg-type]
        raw = _allowlisted_raw(wordlist_idx=0, flag_idx=0, status_idx=idx)
        choice = propose_recon_tuning({"target": "http://example.com"}, client=_fake_client(raw))
        assert choice.filter_codes == raw["filter_codes"]


def test_runconfig_alias_is_recontuningchoice() -> None:
    # prompt name ``RunConfig`` is kept as subclass alias; a RunConfig is a ReconTuningChoice
    assert issubclass(RunConfig, ReconTuningChoice)
    rc = RunConfig(
        wordlist_path=str(RECON_ALLOWLIST["wordlists"][0]),  # type: ignore[index]
        flags=(),
        filter_codes=str(RECON_ALLOWLIST["status_codes"][0]),  # type: ignore[index]
    )
    assert isinstance(rc, ReconTuningChoice)
    # propose returns the base type, which validates against the same allowlist
    raw = _allowlisted_raw()
    choice = propose_recon_tuning({"target": "http://example.com"}, client=_fake_client(raw))
    assert isinstance(choice, ReconTuningChoice)


# ---------------------------------------------------------------------------
# outside allowlist -> fallback safe default, logs why
# ---------------------------------------------------------------------------


def test_propose_wordlist_outside_allowlist_fallback_safe_default(caplog) -> None:
    raw = {
        "wordlist_path": "/tmp/evil.txt",  # noqa: S108
        "flags": "",
        "filter_codes": str(RECON_ALLOWLIST["status_codes"][0]),  # type: ignore[index]
    }
    with caplog.at_level(logging.WARNING):
        choice = propose_recon_tuning({"target": "http://example.com"}, client=_fake_client(raw))
    assert choice.wordlist_path == _SAFE_DEFAULT_WORDLIST
    assert choice.flags == _SAFE_DEFAULT_FLAGS
    assert choice.filter_codes == _SAFE_DEFAULT_STATUS
    assert choice.wordlist_path != "/tmp/evil.txt"  # noqa: S108
    assert any("not allowlisted" in r.message for r in caplog.records)


def test_propose_flags_outside_allowlist_fallback_safe_default(caplog) -> None:
    allowed_wl = str(RECON_ALLOWLIST["wordlists"][0])  # type: ignore[index]
    allowed_code = str(RECON_ALLOWLIST["status_codes"][0])  # type: ignore[index]
    raw = {"wordlist_path": allowed_wl, "flags": "--evil-flag", "filter_codes": allowed_code}
    with caplog.at_level(logging.WARNING):
        choice = propose_recon_tuning({"target": "http://example.com"}, client=_fake_client(raw))
    assert choice == ReconTuningChoice(
        wordlist_path=_SAFE_DEFAULT_WORDLIST,
        flags=_SAFE_DEFAULT_FLAGS,
        filter_codes=_SAFE_DEFAULT_STATUS,
    )
    assert any("not allowlisted" in r.message for r in caplog.records)


def test_propose_status_outside_allowlist_fallback_safe_default(caplog) -> None:
    allowed_wl = str(RECON_ALLOWLIST["wordlists"][0])  # type: ignore[index]
    raw = {"wordlist_path": allowed_wl, "flags": "", "filter_codes": "999"}
    with caplog.at_level(logging.WARNING):
        choice = propose_recon_tuning({"target": "http://example.com"}, client=_fake_client(raw))
    assert choice.filter_codes == _SAFE_DEFAULT_STATUS
    assert choice.wordlist_path == _SAFE_DEFAULT_WORDLIST
    assert any("not allowlisted" in r.message for r in caplog.records)


def test_propose_all_fields_outside_allowlist_fallback() -> None:
    raw = {"wordlist_path": "/tmp/evil.txt", "flags": "-t 999", "filter_codes": "evil"}  # noqa: S108
    choice = propose_recon_tuning({"target": "http://example.com"}, client=_fake_client(raw))
    assert choice.wordlist_path == _SAFE_DEFAULT_WORDLIST
    assert choice.wordlist_path != "/tmp/evil.txt"  # noqa: S108


def test_propose_empty_wordlist_fallback() -> None:
    raw = {"wordlist_path": "", "flags": "", "filter_codes": "200,204,301,302,307,401,403"}
    choice = propose_recon_tuning({"target": "http://example.com"}, client=_fake_client(raw))
    assert choice.wordlist_path == _SAFE_DEFAULT_WORDLIST


def test_propose_injection_path_outside_allowlist_fallback() -> None:
    raw = {
        "wordlist_path": "/usr/share/wordlists/dirb/common.txt; rm -rf /",
        "flags": "",
        "filter_codes": str(RECON_ALLOWLIST["status_codes"][0]),  # type: ignore[index]
    }
    choice = propose_recon_tuning({"target": "http://example.com"}, client=_fake_client(raw))
    assert choice.wordlist_path == _SAFE_DEFAULT_WORDLIST


# ---------------------------------------------------------------------------
# error / timeout -> fallback cleanly, never raises
# ---------------------------------------------------------------------------


def test_propose_mocked_error_fallback_safe_default(caplog) -> None:
    m = Mock()
    m.propose.side_effect = RuntimeError("timeout")
    with caplog.at_level(logging.WARNING):
        choice = propose_recon_tuning({"target": "http://example.com"}, client=m)
    assert choice.wordlist_path == _SAFE_DEFAULT_WORDLIST
    assert isinstance(choice, ReconTuningChoice)
    assert any("fallback" in r.message.lower() for r in caplog.records)


def test_propose_mocked_timeout_exception_fallback_cleanly() -> None:
    m = Mock()
    m.propose.side_effect = TimeoutError("anthropic timeout")
    choice = propose_recon_tuning({"target": "http://example.com"}, client=m)
    assert choice == ReconTuningChoice(
        wordlist_path=_SAFE_DEFAULT_WORDLIST,
        flags=_SAFE_DEFAULT_FLAGS,
        filter_codes=_SAFE_DEFAULT_STATUS,
    )


def test_propose_mocked_generic_exception_fallback_cleanly() -> None:
    m = Mock()
    m.propose.side_effect = ValueError("no JSON in model response")
    choice = propose_recon_tuning({"target": "http://example.com"}, client=m)
    assert choice.wordlist_path == _SAFE_DEFAULT_WORDLIST


def test_propose_no_api_key_fallback_when_client_is_none() -> None:
    # When client is None the default AnthropicTunerClient is built from env;
    # without ANTHROPIC_API_KEY it raises RuntimeError -> safe default.
    with patch.dict(os.environ, {}, clear=False):
        os.environ.pop("ANTHROPIC_API_KEY", None)
        choice = propose_recon_tuning({"target": "http://example.com"}, client=None)
    assert choice.wordlist_path == _SAFE_DEFAULT_WORDLIST
    assert choice.flags == _SAFE_DEFAULT_FLAGS


def test_propose_mocked_returns_missing_keys_fallback() -> None:
    m = Mock()
    m.propose.return_value = {}
    choice = propose_recon_tuning({"target": "http://example.com"}, client=m)
    assert choice.wordlist_path == _SAFE_DEFAULT_WORDLIST


# ---------------------------------------------------------------------------
# safe default is itself allowlisted (invariant)
# ---------------------------------------------------------------------------


def test_safe_default_is_allowlisted() -> None:
    assert _SAFE_DEFAULT_WORDLIST in RECON_ALLOWLIST["wordlists"]
    assert _SAFE_DEFAULT_FLAGS in RECON_ALLOWLIST["flag_presets"]  # type: ignore[operator]
    assert _SAFE_DEFAULT_STATUS in RECON_ALLOWLIST["status_codes"]


def test_validated_choice_round_trips_through_allowlist() -> None:
    raw = _allowlisted_raw(wordlist_idx=2, flag_idx=3, status_idx=1)
    choice = propose_recon_tuning({"target": "http://example.com"}, client=_fake_client(raw))
    assert choice.wordlist_path in RECON_ALLOWLIST["wordlists"]
    assert choice.flags in RECON_ALLOWLIST["flag_presets"]  # type: ignore[operator]
    assert choice.filter_codes in RECON_ALLOWLIST["status_codes"]
