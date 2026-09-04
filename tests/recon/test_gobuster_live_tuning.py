"""Gobuster live-tuning, no flag gate (v4 R3) — hermetic, no live API.

No provider configured is zero-regression: ``GobusterRunner.command``
behaves exactly as with the flag off before (NO_LIVE_TUNING_CHOICE is
recognized as "no genuine choice" and never overrides the operator's own
env config). A mocked allowlisted choice is used and still writes ONLY
facts (Host/Endpoint + resolves_to) — zero Findings, zero candidates, zero
can_call.
"""

from __future__ import annotations

import os
from unittest.mock import Mock, patch

from reachagent.execution.audit import AuditLog
from reachagent.execution.scope import ScopeGuard
from reachagent.graph.store import ReachabilityGraph
from reachagent.recon.live_tuning import RECON_ALLOWLIST, ReconTuningChoice
from reachagent.recon.tools.gobuster import GobusterRunner

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _runner() -> GobusterRunner:
    g = ReachabilityGraph()
    scope = ScopeGuard.from_hosts(["example.com"])
    a = AuditLog()
    return GobusterRunner(graph=g, scope=scope, audit=a)


def _allowlisted_choice(
    *,
    wordlist_idx: int = 0,
    flag_idx: int = 0,
    status_idx: int = 0,
) -> ReconTuningChoice:
    wl = RECON_ALLOWLIST["wordlists"][wordlist_idx]  # type: ignore[index]
    flags = RECON_ALLOWLIST["flag_presets"][flag_idx]  # type: ignore[index]
    code = RECON_ALLOWLIST["status_codes"][status_idx]  # type: ignore[index]
    return ReconTuningChoice(
        wordlist_path=str(wl),
        flags=tuple(flags),  # type: ignore[arg-type]
        filter_codes=str(code),
    )


# ---------------------------------------------------------------------------
# flag OFF — zero regression (most important)
# ---------------------------------------------------------------------------


def test_flag_off_zero_regression_default_argv() -> None:
    r = _runner()
    with patch.dict(os.environ, {}, clear=False):
        os.environ.pop("REACHAGENT_GOBUSTER_LIVE_TUNING", None)
        os.environ.pop("REACHAGENT_RECON_LIVE_TUNING", None)
        os.environ.pop("REACHAGENT_GOBUSTER_WORDLIST", None)
        os.environ.pop("REACHAGENT_GOBUSTER_THREADS", None)
        os.environ.pop("REACHAGENT_GOBUSTER_TIMEOUT", None)
        argv = r.command("http://example.com")
    assert argv[:5] == ["gobuster", "dir", "-q", "-u", "http://example.com"]
    assert "-w" in argv
    # stock preferred_wordlist fallback — still present, not live-tuned
    assert any("dirb/common.txt" in p or "seclists" in p or "raft" in p for p in argv)


def test_no_provider_still_calls_live_tuning_but_result_is_a_safe_no_op() -> None:
    """v4 R3: no flag gate — propose_recon_tuning IS called (no provider
    configured, so it returns NO_LIVE_TUNING_CHOICE), but gobuster recognizes
    that sentinel as "no genuine choice" and falls through to its own
    env-respecting default, same argv as the old flag-off path."""
    r = _runner()
    with patch.dict(os.environ, {}, clear=False):
        os.environ.pop("REACHAGENT_GOBUSTER_LIVE_TUNING", None)
        os.environ.pop("REACHAGENT_RECON_LIVE_TUNING", None)
        argv = r.command("http://example.com")
    assert argv[:5] == ["gobuster", "dir", "-q", "-u", "http://example.com"]
    assert "-w" in argv


def test_flag_off_respects_explicit_wordlist_env() -> None:
    r = _runner()
    with patch.dict(
        os.environ,
        {"REACHAGENT_GOBUSTER_WORDLIST": "/tmp/custom.txt"},  # noqa: S108
        clear=False,
    ):
        os.environ.pop("REACHAGENT_GOBUSTER_LIVE_TUNING", None)
        os.environ.pop("REACHAGENT_RECON_LIVE_TUNING", None)
        argv = r.command("http://example.com")
    assert "/tmp/custom.txt" in argv  # noqa: S108


def test_flag_off_respects_threads_and_timeout_env() -> None:
    r = _runner()
    with patch.dict(
        os.environ,
        {"REACHAGENT_GOBUSTER_THREADS": "25", "REACHAGENT_GOBUSTER_TIMEOUT": "7"},
        clear=False,
    ):
        os.environ.pop("REACHAGENT_GOBUSTER_LIVE_TUNING", None)
        os.environ.pop("REACHAGENT_RECON_LIVE_TUNING", None)
        argv = r.command("http://example.com")
    assert "-t" in argv
    assert "25" in argv
    assert "--timeout" in argv
    assert "7s" in argv


def test_flag_off_ignores_non_digit_threads() -> None:
    r = _runner()
    with patch.dict(os.environ, {"REACHAGENT_GOBUSTER_THREADS": "bad"}, clear=False):
        os.environ.pop("REACHAGENT_GOBUSTER_LIVE_TUNING", None)
        os.environ.pop("REACHAGENT_RECON_LIVE_TUNING", None)
        argv = r.command("http://example.com")
    # non-digit is ignored — no -t injected beyond base
    assert argv.count("-t") == 0


# ---------------------------------------------------------------------------
# flag ON mocked → uses chosen wordlist/flags
# ---------------------------------------------------------------------------


def test_flag_on_uses_chosen_wordlist_and_flags() -> None:
    r = _runner()
    chosen = _allowlisted_choice(wordlist_idx=4, flag_idx=1, status_idx=0)
    with patch("reachagent.llm.client.build_openai_compatible_client", return_value=object()):
        with (
            patch(
                "reachagent.recon.tools.gobuster._collect_signals",
                return_value={"target": "http://example.com"},
            ),
            patch("reachagent.recon.live_tuning.propose_recon_tuning", return_value=chosen),
        ):
            argv = r.command("http://example.com")
    assert chosen.wordlist_path in argv
    assert "-t" in argv
    assert "20" in argv


def test_flag_on_empty_flag_preset_no_extra_flags() -> None:
    r = _runner()
    chosen = _allowlisted_choice(wordlist_idx=0, flag_idx=0, status_idx=0)
    assert chosen.flags == ()
    with patch.dict(os.environ, {"REACHAGENT_GOBUSTER_LIVE_TUNING": "1"}, clear=False):
        with (
            patch(
                "reachagent.recon.tools.gobuster._collect_signals",
                return_value={"target": "http://example.com"},
            ),
            patch("reachagent.recon.live_tuning.propose_recon_tuning", return_value=chosen),
        ):
            argv = r.command("http://example.com")
    assert chosen.wordlist_path in argv
    # no flag injection beyond base gobuster dir -q -u target -w wordlist
    assert argv == ["gobuster", "dir", "-q", "-u", "http://example.com", "-w", chosen.wordlist_path]


def test_flag_on_via_alternate_env_var() -> None:
    r = _runner()
    chosen = _allowlisted_choice(wordlist_idx=1, flag_idx=2, status_idx=0)
    with patch("reachagent.llm.client.build_openai_compatible_client", return_value=object()):
        with (
            patch(
                "reachagent.recon.tools.gobuster._collect_signals",
                return_value={"target": "http://example.com"},
            ),
            patch("reachagent.recon.live_tuning.propose_recon_tuning", return_value=chosen),
        ):
            argv = r.command("http://example.com")
    assert chosen.wordlist_path in argv
    assert "-t" in argv
    assert "50" in argv


def test_flag_on_still_writes_only_facts_no_findings() -> None:
    g = ReachabilityGraph()
    scope = ScopeGuard.from_hosts(["example.com"])
    a = AuditLog()
    r = GobusterRunner(graph=g, scope=scope, audit=a)
    chosen = _allowlisted_choice(wordlist_idx=0, flag_idx=0, status_idx=0)
    with patch.dict(os.environ, {"REACHAGENT_GOBUSTER_LIVE_TUNING": "1"}, clear=False):
        with (
            patch(
                "reachagent.recon.tools.gobuster._collect_signals",
                return_value={"target": "http://example.com"},
            ),
            patch("reachagent.recon.live_tuning.propose_recon_tuning", return_value=chosen),
        ):
            argv = r.command("http://example.com")
            assert "-w" in argv
        r.ingest(
            "http://example.com",
            "/admin                (Status: 200)\n/login                (Status: 403)\n",
        )
    assert len(list(g.hosts())) == 1
    assert len(list(g.endpoints())) == 2
    assert len(list(g.findings())) == 0
    assert len(g.can_call_edges()) == 0
    eps = {ep.path: ep for _, ep in g.endpoints()}
    assert eps["/admin"].access_restricted is None
    assert eps["/login"].access_restricted == "403"
    # resolves_to edges only, no can_call
    assert len(g.resolves_to_edges()) == 2


def test_flag_on_403_still_fact_not_candidate() -> None:
    g = ReachabilityGraph()
    scope = ScopeGuard.from_hosts(["example.com"])
    a = AuditLog()
    r = GobusterRunner(graph=g, scope=scope, audit=a)
    chosen = _allowlisted_choice(wordlist_idx=0, flag_idx=0, status_idx=0)
    with patch.dict(os.environ, {"REACHAGENT_GOBUSTER_LIVE_TUNING": "1"}, clear=False):
        with (
            patch(
                "reachagent.recon.tools.gobuster._collect_signals",
                return_value={"target": "http://example.com"},
            ),
            patch("reachagent.recon.live_tuning.propose_recon_tuning", return_value=chosen),
        ):
            r.command("http://example.com")
        r.ingest("http://example.com", "/secret                (Status: 401)\n")
    assert len(list(g.findings())) == 0
    assert len(g.can_call_edges()) == 0
    eps = {ep.path: ep for _, ep in g.endpoints()}
    assert eps["/secret"].access_restricted == "401"


def test_flag_on_outside_allowlist_fallback_still_safe() -> None:
    r = _runner()
    evil = ReconTuningChoice(
        wordlist_path="/tmp/evil.txt",  # noqa: S108
        flags=("--evil",),
        filter_codes="evil",
    )
    with patch.dict(os.environ, {"REACHAGENT_GOBUSTER_LIVE_TUNING": "1"}, clear=False):
        with (
            patch(
                "reachagent.recon.tools.gobuster._collect_signals",
                return_value={"target": "http://example.com"},
            ),
            patch("reachagent.recon.live_tuning.propose_recon_tuning", return_value=evil),
        ):
            argv = r.command("http://example.com")
    assert "/tmp/evil.txt" not in argv  # noqa: S108
    assert "--evil" not in argv
    assert argv[:5] == ["gobuster", "dir", "-q", "-u", "http://example.com"]


def test_flag_on_propose_error_fallback_cleanly() -> None:
    r = _runner()
    with patch.dict(os.environ, {"REACHAGENT_GOBUSTER_LIVE_TUNING": "1"}, clear=False):
        with (
            patch(
                "reachagent.recon.tools.gobuster._collect_signals",
                return_value={"target": "http://example.com"},
            ),
            patch(
                "reachagent.recon.live_tuning.propose_recon_tuning",
                side_effect=RuntimeError("anthropic timeout"),
            ),
        ):
            argv = r.command("http://example.com")
    # fallback to safe base behavior, no crash
    assert argv[:5] == ["gobuster", "dir", "-q", "-u", "http://example.com"]
    assert "-w" in argv


def test_flag_on_collect_signals_error_fallback_cleanly() -> None:
    r = _runner()
    with patch.dict(os.environ, {"REACHAGENT_GOBUSTER_LIVE_TUNING": "1"}, clear=False):
        with patch(
            "reachagent.recon.tools.gobuster._collect_signals",
            side_effect=TimeoutError("httpx timeout"),
        ):
            argv = r.command("http://example.com")
    assert argv[:5] == ["gobuster", "dir", "-q", "-u", "http://example.com"]
    assert "-w" in argv


def test_flag_on_wordlist_is_distinct_argv_element_not_injection() -> None:
    r = _runner()
    chosen = _allowlisted_choice(wordlist_idx=3, flag_idx=4, status_idx=0)
    with patch("reachagent.llm.client.build_openai_compatible_client", return_value=object()):
        with (
            patch(
                "reachagent.recon.tools.gobuster._collect_signals",
                return_value={"target": "http://example.com"},
            ),
            patch("reachagent.recon.live_tuning.propose_recon_tuning", return_value=chosen),
        ):
            argv = r.command("http://example.com")
    # target is a distinct element, wordlist is a distinct element after -w
    assert argv[4] == "http://example.com"
    w_idx = argv.index("-w")
    assert argv[w_idx + 1] == chosen.wordlist_path
    # chosen flags appended after wordlist, as distinct elements
    for flag in chosen.flags:
        assert flag in argv


def test_gobuster_parse_never_writes_can_call_even_without_flag() -> None:
    g = ReachabilityGraph()
    scope = ScopeGuard.from_hosts(["example.com"])
    a = AuditLog()
    r = GobusterRunner(graph=g, scope=scope, audit=a)
    with patch.dict(os.environ, {}, clear=False):
        os.environ.pop("REACHAGENT_GOBUSTER_LIVE_TUNING", None)
        os.environ.pop("REACHAGENT_RECON_LIVE_TUNING", None)
        r.command("http://example.com")
    r.ingest(
        "http://example.com",
        "/api                (Status: 200)\n/admin                (Status: 403)\n",
    )
    assert len(list(g.findings())) == 0
    assert len(g.can_call_edges()) == 0
    assert len(list(g.hosts())) == 1
    assert len(list(g.endpoints())) == 2


def test_flag_on_mocked_anthropic_client_no_live_api() -> None:
    """End-to-end with a mock Anthropic-style client via propose_recon_tuning.

    No network, no ANTHROPIC_API_KEY needed — the client is injected.
    """
    r = _runner()
    mock_client = Mock()
    mock_client.propose.return_value = {
        "wordlist_path": str(RECON_ALLOWLIST["wordlists"][5]),  # type: ignore[index]
        "flags": "-t 20",
        "filter_codes": str(RECON_ALLOWLIST["status_codes"][0]),  # type: ignore[index]
    }
    # Call live_tuning directly with mock client — no env, no httpx
    from reachagent.recon.live_tuning import propose_recon_tuning as _propose

    choice = _propose({"target": "http://example.com", "tech": "api"}, client=mock_client)
    assert choice.wordlist_path == str(RECON_ALLOWLIST["wordlists"][5])  # type: ignore[index]
    assert choice.flags == ("-t", "20")

    # Feed that choice through gobuster
    with patch("reachagent.llm.client.build_openai_compatible_client", return_value=object()):
        with (
            patch(
                "reachagent.recon.tools.gobuster._collect_signals",
                return_value={"target": "http://example.com", "tech": "api"},
            ),
            patch("reachagent.recon.live_tuning.propose_recon_tuning", return_value=choice),
        ):
            argv = r.command("http://example.com")
    assert choice.wordlist_path in argv
    mock_client.propose.assert_called_once()
