"""Default-credential detector — hermetic tests (§7, Prober-injection pattern).

v3 (CLAUDE.md): confirmation is now an LLM judgment (``fixed_oracle_runner``
stands in for it, see tests/_oracle_test_support.py). This file covers the
v3 V3 inverted-polarity refutation corroboration
(``confirmation/corroboration.py::corroborate_by_refutation``) — the
orchestrator-level wiring (identities collision check, GUI flag) lives in
tests/scan/test_default_credentials_driver.py.
"""

from __future__ import annotations

from reachagent.default_creds.detector import (
    CREDENTIAL_ALLOWLIST,
    detect_default_credentials,
)
from reachagent.identity.login import CapturedSession, LoginError
from tests._oracle_test_support import CONFIRMS, fixed_oracle_runner

_REFUTATION_PAIR = ("reachagent-refutation-probe", "definitely-not-a-real-password")


def test_no_refutation_credential_is_byte_for_byte_unchanged() -> None:
    def attempt_login(username: str, password: str) -> CapturedSession:
        if (username, password) == ("admin", "admin"):
            return CapturedSession(token="tok")
        raise LoginError("nope")

    result = detect_default_credentials(
        form=None,  # type: ignore[arg-type]
        attempt_login=attempt_login,
        order=CREDENTIAL_ALLOWLIST,
        oracle_runner=fixed_oracle_runner(CONFIRMS),
        evidence_ref="ref-plain",
    )
    assert result.confirmed is True
    assert result.corroborated is False


def test_refutation_correctly_refused_corroborates() -> None:
    def attempt_login(username: str, password: str) -> CapturedSession:
        if (username, password) == ("admin", "admin"):
            return CapturedSession(token="tok")
        raise LoginError("nope")  # every other pair, including the control, is refused

    result = detect_default_credentials(
        form=None,  # type: ignore[arg-type]
        attempt_login=attempt_login,
        order=CREDENTIAL_ALLOWLIST,
        oracle_runner=fixed_oracle_runner(CONFIRMS),
        evidence_ref="ref-corroborated",
        refutation_credential=_REFUTATION_PAIR,
    )
    assert result.confirmed is True
    assert result.corroborated is True
    assert result.username == "admin"


def test_refutation_unexpectedly_granted_fails_closed() -> None:
    """A login form that hands out a session to ANY credentials (including
    the garbage control pair) doesn't actually discriminate — the original
    match is not trusted."""

    def attempt_login(username: str, password: str) -> CapturedSession:
        return CapturedSession(token="tok")  # grants a session unconditionally

    result = detect_default_credentials(
        form=None,  # type: ignore[arg-type]
        attempt_login=attempt_login,
        order=CREDENTIAL_ALLOWLIST,
        oracle_runner=fixed_oracle_runner(CONFIRMS),
        refutation_credential=_REFUTATION_PAIR,
    )
    assert result.confirmed is False
    assert result.corroborated is False


def test_refutation_transport_error_is_ambiguous_and_fails_closed() -> None:
    def attempt_login(username: str, password: str) -> CapturedSession:
        if (username, password) == ("admin", "admin"):
            return CapturedSession(token="tok")
        raise ConnectionError("boom")  # neither a clean refusal nor a grant

    result = detect_default_credentials(
        form=None,  # type: ignore[arg-type]
        attempt_login=attempt_login,
        order=CREDENTIAL_ALLOWLIST,
        oracle_runner=fixed_oracle_runner(CONFIRMS),
        refutation_credential=_REFUTATION_PAIR,
    )
    assert result.confirmed is False
    assert result.corroborated is False


def test_refutation_never_fires_when_no_pair_ever_confirms() -> None:
    calls = {"n": 0}

    def attempt_login(username: str, password: str) -> CapturedSession:
        calls["n"] += 1
        raise LoginError("nope")

    result = detect_default_credentials(
        form=None,  # type: ignore[arg-type]
        attempt_login=attempt_login,
        order=CREDENTIAL_ALLOWLIST,
        refutation_credential=_REFUTATION_PAIR,
    )
    assert result.confirmed is False
    # every allowlisted candidate tried, but never the control pair
    assert calls["n"] == len(CREDENTIAL_ALLOWLIST[:5])
