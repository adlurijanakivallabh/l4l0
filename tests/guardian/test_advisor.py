"""Isolated guardian advisor — hermetic tests (Build Order 3).

Same propose/validate/fail-open pattern as recon.live_tuning /
recon.payload_tuning, mirrored here (see tests/recon/test_recon_profile.py).
No flag gate (v4 R3 removed it) — attempted on every call, fails open with
no provider configured.
"""

from __future__ import annotations

from unittest.mock import Mock

import pytest

from reachagent.guardian.advisor import GuardianDecision, advise_on_action


def _fake_client(returning: dict[str, object]) -> Mock:
    m = Mock()
    m.propose.return_value = returning
    return m  # type: ignore[no-any-return]


def test_no_provider_configured_fails_open() -> None:
    decision = advise_on_action("fire_request", "example.com", "POST")
    assert decision.allow is True


def test_flag_on_valid_deny_is_honored() -> None:
    with pytest.MonkeyPatch.context():
        client = _fake_client({"allow": False, "reason": "looks destructive"})
        decision = advise_on_action("fire_request", "example.com", "DELETE", client=client)
    assert decision.allow is False
    assert decision.reason == "looks destructive"


def test_flag_on_valid_allow_is_honored() -> None:
    with pytest.MonkeyPatch.context():
        client = _fake_client({"allow": True, "reason": "ordinary test traffic"})
        decision = advise_on_action("fire_request", "example.com", "POST", client=client)
    assert decision.allow is True


def test_malformed_response_fails_open(caplog: pytest.LogCaptureFixture) -> None:
    with pytest.MonkeyPatch.context():
        client = _fake_client({"allow": "not-a-bool"})
        decision = advise_on_action("fire_request", "example.com", "POST", client=client)
    assert decision.allow is True


def test_unsupported_field_fails_open() -> None:
    with pytest.MonkeyPatch.context():
        client = _fake_client({"allow": True, "reason": "ok", "evil_extra": "x"})
        decision = advise_on_action("fire_request", "example.com", "POST", client=client)
    assert decision.allow is True


def test_client_error_fails_open() -> None:
    boom = Mock()
    boom.propose.side_effect = RuntimeError("provider unavailable")
    with pytest.MonkeyPatch.context():
        decision = advise_on_action("fire_request", "example.com", "POST", client=boom)
    assert decision.allow is True


def test_reason_is_truncated() -> None:
    with pytest.MonkeyPatch.context():
        client = _fake_client({"allow": True, "reason": "x" * 1000})
        decision = advise_on_action("fire_request", "example.com", "POST", client=client)
    assert len(decision.reason) <= 300


def test_guardian_decision_is_a_frozen_dataclass() -> None:
    decision = GuardianDecision(allow=True, reason="test")
    with pytest.raises(Exception):  # noqa: B017, PT011 — frozen dataclass, any exception is fine
        decision.allow = False  # type: ignore[misc]
