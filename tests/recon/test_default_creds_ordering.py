"""Hermetic tests for default-credential LLM ordering — allowlist-validated,
never able to invent a pair (mirrors tests/recon/test_recon_profile.py).
"""

from __future__ import annotations

from unittest.mock import Mock

from reachagent.default_creds.detector import (
    _MAX_ATTEMPTS,
    CREDENTIAL_ALLOWLIST,
    propose_credential_order,
)


def _fake_client(returning: dict[str, object]) -> Mock:
    m = Mock()
    m.propose.return_value = returning
    return m  # type: ignore[no-any-return]


def test_valid_order_is_used_verbatim() -> None:
    order = propose_credential_order(
        {"target": "http://example.com"},
        client=_fake_client({"order": ["admin:password", "admin:admin"]}),
    )
    assert order == (("admin", "password"), ("admin", "admin"))


def test_invented_pair_outside_allowlist_is_dropped_not_substituted() -> None:
    order = propose_credential_order(
        {"target": "http://example.com"},
        client=_fake_client({"order": ["admin:admin", "hacker:invented-password"]}),
    )
    assert order == (("admin", "admin"),)
    assert ("hacker", "invented-password") not in order


def test_malformed_response_falls_back_to_fixed_order() -> None:
    order = propose_credential_order(
        {"target": "http://example.com"}, client=_fake_client({"order": "not-a-list"})
    )
    assert order == CREDENTIAL_ALLOWLIST[:_MAX_ATTEMPTS]


def test_empty_after_filtering_falls_back_to_fixed_order() -> None:
    order = propose_credential_order(
        {"target": "http://example.com"}, client=_fake_client({"order": ["nope:nope"]})
    )
    assert order == CREDENTIAL_ALLOWLIST[:_MAX_ATTEMPTS]


def test_client_error_falls_back_to_fixed_order() -> None:
    boom = Mock()
    boom.propose.side_effect = RuntimeError("provider unavailable")
    order = propose_credential_order({"target": "http://example.com"}, client=boom)
    assert order == CREDENTIAL_ALLOWLIST[:_MAX_ATTEMPTS]


def test_order_is_capped_at_max_attempts() -> None:
    all_pairs = [f"{u}:{p}" for u, p in CREDENTIAL_ALLOWLIST] * 3
    order = propose_credential_order(
        {"target": "http://example.com"}, client=_fake_client({"order": all_pairs})
    )
    assert len(order) <= _MAX_ATTEMPTS
