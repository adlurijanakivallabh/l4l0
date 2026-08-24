"""Hermetic tests for live-reasoning payload choice — proposal-only, dynamic allowlist."""

from __future__ import annotations

from unittest.mock import Mock

from reachagent.recon.payload_tuning import PayloadChoice, propose_payload_choice


def _fake_client(returning: dict[str, object]) -> Mock:
    m = Mock()
    m.propose.return_value = returning
    return m  # type: ignore[no-any-return]


def test_mocked_valid_allowlisted_subset_reorder() -> None:
    cands = ["a", "b", "c"]
    raw = {"payload_refs": ["c", "a"]}
    choice = propose_payload_choice({"sink": "sql"}, "sqli", cands, client=_fake_client(raw))
    assert choice.payload_refs == ("c", "a")
    assert all(r in cands for r in choice.payload_refs)


def test_mocked_outside_allowlist_fallback_original_order() -> None:
    cands = ["a", "b", "c"]
    raw: dict[str, object] = {"payload_refs": ["evil", "a"]}
    choice = propose_payload_choice({"sink": "sql"}, "sqli", cands, client=_fake_client(raw))
    assert "evil" not in choice.payload_refs
    assert choice.payload_refs == tuple(cands[:20])


def test_mocked_invented_ref_logs_and_fallback() -> None:
    cands = ["a", "b"]
    raw: dict[str, object] = {"payload_refs": ["invented-ref"]}
    choice = propose_payload_choice({"sink": "sql"}, "sqli", cands, client=_fake_client(raw))
    assert choice.payload_refs == tuple(cands)
    assert "invented-ref" not in choice.payload_refs


def test_mocked_error_fallback_cleanly() -> None:
    cands = ["a", "b"]
    m = Mock()
    m.propose.side_effect = RuntimeError("timeout")
    choice = propose_payload_choice({"sink": "sql"}, "sqli", cands, client=m)
    assert choice.payload_refs == tuple(cands)
    assert isinstance(choice, PayloadChoice)


def test_mocked_timeout_exception_fallback_cleanly() -> None:
    cands = ["a", "b", "c"]
    m = Mock()
    m.propose.side_effect = TimeoutError("deadline")
    choice = propose_payload_choice({"sink": "sql"}, "sqli", cands, client=m)
    assert choice.payload_refs == tuple(cands[:20])


def test_mocked_empty_after_validation_fallback() -> None:
    cands = ["a", "b"]
    raw: dict[str, object] = {"payload_refs": []}
    choice = propose_payload_choice({"sink": "sql"}, "sqli", cands, client=_fake_client(raw))
    assert choice.payload_refs == tuple(cands)


def test_dedup_preserves_order_and_trims_to_bucket() -> None:
    cands = ["a", "b", "c"]
    raw: dict[str, object] = {"payload_refs": ["c", "c", "a"]}
    choice = propose_payload_choice({"sink": "sql"}, "sqli", cands, client=_fake_client(raw))
    assert choice.payload_refs == ("c", "a")


def test_empty_candidate_bucket_returns_empty() -> None:
    choice = propose_payload_choice(
        {"sink": "sql"}, "sqli", [], client=_fake_client({"payload_refs": ["a"]})
    )
    assert choice.payload_refs == ()
