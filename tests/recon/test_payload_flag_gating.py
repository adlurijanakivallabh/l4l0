"""Hermetic: payload-choice ordering flag-gated — OFF zero regression, ON smart."""

from __future__ import annotations

import os
from unittest.mock import patch

from reachagent.recon.payload_tuning import PayloadChoice
from reachagent.tools.payload_chain import _maybe_reorder_payloads


def _entries(refs: list[str]) -> list[dict[str, object]]:
    return [{"payload_ref": r, "resolved_value": r, "oracle_type": "structural"} for r in refs]


def test_flag_off_zero_regression_confidence_order() -> None:
    refs = ["a", "b", "c"]
    entries = _entries(refs)
    with patch.dict(os.environ, {}, clear=False):
        for k in ("REACHAGENT_PAYLOAD_TUNING", "REACHAGENT_RECON_LIVE_TUNING"):
            os.environ.pop(k, None)
        got = _maybe_reorder_payloads(entries, "sqli", "sql", None)
    assert [e["payload_ref"] for e in got] == refs  # byte-identical ordering


def test_flag_on_mocked_uses_chosen_subset_pruning_the_rest() -> None:
    refs = ["a", "b", "c", "d"]
    entries = _entries(refs)
    chosen = PayloadChoice(payload_refs=("c", "a"))
    with patch.dict(os.environ, {"REACHAGENT_PAYLOAD_TUNING": "1"}, clear=False):
        with patch("reachagent.recon.payload_tuning.propose_payload_choice", return_value=chosen):
            got = _maybe_reorder_payloads(entries, "sqli", "sql", None)
    # A genuine choice PRUNES to just the picks — "b" and "d" are dropped,
    # not ground through afterward. This is the fix for the real-world
    # complaint that live tuning only moved good picks to the front while
    # still exhausting the entire remaining bucket when they didn't confirm.
    assert [e["payload_ref"] for e in got] == ["c", "a"]
    assert all(e["payload_ref"] in refs for e in got)


def test_flag_on_outside_allowlist_ignored_defense_in_depth() -> None:
    refs = ["a", "b", "c"]
    entries = _entries(refs)
    # proposer returns an evil ref not in bucket (should be filtered even if proposer validated)
    evil = PayloadChoice(payload_refs=("evil", "a"))  # type: ignore[arg-type]
    with patch.dict(os.environ, {"REACHAGENT_PAYLOAD_TUNING": "1"}, clear=False):
        with patch("reachagent.recon.payload_tuning.propose_payload_choice", return_value=evil):
            got = _maybe_reorder_payloads(entries, "sqli", "sql", None)
    # evil filtered out; only the one legitimate pick survives — pruned, not
    # backfilled with the rest of the bucket.
    assert [e["payload_ref"] for e in got] == ["a"]
    assert "evil" not in [e["payload_ref"] for e in got]


def test_flag_on_proposer_error_fallback_original_order() -> None:
    refs = ["a", "b"]
    entries = _entries(refs)
    with patch.dict(os.environ, {"REACHAGENT_PAYLOAD_TUNING": "1"}, clear=False):
        with patch(
            "reachagent.recon.payload_tuning.propose_payload_choice",
            side_effect=RuntimeError("boom"),
        ):
            got = _maybe_reorder_payloads(entries, "sqli", "sql", None)
    assert [e["payload_ref"] for e in got] == refs


def test_flag_on_empty_bucket_returns_original() -> None:
    entries: list[dict[str, object]] = []
    with patch.dict(os.environ, {"REACHAGENT_PAYLOAD_TUNING": "1"}, clear=False):
        got = _maybe_reorder_payloads(entries, "sqli", "sql", None)
    assert got == []


def test_flag_on_via_alternate_env_var() -> None:
    refs = ["a", "b", "c"]
    entries = _entries(refs)
    chosen = PayloadChoice(payload_refs=("b",))
    with patch.dict(os.environ, {"REACHAGENT_RECON_LIVE_TUNING": "1"}, clear=False):
        with patch("reachagent.recon.payload_tuning.propose_payload_choice", return_value=chosen):
            got = _maybe_reorder_payloads(entries, "sqli", "sql", None)
    assert [e["payload_ref"] for e in got] == ["b"]


def test_max_attempts_still_honored_by_caller() -> None:
    # Pruning only drops UNCHOSEN entries — here the LLM chose all 25 (just
    # reordered), so nothing is pruned; max_attempts=20 is still enforced by
    # the run_payload_chain loop on top of whatever list comes back.
    refs = [f"p{i}" for i in range(25)]
    entries = _entries(refs)
    chosen = PayloadChoice(payload_refs=tuple(reversed(refs)))
    with patch.dict(os.environ, {"REACHAGENT_PAYLOAD_TUNING": "1"}, clear=False):
        with patch("reachagent.recon.payload_tuning.propose_payload_choice", return_value=chosen):
            got = _maybe_reorder_payloads(entries, "sqli", "sql", None)
    assert len(got) == 25
    assert got[0]["payload_ref"] == "p24"
    # caller will slice by max_attempts=20
    assert [e["payload_ref"] for e in got[:20]] == list(reversed(refs))[:20]
