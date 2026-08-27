"""Strict GUI-mode provider failures do not silently fall back."""

from __future__ import annotations

from collections.abc import Mapping
from unittest.mock import Mock

import pytest

from reachagent.graph.store import ReachabilityGraph
from reachagent.llm.runtime import override
from reachagent.recon.live_tuning import profile_decision, propose_recon_profile
from reachagent.recon.vuln_tuning import _SAFE_DEFAULT_CLASSES, propose_vuln_targets
from reachagent.report.llm_report import generate_llm_report
from reachagent.tools.payload_chain import _maybe_reorder_payloads


def _failing_client() -> Mock:
    client = Mock()
    client.propose.side_effect = RuntimeError("provider unavailable")
    return client


def test_strict_vulnerability_proposal_propagates_provider_error() -> None:
    with override(enabled=True, provider="deepseek", required=True):
        with pytest.raises(RuntimeError, match="provider unavailable"):
            propose_vuln_targets({"method": "GET"}, client=_failing_client())


def test_strict_empty_model_output_uses_allowlisted_safe_proposal() -> None:
    client = Mock()
    client.propose.side_effect = ValueError("LLM Responses API returned no output text")
    with override(enabled=True, provider="deepseek", required=True):
        choice = propose_vuln_targets({"method": "GET"}, client=client)
    assert choice.vuln_classes == _SAFE_DEFAULT_CLASSES


def test_strict_profile_proposal_propagates_provider_error() -> None:
    with override(enabled=True, provider="deepseek", required=True):
        with pytest.raises(RuntimeError, match="provider unavailable"):
            propose_recon_profile({"target": "https://example.test"}, client=_failing_client())


def test_strict_profile_decision_does_not_return_default_on_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "reachagent.recon.live_tuning._collect_target_signals",
        lambda _target, _operator_prompt=None: {"target": "https://example.test"},
    )
    with override(enabled=True, provider="deepseek", required=True):
        with pytest.raises(RuntimeError, match="provider unavailable"):
            profile_decision("https://example.test", client=_failing_client())


def test_strict_payload_reorder_propagates_provider_error() -> None:
    entries: list[Mapping[str, object]] = [
        {"payload_ref": "a", "resolved_value": "a", "oracle_type": "structural"}
    ]
    with override(enabled=True, provider="deepseek", required=True):
        with pytest.MonkeyPatch.context() as monkeypatch:
            monkeypatch.setattr(
                "reachagent.recon.payload_tuning.propose_payload_choice",
                Mock(side_effect=RuntimeError("provider unavailable")),
            )
            with pytest.raises(RuntimeError, match="provider unavailable"):
                _maybe_reorder_payloads(entries, "sqli", "sql", None)


def test_strict_report_does_not_fallback_to_deterministic_table() -> None:
    with override(enabled=True, provider="deepseek", required=True):
        with pytest.raises(RuntimeError, match="provider unavailable"):
            generate_llm_report(ReachabilityGraph(), client=_failing_client())
