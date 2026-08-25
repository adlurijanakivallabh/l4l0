"""Hermetic provider-selection tests for all proposal/report phases."""

from __future__ import annotations

import pytest

from reachagent.graph.nodes import Finding, FindingStatus
from reachagent.graph.store import ReachabilityGraph
from reachagent.llm.client import OpenAICompatibleClient
from reachagent.recon import live_tuning, payload_tuning, vuln_tuning
from reachagent.report import llm_report


class _FakeJSONClient(OpenAICompatibleClient):
    """Protocol-compatible adapter; no HTTPX client is created."""

    def __init__(self, response: dict[str, object]) -> None:
        self.response = response
        self.prompts: list[str] = []

    def propose_json(self, prompt: str, *, max_tokens: int = 512) -> dict[str, object]:
        self.prompts.append(f"{max_tokens}:{prompt}")
        return self.response


@pytest.fixture
def compatible_provider(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("REACHAGENT_LLM_PROVIDER", "deepseek")


def test_recon_tuning_selects_compatible_provider(
    compatible_provider: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    adapter = _FakeJSONClient(
        {
            "wordlist_path": "/usr/share/wordlists/dirb/common.txt",
            "flags": "",
            "filter_codes": "200,204,301,302,307,401,403",
        }
    )
    monkeypatch.setattr(live_tuning, "build_openai_compatible_client", lambda: adapter)
    choice = live_tuning.propose_recon_tuning({"target": "https://example.test"})
    assert choice.wordlist_path.endswith("dirb/common.txt")
    assert adapter.prompts


def test_recon_profile_selects_compatible_provider(
    compatible_provider: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    adapter = _FakeJSONClient({"profile_name": "api_target"})
    monkeypatch.setattr(live_tuning, "build_openai_compatible_client", lambda: adapter)
    choice = live_tuning.propose_recon_profile({"target": "https://example.test"})
    assert choice is live_tuning.RECON_PROFILES["api_target"]
    assert adapter.prompts


def test_vuln_and_payload_phases_select_compatible_provider(
    compatible_provider: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    vuln_adapter = _FakeJSONClient({"vuln_classes": ["sqli", "xss_reflected"]})
    monkeypatch.setattr(vuln_tuning, "build_openai_compatible_client", lambda: vuln_adapter)
    vuln_choice = vuln_tuning.propose_vuln_targets({"method": "GET"})
    assert vuln_choice.vuln_classes == ("sqli", "xss_reflected")
    assert vuln_adapter.prompts

    payload_adapter = _FakeJSONClient({"payload_refs": ["ref-b", "ref-a"]})
    monkeypatch.setattr(payload_tuning, "build_openai_compatible_client", lambda: payload_adapter)
    payload_choice = payload_tuning.propose_payload_choice(
        {"sink": "sql"}, "sqli", ["ref-a", "ref-b"]
    )
    assert payload_choice.payload_refs == ("ref-b", "ref-a")
    assert payload_adapter.prompts


def test_report_selects_compatible_provider_without_changing_finding_gate(
    compatible_provider: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    adapter = _FakeJSONClient({"narrative": "# Confirmed report"})
    monkeypatch.setattr(llm_report, "build_openai_compatible_client", lambda: adapter)
    graph = ReachabilityGraph()
    graph.add_finding(
        Finding(
            vuln_class="sqli",
            severity="high",
            oracle_used="differential",
            evidence_ref="evidence-1",
            status=FindingStatus.CONFIRMED_VIOLATION,
        )
    )
    report = llm_report.generate_llm_report(graph)
    assert report.startswith("# Confirmed report")
    assert "evidence-1" in report
    assert adapter.prompts


def test_provider_failure_keeps_existing_safe_fallback(
    compatible_provider: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    class _FailingAdapter(_FakeJSONClient):
        def propose_json(self, prompt: str, *, max_tokens: int = 512) -> dict[str, object]:
            raise RuntimeError("provider unavailable")

    adapter = _FailingAdapter({})
    monkeypatch.setattr(vuln_tuning, "build_openai_compatible_client", lambda: adapter)
    choice = vuln_tuning.propose_vuln_targets({"method": "GET"})
    assert choice.vuln_classes == vuln_tuning._SAFE_DEFAULT_CLASSES
