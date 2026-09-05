"""Tests for multi-agent orchestration: monitor, coordinator merge, critic."""

from __future__ import annotations

from lalo.agent.monitor import LoopMonitor
from lalo.agent.tools import FunctionTool, ToolRegistry, ToolResult
from lalo.agents import (
    MultiAgentCoordinator,
    SubAgentSpec,
    completeness_critic,
    merge_findings,
    rehunt_spec,
)
from lalo.core.model_router import CompletionRequest, CompletionResponse, ModelRouter
from lalo.detectors.ledger import CoverageLedger
from lalo.graph.store import ReachGraph
from lalo.models import Finding, Severity


def test_loop_monitor_flags_repetition() -> None:
    mon = LoopMonitor(repeat_threshold=3)
    assert mon.observe("http", {"url": "x"}) is None
    assert mon.observe("http", {"url": "x"}) is None
    note = mon.observe("http", {"url": "x"})
    assert note is not None and "different" in note
    # A different call does not trip it.
    assert mon.observe("http", {"url": "y"}) is None


def test_merge_findings_by_id_dedups() -> None:
    a = ReachGraph()
    b = ReachGraph()
    f = Finding.create("t", "xss", Severity.MEDIUM, "https://x/")
    b.add_finding(f)
    assert merge_findings(a, b) == [f.id]
    # merging again adds nothing (already present by id)
    assert merge_findings(a, b) == []
    assert len(a.findings()) == 1


class _ScriptedProvider:
    name = "scripted"

    def __init__(self, responses: list[str]) -> None:
        self._responses = responses
        self.calls = 0

    def complete(self, request: CompletionRequest) -> CompletionResponse:
        text = self._responses[min(self.calls, len(self._responses) - 1)]
        self.calls += 1
        return CompletionResponse(text=text, provider=self.name, model="scripted")


def _record_registry(graph: ReachGraph) -> ToolRegistry:
    def record(args: dict[str, object]) -> ToolResult:
        f = Finding.create(str(args.get("title", "x")), "sqli", Severity.HIGH, "https://x/")
        graph.add_finding(f)
        return ToolResult(f"recorded {f.id}")

    return ToolRegistry([FunctionTool("record_finding", "record", record)])


def test_coordinator_merges_authoritative_findings_from_isolated_subgraph() -> None:
    base = ReachGraph()
    router = ModelRouter(
        providers={
            "scripted": _ScriptedProvider(
                [
                    '{"tool":"record_finding","args":{"title":"sqli in id"}}',
                    '{"tool":"finish","args":{"summary":"prose summary only"}}',
                ]
            )
        },
        routes={"reasoning": ("scripted",)},
    )
    coord = MultiAgentCoordinator(router, base)
    report = coord.run_specialist(
        SubAgentSpec(role="sqli", objective="find sqli", registry_factory=_record_registry)
    )
    # The finding is merged from the sub-graph by id (authoritative), not the prose.
    assert len(report.finding_ids) == 1
    assert report.stop_reason == "finished"
    assert len(base.findings()) == 1  # merged into the shared graph


def test_completeness_critic_and_rehunt() -> None:
    ledger = CoverageLedger()
    ledger.mark_applicable("https://app/x", "xss")
    ledger.mark_assessed("https://app/x", "sqli")
    items = completeness_critic(ledger)
    assert any(i.vuln_class == "xss" for i in items)
    assert "not tested" in items[0].as_objective()

    lead = Finding.create("rce", "cmdi", Severity.CRITICAL, "https://app/ping")
    lead.confidence = 92.0
    spec = rehunt_spec(lead, _record_registry)
    assert spec.role == "rehunt:cmdi"
    assert "Escalate" in spec.objective
