"""Focused tests for adaptive recon selection and new fact emitters."""

from __future__ import annotations

import json

import pytest

from reachagent.execution.audit import AuditLog
from reachagent.execution.scope import ScopeGuard
from reachagent.graph.store import ReachabilityGraph
from reachagent.llm.planner import (
    PlanningContext,
    PlanValidationError,
    ReconSelection,
    select_recon_tools,
    validate_recon_selection,
)
from reachagent.recon.calibration import DnsWildcardResult
from reachagent.recon.tools import BbotRunner, DnsreconRunner, UrlfinderRunner


class _Client:
    def __init__(self, response: dict[str, object]) -> None:
        self.response = response
        self.prompts: list[str] = []

    def propose_json(self, prompt: str, *, max_tokens: int = 512) -> dict[str, object]:
        self.prompts.append(prompt)
        return self.response


def _context() -> PlanningContext:
    return PlanningContext(
        target="https://target.test",
        target_type="url",
        in_scope=("target.test",),
        graph_facts={"host_count": "1"},
        operator_prompt="map the authorized web surface",
        max_tool_budget=4,
    )


def test_recon_selection_is_allowlisted_and_contextual() -> None:
    client = _Client(
        {
            "tools": ["urlfinder", "dnsrecon"],
            "rationale": "passive URL and DNS coverage",
            "stop": False,
        }
    )
    choice = select_recon_tools(
        _context(),
        client,
        state={"endpoint_count": "0"},
        available_tools=("urlfinder", "dnsrecon"),
    )
    assert choice == ReconSelection(
        ("urlfinder", "dnsrecon"), "passive URL and DNS coverage", False
    )
    assert '"capabilities"' in client.prompts[0]
    assert "nmap -" not in client.prompts[0].lower()


@pytest.mark.parametrize(
    "raw, message",
    [
        ({"tools": ["nuclei"], "rationale": "claim", "stop": False}, "fact emitter"),
        ({"tools": ["urlfinder"], "rationale": "repeat", "stop": False}, "completed"),
        ({"tools": ["unknown"], "rationale": "unknown", "stop": False}, "unavailable"),
        ({"tools": [], "rationale": "missing stop", "stop": False}, "choose a tool"),
    ],
)
def test_recon_selection_rejects_unsafe_or_empty_choices(
    raw: dict[str, object], message: str
) -> None:
    with pytest.raises(PlanValidationError, match=message):
        validate_recon_selection(
            raw,
            context=_context(),
            available_tools=("urlfinder", "nuclei", "unknown"),
            completed_tools=("urlfinder",),
        )


def test_new_recon_emitters_parse_scoped_facts() -> None:
    scope = ScopeGuard.from_hosts(["target.test", "*.target.test"])

    url_graph = ReachabilityGraph()
    url_audit = AuditLog()
    url_result = UrlfinderRunner(graph=url_graph, scope=scope, audit=url_audit).ingest(
        "target.test",
        '{"url":"https://api.target.test/v1/users?id=1","source":"archive"}\n'
        '{"url":"https://outside.example/secret","source":"archive"}\n',
    )
    assert url_result.nodes and len(list(url_graph.endpoints())) == 1
    assert any(entry.outcome == "refused_out_of_scope" for entry in url_audit.entries)

    dns_graph = ReachabilityGraph()
    dns_result = DnsreconRunner(graph=dns_graph, scope=scope).ingest(
        "target.test",
        json.dumps(
            [
                {"type": "A", "name": "api.target.test", "address": "10.0.0.1"},
                {"type": "CNAME", "name": "cdn.target.test", "target": "edge.example"},
            ]
        ),
    )
    assert dns_result.nodes and len(list(dns_graph.hosts())) == 2
    assert all(host.hostname.endswith("target.test") for _, host in dns_graph.hosts())

    bbot_graph = ReachabilityGraph()
    bbot_result = BbotRunner(graph=bbot_graph, scope=scope).ingest(
        "target.test",
        '{"type":"DNS_NAME","data":"api.target.test"}\n'
        '{"type":"OPEN_TCP_PORT","data":"api.target.test:443"}\n'
        '{"type":"URL","data":"https://api.target.test/v1"}\n',
    )
    assert bbot_result.nodes
    assert {service.port for _, service in bbot_graph.services()} == {443}
    assert {endpoint.path for _, endpoint in bbot_graph.endpoints()} == {"/v1"}


def test_adaptive_scan_adds_next_tool_from_observed_state(monkeypatch: pytest.MonkeyPatch) -> None:
    from reachagent.scan import entrypoint

    monkeypatch.setattr(entrypoint._coordinator, "query_graph", lambda _context: [])
    monkeypatch.setattr(
        "reachagent.recon.api_discovery.discover_api",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        "reachagent.recon.calibration.DnsWildcardProber.run",
        lambda _self: DnsWildcardResult(False, ips=(None, None, None)),
    )

    calls: list[tuple[tuple[str, ...], tuple[str, ...]]] = []

    def select(
        _state: dict[str, str],
        available: tuple[str, ...],
        completed: tuple[str, ...],
    ) -> ReconSelection:
        calls.append((available, completed))
        if not completed:
            return ReconSelection(("urlfinder",), "start with passive URLs")
        return ReconSelection(("dnsrecon",), "DNS records fill the remaining gap")

    result = entrypoint.scan_target(
        base_url="https://target.test",
        in_scope="target.test",
        dry_run=False,
        fixtures={
            "urlfinder": '{"url":"https://target.test/api","source":"archive"}\n',
            "dnsrecon": json.dumps([{"type": "A", "name": "target.test", "address": "10.0.0.1"}]),
        },
        recon_tools=("urlfinder",),
        recon_candidates=("urlfinder", "dnsrecon"),
        recon_selector=select,
    )
    assert result["recon_tools"] == ("urlfinder", "dnsrecon")
    assert calls[0][1] == ()
    assert calls[1][1] == ("urlfinder",)
