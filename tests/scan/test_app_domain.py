"""Build Order v2 W18 — application-domain inference.

A single bounded LLM call classifies WHAT the app is (hospital/ecommerce/...) from the
observed surface. Advisory + order-only: it becomes a host fact and a class-priority signal,
NEVER a finding and NEVER a coverage gate. Fails open to "" on any error.
"""

from __future__ import annotations

from dataclasses import replace

from reachagent.graph.nodes import Endpoint, Host
from reachagent.graph.store import ReachabilityGraph
from reachagent.scan.app_domain import classify_app_domain
from reachagent.scan.orchestrator import _class_priority_signals


class _FakeClient:
    def __init__(self, reply: dict) -> None:
        self.reply = reply
        self.seen_prompt = ""

    def propose_json(self, prompt: str, *, max_tokens: int = 200) -> dict:
        self.seen_prompt = prompt
        return self.reply


def _graph_with_surface() -> ReachabilityGraph:
    g = ReachabilityGraph()
    g.add_host(Host(address="demo.example", source="t", technology="PHP"))
    g.add_endpoint(Endpoint(method="GET", path="/patients/1/records"))
    g.add_endpoint(Endpoint(method="POST", path="/appointments"))
    return g


def test_classify_returns_domain_from_surface() -> None:
    g = _graph_with_surface()
    fake = _FakeClient({"domain": "hospital records system", "rationale": "patient endpoints"})
    assert classify_app_domain(g, client=fake) == "hospital records system"
    assert "patients" in fake.seen_prompt  # the surface was actually sent


def test_classify_fails_open_on_error() -> None:
    class Boom:
        def propose_json(self, prompt: str, *, max_tokens: int = 200) -> dict:
            raise RuntimeError("no provider")

    assert classify_app_domain(_graph_with_surface(), client=Boom()) == ""


def test_classify_empty_graph_is_empty() -> None:
    fake = _FakeClient({"domain": "whatever"})
    assert classify_app_domain(ReachabilityGraph(), client=fake) == ""


def test_classify_unknown_label_is_empty() -> None:
    fake = _FakeClient({"domain": "unknown"})
    assert classify_app_domain(_graph_with_surface(), client=fake) == ""


def test_app_domain_becomes_an_order_only_signal_and_preserves_tech() -> None:
    g = _graph_with_surface()
    for _n, h in g.hosts():
        g.add_host(replace(h, app_domain="ecommerce store"))
    # merge-enrich must not drop the pre-existing technology fact
    assert [h.technology for _n, h in g.hosts()] == ["PHP"]
    signals = _class_priority_signals(g, None)
    assert signals["app_domain"] == "ecommerce store"


def test_app_domain_never_creates_a_finding() -> None:
    g = _graph_with_surface()
    for _n, h in g.hosts():
        g.add_host(replace(h, app_domain="banking portal"))
    assert g.findings() == []
