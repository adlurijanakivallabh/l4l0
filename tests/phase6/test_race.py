"""Hermetic Phase 6 race-condition tests."""

from __future__ import annotations

import ast
import os
from dataclasses import dataclass
from pathlib import Path

import httpx
import pytest

from reachagent.business_logic import SingleUseReuseTemplate
from reachagent.business_logic.templates import TemplateCheck
from reachagent.execution import AuditLog, RequestFirer, ScopeGuard
from reachagent.graph.nodes import Endpoint, Parameter
from reachagent.graph.store import ReachabilityGraph
from reachagent.race import (
    Delivery,
    DeliveryMode,
    DeliveryObservation,
    DeliveryRequest,
    Http2MultiplexedDeliveryRunner,
    RequestFirerDeliveryRunner,
    identify_resources,
    probe_race,
)


@dataclass
class RecordingDelivery:
    sequential_statuses: tuple[int, ...]
    concurrent_statuses: tuple[int, ...]

    def __post_init__(self) -> None:
        self.calls: list[DeliveryMode] = []

    def deliver(
        self, identity: str, resource: object, delivery: Delivery
    ) -> tuple[DeliveryObservation, ...]:
        del identity, resource
        self.calls.append(delivery.mode)
        statuses = (
            self.sequential_statuses
            if delivery.mode is DeliveryMode.SEQUENTIAL
            else self.concurrent_statuses
        )
        if len(statuses) != len(delivery.requests):
            statuses = statuses[: len(delivery.requests)]
        return tuple(
            DeliveryObservation(request.label, status)
            for request, status in zip(delivery.requests, statuses, strict=True)
        )


def _check_graph() -> tuple[ReachabilityGraph, TemplateCheck]:
    graph = ReachabilityGraph()
    endpoint = graph.add_endpoint(Endpoint("POST", "/coupon/redeem"))
    graph.add_parameter(endpoint, Parameter("coupon_code", "body"))
    (check,) = SingleUseReuseTemplate().instantiate(graph)
    return graph, check


def test_sequential_replay_confirms_double_spend_without_concurrency() -> None:
    graph, check = _check_graph()
    runner = RecordingDelivery((200, 200), (200, 200))
    evidence, outcome = probe_race(graph, "owner", check, runner)
    assert evidence.delivery_mode is DeliveryMode.SEQUENTIAL
    assert outcome.is_violation is True
    assert runner.calls == [DeliveryMode.SEQUENTIAL]


def test_serialized_target_is_not_a_false_positive() -> None:
    graph, check = _check_graph()
    runner = RecordingDelivery((200, 403), (200, 200))
    evidence, outcome = probe_race(graph, "owner", check, runner)
    assert evidence.delivery_mode is DeliveryMode.SEQUENTIAL
    assert outcome.confirmed is True
    assert outcome.is_violation is False
    assert runner.calls == [DeliveryMode.SEQUENTIAL]


def test_concurrency_escalates_only_after_sequential_finds_nothing() -> None:
    graph, check = _check_graph()
    runner = RecordingDelivery((200, 0), (200, 200))
    concurrent = Delivery(
        DeliveryMode.CONCURRENT,
        (
            DeliveryRequest(
                "race-a", "POST", "/coupon/redeem", True, {"coupon_code": "sample-coupon_code"}
            ),
            DeliveryRequest(
                "race-b", "POST", "/coupon/redeem", True, {"coupon_code": "sample-coupon_code"}
            ),
        ),
    )
    evidence, outcome = probe_race(graph, "owner", check, runner, concurrent_delivery=concurrent)
    assert evidence.delivery_mode is DeliveryMode.CONCURRENT
    assert outcome.is_violation is True
    assert runner.calls == [DeliveryMode.SEQUENTIAL, DeliveryMode.CONCURRENT]


def test_concurrent_delivery_requires_two_accepted_duplicate_requests() -> None:
    graph, check = _check_graph()
    runner = RecordingDelivery((200, 0), (403, 200))
    concurrent = Delivery(
        DeliveryMode.CONCURRENT,
        (
            DeliveryRequest(
                "race-a", "POST", "/coupon/redeem", True, {"coupon_code": "sample-coupon_code"}
            ),
            DeliveryRequest(
                "race-b", "POST", "/coupon/redeem", True, {"coupon_code": "sample-coupon_code"}
            ),
        ),
    )
    evidence, outcome = probe_race(graph, "owner", check, runner, concurrent_delivery=concurrent)
    assert evidence.delivery_mode is DeliveryMode.CONCURRENT
    assert outcome.confirmed is True
    assert outcome.is_violation is False


def test_concurrent_ambiguous_response_is_inconclusive_regardless_of_order() -> None:
    graph, check = _check_graph()
    concurrent = Delivery(
        DeliveryMode.CONCURRENT,
        (
            DeliveryRequest(
                "race-a", "POST", "/coupon/redeem", True, {"coupon_code": "sample-coupon_code"}
            ),
            DeliveryRequest(
                "race-b", "POST", "/coupon/redeem", True, {"coupon_code": "sample-coupon_code"}
            ),
        ),
    )
    for statuses in ((0, 403), (403, 0)):
        evidence, outcome = probe_race(
            graph,
            "owner",
            check,
            RecordingDelivery((200, 0), statuses),
            concurrent_delivery=concurrent,
        )
        assert evidence.delivery_mode is DeliveryMode.CONCURRENT
        assert outcome.confirmed is False


def test_fresh_provider_allows_escalation_after_serial_denial() -> None:
    graph, check = _check_graph()
    fresh = Delivery(
        DeliveryMode.CONCURRENT,
        (
            DeliveryRequest(
                "fresh-a", "POST", "/coupon/redeem", True, {"coupon_code": "fresh-code"}
            ),
            DeliveryRequest(
                "fresh-b", "POST", "/coupon/redeem", True, {"coupon_code": "fresh-code"}
            ),
        ),
    )
    runner = RecordingDelivery((200, 403), (200, 200))
    evidence, outcome = probe_race(
        graph,
        "owner",
        check,
        runner,
        fresh_delivery_provider=lambda identity, resource, template, sequential: fresh,
    )
    assert evidence.delivery_mode is DeliveryMode.CONCURRENT
    assert outcome.is_violation is True
    assert runner.calls == [DeliveryMode.SEQUENTIAL, DeliveryMode.CONCURRENT]


def test_invalid_concurrent_delivery_is_rejected_before_sequential_replay() -> None:
    graph, check = _check_graph()
    runner = RecordingDelivery((200, 0), (200, 200))
    invalid = Delivery(
        DeliveryMode.CONCURRENT,
        (DeliveryRequest("only-one", "POST", "/coupon/redeem", True),),
    )
    with pytest.raises(ValueError, match="at least two"):
        probe_race(graph, "owner", check, runner, concurrent_delivery=invalid)
    assert runner.calls == []


def test_probe_race_rejects_non_single_use_checks() -> None:
    graph = ReachabilityGraph()
    endpoint = graph.add_endpoint(Endpoint("POST", "/cart/add"))
    graph.add_parameter(endpoint, Parameter("quantity", "body"))
    from reachagent.business_logic import QuantityLimitTemplate

    (check,) = QuantityLimitTemplate().instantiate(graph)
    with pytest.raises(ValueError, match="single-use"):
        probe_race(graph, "owner", check, RecordingDelivery((200, 200), (200, 200)))


def test_resources_only_come_from_recon_materialized_limited_parameter() -> None:
    graph, _ = _check_graph()
    resources = identify_resources(graph)
    assert len(resources) == 1
    assert resources[0].provenance == "graph:endpoint:POST /coupon/redeem"
    assert resources[0].resource_kind == "single_use_reuse"
    empty = ReachabilityGraph()
    assert identify_resources(empty) == ()


def test_http2_runner_requires_http2_enabled_client() -> None:
    firer = RequestFirer(
        httpx.Client(transport=httpx.MockTransport(lambda request: httpx.Response(200))),
        ScopeGuard.from_hosts(["shop.test"]),
        AuditLog(),
    )
    with pytest.raises(ValueError, match="HTTP/2"):
        Http2MultiplexedDeliveryRunner(firer, base_url="https://shop.test")


def test_request_firer_delivery_runner_concurrent_mode_preserves_scope_and_audit() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={"ok": True})

    audit = AuditLog()
    firer = RequestFirer(
        httpx.Client(transport=httpx.MockTransport(handler)),
        ScopeGuard.from_hosts(["shop.test"]),
        audit,
    )
    runner = RequestFirerDeliveryRunner(firer, base_url="https://shop.test")
    resource = next(iter(identify_resources(_check_graph()[0])))
    delivery = Delivery(
        DeliveryMode.CONCURRENT,
        (
            DeliveryRequest("a", "GET", "/coupon/redeem"),
            DeliveryRequest("b", "GET", "/coupon/redeem"),
        ),
    )
    observations = runner.deliver("owner", resource, delivery)
    assert [observation.status_code for observation in observations] == [200, 200]
    assert len(seen) == 2
    assert len(audit.entries) == 2


def test_request_firer_delivery_runner_concurrent_mutations_require_read_only_clearance() -> None:
    audit = AuditLog()
    firer = RequestFirer(
        httpx.Client(transport=httpx.MockTransport(lambda request: httpx.Response(200))),
        ScopeGuard.from_hosts(["shop.test"]),
        audit,
    )
    runner = RequestFirerDeliveryRunner(firer, base_url="https://shop.test")
    resource = next(iter(identify_resources(_check_graph()[0])))
    delivery = Delivery(
        DeliveryMode.CONCURRENT,
        (
            DeliveryRequest("a", "POST", "/coupon/redeem", True),
            DeliveryRequest("b", "POST", "/coupon/redeem", True),
        ),
    )
    observations = runner.deliver("owner", resource, delivery)
    assert [observation.status_code for observation in observations] == [0, 0]
    assert all(entry.outcome == "refused_read_only_first" for entry in audit.entries)


def test_concurrent_delivery_overlaps_requests_through_firer() -> None:
    import threading

    active = 0
    max_active = 0
    lock = threading.Lock()
    entered = threading.Barrier(2)
    release = threading.Barrier(2)

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal active, max_active
        with lock:
            active += 1
            max_active = max(max_active, active)
        entered.wait(timeout=2)
        release.wait(timeout=2)
        with lock:
            active -= 1
        return httpx.Response(200, text="accepted")

    audit = AuditLog()
    firer = RequestFirer(
        httpx.Client(transport=httpx.MockTransport(handler)),
        ScopeGuard.from_hosts(["shop.test"]),
        audit,
    )
    runner = RequestFirerDeliveryRunner(firer, base_url="https://shop.test")
    resource = next(iter(identify_resources(_check_graph()[0])))
    delivery = Delivery(
        DeliveryMode.CONCURRENT,
        (
            DeliveryRequest("race-a", "GET", "/coupon/redeem"),
            DeliveryRequest("race-b", "GET", "/coupon/redeem"),
        ),
    )
    observations = runner.deliver("owner", resource, delivery)
    assert [observation.status_code for observation in observations] == [200, 200]
    assert max_active == 2


def test_race_module_uses_business_rule_family_only() -> None:
    path = Path(__file__).parents[2] / "src" / "reachagent" / "race" / "module.py"
    tree = ast.parse(path.read_text(encoding="utf-8"))
    mechanisms = {
        node.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Attribute)
        and isinstance(node.value, ast.Name)
        and node.value.id == "OracleMechanism"
    }
    assert mechanisms == {"BUSINESS_RULE_INVARIANT"}
    assert not any(
        isinstance(node, ast.ImportFrom) and "tools.validator" in (node.module or "")
        for node in ast.walk(tree)
    )


def test_live_gate_requires_both_credentials(monkeypatch: pytest.MonkeyPatch) -> None:
    from reachagent.race import live_gate_configured

    for url, token in (("", "token"), ("https://lab.test", ""), ("", "")):
        monkeypatch.setenv("REACHAGENT_PORTSWIGGER_LAB_URL", url)
        monkeypatch.setenv("REACHAGENT_PORTSWIGGER_SESSION_TOKEN", token)
        assert live_gate_configured() is False


@pytest.mark.skipif(
    not (
        os.environ.get("REACHAGENT_PORTSWIGGER_LAB_URL")
        and os.environ.get("REACHAGENT_PORTSWIGGER_SESSION_TOKEN")
    ),
    reason="PortSwigger race lab credentials unavailable",
)
def test_live_portswigger_race_lab_is_env_gated() -> None:
    """Configured lab remains a deferred live assertion, never run in unit tests."""
    pytest.skip("live PortSwigger race assertion requires dedicated lab adapter")
