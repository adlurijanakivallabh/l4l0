"""Sequential-first race-condition probing (plan §7, Phase 6).

Race delivery is secondary. This module only orchestrates graph-recognized business
checks and injected delivery mechanisms; deterministic confirmation remains the
existing ``business_rule_invariant`` oracle family. Production delivery adapters
must call ``RequestFirer`` for every request so scope, audit, and read-only-first
remain execution-layer gates.
"""

from __future__ import annotations

import os
import threading
from collections import Counter
from collections.abc import Mapping
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol

from reachagent.business_logic.templates import (
    ReplayStep,
    StepRole,
    TemplateCheck,
    instantiate_all,
)
from reachagent.detection.oracle_gateway import OracleOutcome, OracleRunner, registry_runner
from reachagent.execution.firer import RequestFirer
from reachagent.graph.store import ReachabilityGraph
from reachagent.oracles import OracleMechanism
from reachagent.oracles.business_rule import (
    BusinessRule,
    BusinessRuleEvidence,
    ReplayObservation,
)


class DeliveryMode(StrEnum):
    SEQUENTIAL = "sequential"
    CONCURRENT = "concurrent"


@dataclass(frozen=True)
class TargetResource:
    """Recon-derived limited resource eligible for race probing."""

    ref: str
    endpoint_ref: str
    identity_ref: str
    method: str
    path: str
    resource_kind: str
    provenance: str
    evidence_ref: str


@dataclass(frozen=True)
class DeliveryRequest:
    """One delivery request, copied from an instantiated business template step."""

    label: str
    method: str
    path: str
    state_changing: bool = False
    json_body: Mapping[str, object] | None = None

    @classmethod
    def from_step(cls, step: ReplayStep) -> DeliveryRequest:
        return cls(step.label, step.method, step.path, step.state_changing, step.json_body)


@dataclass(frozen=True)
class Delivery:
    """Sequential or concurrent request batch supplied to a delivery runner."""

    mode: DeliveryMode
    requests: tuple[DeliveryRequest, ...]


@dataclass(frozen=True)
class DeliveryObservation:
    """One response signal from a delivery attempt."""

    label: str
    status_code: int
    body: str = ""

    def to_replay(self) -> ReplayObservation:
        return ReplayObservation(self.label, self.status_code, self.body)


@dataclass(frozen=True)
class RaceEvidence:
    """Unconfirmed delivery evidence, preserving resource provenance and ordering."""

    resource: TargetResource
    delivery_mode: DeliveryMode
    observations: tuple[DeliveryObservation, ...]
    rule: BusinessRule = BusinessRule.SINGLE_USE_REUSE
    baseline: DeliveryObservation | None = None
    violating: DeliveryObservation | None = None

    def to_business_rule(self, *, evidence_ref: str | None = None) -> BusinessRuleEvidence:
        baseline = self.baseline
        violating = self.violating
        if baseline is None or violating is None:
            raise ValueError("race evidence requires explicit baseline and violating observations")
        return BusinessRuleEvidence(
            rule=self.rule,
            baseline=baseline.to_replay(),
            violating=violating.to_replay(),
            evidence_ref=evidence_ref or self.resource.evidence_ref,
        )


class DeliveryRunner(Protocol):
    """Injected transport seam; implementations must preserve execution gates."""

    def deliver(
        self,
        identity: str,
        resource: TargetResource,
        delivery: Delivery,
    ) -> tuple[DeliveryObservation, ...]: ...


class FreshDeliveryProvider(Protocol):
    """Supplies a disposable resource-specific concurrent delivery batch."""

    def __call__(
        self,
        identity: str,
        resource: TargetResource,
        check: TemplateCheck,
        sequential: RaceEvidence,
    ) -> Delivery: ...


class RequestFirerDeliveryRunner:
    """Concurrent delivery adapter through execution-layer ``RequestFirer``.

    A worker barrier releases all concurrent requests together into the client's
    transport. This proves overlapping dispatch in hermetic tests, while every
    request still receives ordinary scope, audit, and read-only-first enforcement.
    It is not a wire-level HTTP/2 single-packet implementation.
    """

    def __init__(self, firer: RequestFirer, *, base_url: str):
        self._firer = firer
        self._base_url = base_url.rstrip("/")

    def _deliver_one(
        self,
        identity: str,
        request: DeliveryRequest,
        *,
        clear_read_only: bool,
        start_barrier: threading.Barrier | None = None,
    ) -> DeliveryObservation:
        kwargs: dict[str, object] = {}
        if request.json_body is not None:
            kwargs["json"] = dict(request.json_body)
        try:
            if start_barrier is not None:
                start_barrier.wait(timeout=5)
            if request.state_changing and clear_read_only:
                self._firer.fire(identity, "GET", self._base_url + request.path)
            result = self._firer.fire(
                identity,
                request.method,
                self._base_url + request.path,
                state_changing=request.state_changing,
                **kwargs,
            )
        except Exception:  # noqa: BLE001 — a delivery error is inconclusive evidence
            return DeliveryObservation(request.label, 0)
        return DeliveryObservation(
            request.label,
            result.status_code,
            result.body.decode("utf-8", errors="replace"),
        )

    def deliver(
        self,
        identity: str,
        resource: TargetResource,
        delivery: Delivery,
    ) -> tuple[DeliveryObservation, ...]:
        del resource
        if delivery.mode is DeliveryMode.SEQUENTIAL:
            return tuple(
                self._deliver_one(identity, request, clear_read_only=True)
                for request in delivery.requests
            )
        if delivery.mode is not DeliveryMode.CONCURRENT:
            raise ValueError(f"unsupported delivery mode: {delivery.mode}")
        if not delivery.requests:
            return ()
        start_barrier = threading.Barrier(len(delivery.requests))
        with ThreadPoolExecutor(max_workers=len(delivery.requests)) as pool:
            futures = [
                pool.submit(
                    self._deliver_one,
                    identity,
                    request,
                    clear_read_only=False,
                    start_barrier=start_barrier,
                )
                for request in delivery.requests
            ]
            return tuple(future.result() for future in futures)


class Http2MultiplexedDeliveryRunner(RequestFirerDeliveryRunner):
    """Concurrent delivery requiring an HTTP/2-configured RequestFirer.

    HTTPX exposes neither a one-packet write primitive nor negotiated-protocol
    certainty before a request. Adapter guarantees concurrent dispatch into an
    HTTP/2-configured client, not wire-level packet coalescing.
    """

    def __init__(self, firer: RequestFirer, *, base_url: str):
        if not firer.http2_enabled:
            raise ValueError("HTTP/2 multiplexed delivery requires an HTTP/2 client")
        super().__init__(firer, base_url=base_url)


def identify_resources(
    graph: ReachabilityGraph, *, identity: str | None = None
) -> tuple[TargetResource, ...]:
    """Instantiate race candidates only from graph-recognized limited resources.

    ``identity`` binds returned resources to a caller whose graph edge can be
    tested; omission is retained for discovery-only reporting.
    """
    result = []
    for check in instantiate_all(graph).checks:
        if check.rule is not BusinessRule.SINGLE_USE_REUSE:
            continue
        endpoint = graph.endpoint(check.resource_ref)
        result.append(
            TargetResource(
                ref=check.resource_ref,
                endpoint_ref=check.resource_ref,
                identity_ref=identity or "",
                method=endpoint.method,
                path=endpoint.path,
                resource_kind=check.rule.value,
                provenance=f"graph:{check.resource_ref}",
                evidence_ref=check.evidence_ref,
            )
        )
    return tuple(result)


def _resource_for_check(
    graph: ReachabilityGraph, check: TemplateCheck, identity: str
) -> TargetResource:
    endpoint = graph.endpoint(check.resource_ref)
    return TargetResource(
        ref=check.resource_ref,
        endpoint_ref=check.resource_ref,
        identity_ref=identity,
        method=endpoint.method,
        path=endpoint.path,
        resource_kind=check.rule.value,
        provenance=f"graph:{check.resource_ref}",
        evidence_ref=check.evidence_ref,
    )


def _violating_request(check: TemplateCheck) -> DeliveryRequest:
    violating = next((step for step in check.steps if step.role is StepRole.VIOLATING), None)
    if violating is None:
        raise ValueError("race probing requires a violating template step")
    return DeliveryRequest.from_step(violating)


def _delivery_from_check(check: TemplateCheck, mode: DeliveryMode) -> Delivery:
    if mode is DeliveryMode.SEQUENTIAL:
        return Delivery(mode, tuple(DeliveryRequest.from_step(step) for step in check.steps))
    violating = _violating_request(check)
    return Delivery(mode, (violating, violating))


def _same_request(left: DeliveryRequest, right: DeliveryRequest) -> bool:
    return (
        left.method.upper() == right.method.upper()
        and left.path == right.path
        and left.state_changing is right.state_changing
        and left.json_body == right.json_body
    )


def _validate_concurrent_delivery(check: TemplateCheck, delivery: Delivery) -> None:
    """Reject batches that cannot represent this check's violating action."""
    if delivery.mode is not DeliveryMode.CONCURRENT:
        raise ValueError("concurrent race delivery must use concurrent mode")
    if len(delivery.requests) < 2:
        raise ValueError("concurrent race delivery needs at least two requests")
    violating = _violating_request(check)
    if not violating.state_changing:
        raise ValueError("concurrent race delivery needs a state-changing violation")
    if not all(request.state_changing for request in delivery.requests):
        raise ValueError("concurrent race delivery requests must be state-changing")
    if not all(
        request.method.upper() == violating.method.upper() and request.path == violating.path
        for request in delivery.requests
    ):
        raise ValueError("concurrent race delivery must target the violating endpoint")
    first = delivery.requests[0]
    if not all(_same_request(request, first) for request in delivery.requests[1:]):
        raise ValueError("concurrent race delivery must duplicate one fresh resource request")


def _observations_match_delivery(
    observations: tuple[DeliveryObservation, ...], delivery: Delivery
) -> bool:
    return Counter(observation.label for observation in observations) == Counter(
        request.label for request in delivery.requests
    )


def _concurrent_violation(
    observations: tuple[DeliveryObservation, ...],
) -> DeliveryObservation:
    """Reduce a concurrent batch only when duplicate mutations both succeed."""
    accepted = tuple(
        observation for observation in observations if 200 <= observation.status_code < 300
    )
    if len(accepted) >= 2:
        return accepted[1]
    refused = tuple(
        observation for observation in observations if 400 <= observation.status_code < 500
    )
    if refused and len(accepted) + len(refused) == len(observations):
        return refused[0]
    return DeliveryObservation("concurrent-inconclusive", 0)


def _sequential_evidence(
    resource: TargetResource,
    check: TemplateCheck,
    observations: tuple[DeliveryObservation, ...],
) -> RaceEvidence:
    by_label = {observation.label: observation for observation in observations}
    baseline_step = next((step for step in check.steps if step.role is StepRole.BASELINE), None)
    violating_step = next((step for step in check.steps if step.role is StepRole.VIOLATING), None)
    baseline = (
        by_label.get(baseline_step.label)
        if baseline_step is not None
        else DeliveryObservation("baseline-missing", 0)
    )
    violating = (
        by_label.get(violating_step.label)
        if violating_step is not None
        else DeliveryObservation("violating-missing", 0)
    )
    return RaceEvidence(
        resource,
        DeliveryMode.SEQUENTIAL,
        observations,
        rule=check.rule,
        baseline=baseline or DeliveryObservation("baseline-missing", 0),
        violating=violating or DeliveryObservation("violating-missing", 0),
    )


def probe_race(
    graph: ReachabilityGraph,
    identity: str,
    check: TemplateCheck,
    runner: DeliveryRunner,
    *,
    concurrent_delivery: Delivery | None = None,
    fresh_delivery_provider: FreshDeliveryProvider | None = None,
    oracle_runner: OracleRunner = registry_runner,
) -> tuple[RaceEvidence, OracleOutcome]:
    """Run sequential replay first; use explicit concurrent delivery only if needed.

    A concurrent batch is opt-in because a target-specific fresh consumable is
    needed after the sequential replay. It must duplicate the instantiated
    violating request and is never attempted after a deterministic serial verdict.
    """
    if check.rule is not BusinessRule.SINGLE_USE_REUSE:
        raise ValueError("race probing requires a single-use resource check")
    if concurrent_delivery is not None and fresh_delivery_provider is not None:
        raise ValueError("provide concurrent_delivery or fresh_delivery_provider, not both")
    resource = _resource_for_check(graph, check, identity)
    if concurrent_delivery is not None:
        _validate_concurrent_delivery(check, concurrent_delivery)
    sequential = _delivery_from_check(check, DeliveryMode.SEQUENTIAL)
    sequential_evidence = _sequential_evidence(
        resource,
        check,
        runner.deliver(identity, resource, sequential),
    )
    sequential_outcome = oracle_runner(
        OracleMechanism.BUSINESS_RULE_INVARIANT,
        sequential_evidence.to_business_rule(evidence_ref=f"{resource.evidence_ref}#sequential"),
    )
    if sequential_outcome.is_violation:
        return sequential_evidence, sequential_outcome
    if fresh_delivery_provider is None and concurrent_delivery is None:
        return sequential_evidence, sequential_outcome
    baseline = sequential_evidence.baseline
    if baseline is None or not 200 <= baseline.status_code < 300:
        return sequential_evidence, sequential_outcome

    if fresh_delivery_provider is not None:
        concurrent_delivery = fresh_delivery_provider(
            identity, resource, check, sequential_evidence
        )
        _validate_concurrent_delivery(check, concurrent_delivery)
    if concurrent_delivery is None:
        return sequential_evidence, sequential_outcome
    concurrent_observations = runner.deliver(identity, resource, concurrent_delivery)
    if not _observations_match_delivery(concurrent_observations, concurrent_delivery):
        concurrent_observations = ()
    concurrent_evidence = RaceEvidence(
        resource,
        DeliveryMode.CONCURRENT,
        concurrent_observations,
        rule=check.rule,
        baseline=sequential_evidence.baseline,
        violating=_concurrent_violation(concurrent_observations),
    )
    concurrent_outcome = oracle_runner(
        OracleMechanism.BUSINESS_RULE_INVARIANT,
        concurrent_evidence.to_business_rule(evidence_ref=f"{resource.evidence_ref}#concurrent"),
    )
    return concurrent_evidence, concurrent_outcome


@dataclass(frozen=True)
class LiveGateConfig:
    """Opt-in PortSwigger race-lab configuration, without credential contents."""

    base_url: str
    session_token: str
    enabled: bool

    @property
    def configured(self) -> bool:
        return self.enabled and bool(self.base_url and self.session_token)


def live_gate_config() -> LiveGateConfig:
    """Read race-lab credentials at test invocation time."""
    return LiveGateConfig(
        base_url=os.environ.get("REACHAGENT_PORTSWIGGER_LAB_URL", ""),
        session_token=os.environ.get("REACHAGENT_PORTSWIGGER_SESSION_TOKEN", ""),
        enabled=os.environ.get("REACHAGENT_PORTSWIGGER_LIVE", "") == "1",
    )


def live_gate_configured() -> bool:
    """Whether opt-in PortSwigger race credentials are present."""
    return live_gate_config().configured
