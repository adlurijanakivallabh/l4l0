"""Business-logic 4-template invariant library (plan §5, §7, §9).

Exactly four templates — single-use reuse, quantity/limit, price/parameter
tamper, and step-order — matching the four the ``business_rule_invariant`` §7
family names. CLAUDE.md forbids growing the family set without a plan change,
so the count is asserted by a test and the :class:`~reachagent.oracles.
business_rule.BusinessRule` enum is the single source of truth for "which four".

A template is **not** a hand-written per-target check. It is a *recognizer*: it
inspects the reachability graph for a resource of its shape — a coupon/token
parameter, a quantity/limit parameter, a priced parameter/object, or an ordered
multi-step flow — that recon already materialized, and only then emits a concrete
:class:`TemplateCheck`. A surface with no matching resource yields no check
(empirical-or-absent, mirroring ``owns``/``can_call``). The recognizers key off
*generic* commerce vocabulary (``coupon``, ``quantity``, ``price``, …), never a
target-specific name, so the library stays generic across targets.

Recognition emits a *plan*; it fires nothing. The
:class:`~reachagent.business_logic.runner.SequentialReplayRunner` executes the
plan as a sequential replay under read-only-first, and the deterministic
business-rule oracle (not this module, and never an LLM) decides the verdict.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from enum import StrEnum

from reachagent.graph.nodes import Endpoint, Object, Parameter
from reachagent.graph.store import ReachabilityGraph
from reachagent.oracles.business_rule import BusinessRule


class StepRole(StrEnum):
    """Whether a replay step establishes the legitimate baseline or breaks the rule.

    The runner reduces a fired check to one baseline observation (the legitimate
    action a secure app accepts) and one violating observation (the rule-breaking
    action it must refuse) — the two the business-rule oracle diffs.
    """

    SETUP = "setup"  # a prerequisite whose own outcome is not the invariant
    BASELINE = "baseline"  # the legitimate action; a secure app accepts it (2xx)
    VIOLATING = "violating"  # the rule-breaking action; a secure app must refuse it


@dataclass(frozen=True)
class ReplayStep:
    """One request in a sequential replay, fully specified so the runner just fires it.

    ``json_body`` is the request payload (``None`` for a bodyless read). The step
    declares its own ``state_changing`` flag so the runner gates it behind
    read-only-first (§10) exactly as the firer does — the library never smuggles a
    mutation past the safety gate.
    """

    label: str
    role: StepRole
    method: str
    path: str
    state_changing: bool = False
    json_body: Mapping[str, object] | None = None


@dataclass(frozen=True)
class TemplateCheck:
    """A concrete, instantiated business-logic check: the ordered steps to replay.

    ``resource_ref`` is the graph node id the check instantiated from, so a
    confirmation traces back to the recon-discovered resource that triggered it.
    ``steps`` is ordered: zero or more ``SETUP``/``BASELINE`` steps, then exactly
    one ``VIOLATING`` step last — the sequential replay the runner fires.
    """

    rule: BusinessRule
    resource_ref: str
    evidence_ref: str
    steps: tuple[ReplayStep, ...]


# -- generic resource vocabulary (no target-specific names) ----------------
# Word-boundary matched against a parameter/object name, case-insensitively.
# These are generic commerce shapes, not per-target identifiers, so the grep-
# clean discipline (no target names in the library) holds.
_COUPON_HINTS = re.compile(r"\b(coupon|voucher|promo|giftcard|gift_card|redeem|token)\b", re.I)
_QUANTITY_HINTS = re.compile(r"\b(quantity|qty|amount|count|limit|quota|units?)\b", re.I)
_PRICE_HINTS = re.compile(r"\b(price|cost|total|subtotal|charge|fee)\b", re.I)


def _name_matches(name: str, pattern: re.Pattern[str]) -> bool:
    # Match the underscore/camel word too: split on non-alphanumerics first so a
    # `couponCode`/`coupon_code` field is recognized by the `coupon` hint.
    spaced = re.sub(r"[_\W]+", " ", name)
    return bool(pattern.search(name) or pattern.search(spaced))


def _params_with(
    graph: ReachabilityGraph, pattern: re.Pattern[str]
) -> list[tuple[str, str, Endpoint, Parameter]]:
    """Every (endpoint_id, param_id, Endpoint, Parameter) whose param name matches.

    Reads only what recon materialized — the endpoints and their ``accepts``
    parameters — so a template can instantiate solely from graph resources.
    """
    hits: list[tuple[str, str, Endpoint, Parameter]] = []
    for endpoint_id, endpoint in graph.endpoints():
        for param_id, param in graph.parameters_of(endpoint_id):
            if _name_matches(param.name, pattern):
                hits.append((endpoint_id, param_id, endpoint, param))
    return hits


def _objects_with(graph: ReachabilityGraph, pattern: re.Pattern[str]) -> list[tuple[str, Object]]:
    """Every (object_id, Object) whose type name matches ``pattern``."""
    return [(oid, obj) for oid, obj in graph.objects() if _name_matches(obj.type, pattern)]


class Template:
    """Base recognizer: inspect the graph, emit zero or more concrete checks.

    A template holds no target knowledge and fires nothing. ``instantiate`` is a
    pure read of the graph — the same discipline as recon's ``map_structure``.
    """

    rule: BusinessRule

    def instantiate(self, graph: ReachabilityGraph) -> list[TemplateCheck]:
        raise NotImplementedError


class SingleUseReuseTemplate(Template):
    """A single-use token/coupon must be redeemable once; a second redemption fails."""

    rule = BusinessRule.SINGLE_USE_REUSE

    def instantiate(self, graph: ReachabilityGraph) -> list[TemplateCheck]:
        checks: list[TemplateCheck] = []
        for endpoint_id, _pid, endpoint, param in _params_with(graph, _COUPON_HINTS):
            # A redemption is an action, so only a state-changing endpoint is a
            # real single-use surface — a read-only "check my coupon" isn't reuse.
            if endpoint.method.upper() in ("GET", "HEAD", "OPTIONS"):
                continue
            body = {param.name: f"sample-{param.name}"}
            checks.append(
                TemplateCheck(
                    rule=self.rule,
                    resource_ref=endpoint_id,
                    evidence_ref=f"single_use/{endpoint.method} {endpoint.path}/{param.name}",
                    steps=(
                        ReplayStep(
                            "first-redeem",
                            StepRole.BASELINE,
                            endpoint.method,
                            endpoint.path,
                            state_changing=True,
                            json_body=body,
                        ),
                        # Identical replay: a secure app rejects the second use.
                        ReplayStep(
                            "reuse",
                            StepRole.VIOLATING,
                            endpoint.method,
                            endpoint.path,
                            state_changing=True,
                            json_body=body,
                        ),
                    ),
                )
            )
        return checks


class QuantityLimitTemplate(Template):
    """A quantity/limit parameter must be bounded; an out-of-bounds value is refused."""

    rule = BusinessRule.QUANTITY_LIMIT

    def instantiate(self, graph: ReachabilityGraph) -> list[TemplateCheck]:
        checks: list[TemplateCheck] = []
        for endpoint_id, _pid, endpoint, param in _params_with(graph, _QUANTITY_HINTS):
            if endpoint.method.upper() in ("GET", "HEAD", "OPTIONS"):
                continue
            checks.append(
                TemplateCheck(
                    rule=self.rule,
                    resource_ref=endpoint_id,
                    evidence_ref=f"quantity_limit/{endpoint.method} {endpoint.path}/{param.name}",
                    steps=(
                        ReplayStep(
                            "in-bounds",
                            StepRole.BASELINE,
                            endpoint.method,
                            endpoint.path,
                            state_changing=True,
                            json_body={param.name: 1},
                        ),
                        # A negative quantity is the canonical out-of-bounds probe
                        # (refund abuse / free goods); a secure app rejects it.
                        ReplayStep(
                            "out-of-bounds",
                            StepRole.VIOLATING,
                            endpoint.method,
                            endpoint.path,
                            state_changing=True,
                            json_body={param.name: -1},
                        ),
                    ),
                )
            )
        return checks


class PriceTamperTemplate(Template):
    """A client-supplied price must not be honored; a tampered price is refused."""

    rule = BusinessRule.PRICE_TAMPER

    def instantiate(self, graph: ReachabilityGraph) -> list[TemplateCheck]:
        checks: list[TemplateCheck] = []
        for endpoint_id, _pid, endpoint, param in _params_with(graph, _PRICE_HINTS):
            if endpoint.method.upper() in ("GET", "HEAD", "OPTIONS"):
                continue
            checks.append(
                TemplateCheck(
                    rule=self.rule,
                    resource_ref=endpoint_id,
                    evidence_ref=f"price_tamper/{endpoint.method} {endpoint.path}/{param.name}",
                    steps=(
                        ReplayStep(
                            "real-price",
                            StepRole.BASELINE,
                            endpoint.method,
                            endpoint.path,
                            state_changing=True,
                            json_body={param.name: 100},
                        ),
                        # Tamper the price down to a token amount; a secure app
                        # recomputes server-side and refuses the client's figure.
                        ReplayStep(
                            "tampered-price",
                            StepRole.VIOLATING,
                            endpoint.method,
                            endpoint.path,
                            state_changing=True,
                            json_body={param.name: 1},
                        ),
                    ),
                )
            )
        return checks


class StepOrderTemplate(Template):
    """A later workflow step must not be reachable without its prerequisite step.

    Runtime-dependent surface (same pattern as ownership discovery, §6/Task 2):
    the ordered flow is **not** read from a static field. This recognizer only
    proposes the *candidate* flow — the ordered state-changing endpoints recon
    materialized — and marks the final step ``VIOLATING`` to be fired without its
    prerequisites. Whether that jump is actually a violation is read from the
    app's own response by the oracle; the runner discovers empirically whether the
    earlier steps were even needed. A surface with fewer than two ordered
    state-changing steps has no flow, so nothing instantiates.
    """

    rule = BusinessRule.STEP_ORDER

    def instantiate(self, graph: ReachabilityGraph) -> list[TemplateCheck]:
        flow = self._candidate_flow(graph.endpoints())
        if len(flow) < 2:
            return []
        *prerequisites, last = flow
        steps = [
            ReplayStep(
                f"prereq:{ep.method} {ep.path}",
                StepRole.SETUP,
                ep.method,
                ep.path,
                state_changing=True,
            )
            for _eid, ep in prerequisites
        ]
        # Fire the final step *without* having satisfied the prerequisites — the
        # baseline is the prerequisites' reachability, the violation is the jump.
        last_id, last_ep = last
        steps.append(
            ReplayStep(
                "skip-to-last",
                StepRole.VIOLATING,
                last_ep.method,
                last_ep.path,
                state_changing=True,
            )
        )
        # Mark the last prerequisite as the legitimate baseline the oracle diffs.
        if steps and steps[0].role is StepRole.SETUP:
            steps[-2] = ReplayStep(
                steps[-2].label,
                StepRole.BASELINE,
                steps[-2].method,
                steps[-2].path,
                state_changing=True,
            )
        return [
            TemplateCheck(
                rule=self.rule,
                resource_ref=last_id,
                evidence_ref=f"step_order/{last_ep.method} {last_ep.path}",
                steps=tuple(steps),
            )
        ]

    @staticmethod
    def _candidate_flow(endpoints: Iterable[tuple[str, Endpoint]]) -> list[tuple[str, Endpoint]]:
        """The ordered state-changing endpoints that could form a multi-step flow.

        Ordered by path so a stable, deterministic candidate sequence emerges from
        whatever recon materialized — read-only endpoints are not workflow steps,
        so they are excluded.
        """
        state_changing = [
            (eid, ep)
            for eid, ep in endpoints
            if ep.method.upper() not in ("GET", "HEAD", "OPTIONS")
        ]
        return sorted(state_changing, key=lambda item: (item[1].path, item[1].method))


# The four templates — no more, no fewer. Adding a fifth requires adding a
# BusinessRule member first (a plan-change tripwire), which the library test guards.
TEMPLATES: tuple[Template, ...] = (
    SingleUseReuseTemplate(),
    QuantityLimitTemplate(),
    PriceTamperTemplate(),
    StepOrderTemplate(),
)


@dataclass(frozen=True)
class InstantiationResult:
    """Every check the library produced against a graph, plus which rules fired."""

    checks: tuple[TemplateCheck, ...] = field(default_factory=tuple)

    @property
    def rules(self) -> frozenset[BusinessRule]:
        return frozenset(c.rule for c in self.checks)


def instantiate_all(graph: ReachabilityGraph) -> InstantiationResult:
    """Run every template against the graph and collect the concrete checks.

    Generic by construction: each template reads only graph resources, so a
    surface with no consumable/limited/priced/ordered resource yields no checks.
    """
    checks: list[TemplateCheck] = []
    for template in TEMPLATES:
        checks.extend(template.instantiate(graph))
    return InstantiationResult(checks=tuple(checks))
