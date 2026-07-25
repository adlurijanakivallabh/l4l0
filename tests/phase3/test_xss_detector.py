"""Stored and DOM XSS detection tests (plan §7, §9; Phase 3 Task 6).

Covers the Task 6 DoD:
  * EXECUTION_CONFIRMATION oracle is now registered — get_oracle no longer raises.
  * DOM XSS: taint flows confirm via oracle; clean target finds nothing.
  * Stored XSS: write→read-back confirms when tag present; clean read-back finds nothing.
  * Read-only-first (§10): DOM probe fires before any write; stored write fires only
    when DOM did not confirm and a write callback is supplied.
  * Chain Solver enables edge: XSS finding → downstream SSRF finding; chain_paths
    returns the connected path.
  * Full path reaches oracle through run_oracle (mcp.call_tool boundary), not direct
    Playwright call — proven by the BrowserDriver Protocol seam (same as Task 5).
"""

from __future__ import annotations

import pytest

from reachagent.browser.shim import BrowserFireResult, TaintFlow
from reachagent.graph.nodes import Finding, FindingStatus
from reachagent.graph.store import ReachabilityGraph
from reachagent.oracles import OracleMechanism
from reachagent.oracles.execution_confirmation import (
    ExecutionConfirmationEvidence,
    ExecutionConfirmationOracle,
    decide,
)
from reachagent.oracles.registry import get_oracle
from reachagent.xss.detector import DomProbe, StoredProbe, XssProber, detect_xss

# === Oracle unit tests ========================================================


def test_oracle_registered() -> None:
    # Task 5 proved deferral; Task 6 proves it is now built.
    oracle = get_oracle(OracleMechanism.EXECUTION_CONFIRMATION)
    assert isinstance(oracle, ExecutionConfirmationOracle)


def test_decide_dom_flow_confirms() -> None:
    flow = TaintFlow(source="location.hash", sink="innerHTML", url="http://t/p")
    ev = ExecutionConfirmationEvidence(flows=(flow,))
    assert decide(ev) is FindingStatus.CONFIRMED_VIOLATION


def test_decide_no_flows_no_tag_inconclusive() -> None:
    ev = ExecutionConfirmationEvidence()
    assert decide(ev) is FindingStatus.INCONCLUSIVE


def test_decide_tag_in_body_confirms() -> None:
    ev = ExecutionConfirmationEvidence(
        payload_tag="xss-probe-abc123",
        response_body="<p>xss-probe-abc123</p>",
    )
    assert decide(ev) is FindingStatus.CONFIRMED_VIOLATION


def test_decide_tag_absent_inconclusive() -> None:
    ev = ExecutionConfirmationEvidence(
        payload_tag="xss-probe-abc123",
        response_body="<p>safe content</p>",
    )
    assert decide(ev) is FindingStatus.INCONCLUSIVE


def test_oracle_wrong_evidence_type_raises() -> None:
    oracle = ExecutionConfirmationOracle()
    with pytest.raises(TypeError):
        oracle.run({"flows": []})


def test_oracle_verdict_is_violation_on_flow() -> None:
    flow = TaintFlow(source="postMessage", sink="eval", url="http://t/p")
    ev = ExecutionConfirmationEvidence(flows=(flow,), evidence_ref="xss/dom/test")
    verdict = ExecutionConfirmationOracle().run(ev)
    assert verdict.is_violation is True
    assert verdict.mechanism is OracleMechanism.EXECUTION_CONFIRMATION
    assert verdict.evidence_ref == "xss/dom/test"


# === DOM XSS detector =========================================================


def _dom_prober(flows: list[dict] | None = None) -> XssProber:
    """Prober whose DOM probe returns the given flows (no stored callback)."""
    flow_objs = tuple(
        TaintFlow(
            source=f["source"],
            sink=f["sink"],
            url=f.get("url", "http://target/page"),
        )
        for f in (flows or [])
    )
    result = BrowserFireResult(
        url="http://target/page",
        identity="user",
        flows=flow_objs,
        shim_installed=True,
    )

    def fire_dom() -> DomProbe:
        return DomProbe(result=result)

    return XssProber(fire_dom=fire_dom)


def test_dom_xss_confirms_on_taint_flow() -> None:
    prober = _dom_prober(flows=[{"source": "location.hash", "sink": "innerHTML"}])
    result = detect_xss(prober, evidence_ref="xss/dom/1")
    assert result.confirmed is True
    assert result.xss_type == "dom"
    assert len(result.flows) == 1
    assert result.flows[0].sink == "innerHTML"


def test_dom_xss_clean_target_finds_nothing() -> None:
    # Full discovery path: shim installed, navigation happened, no flows.
    prober = _dom_prober(flows=[])
    result = detect_xss(prober, evidence_ref="xss/dom/clean")
    assert result.confirmed is False
    assert result.xss_type is None
    assert result.flows == ()


def test_dom_xss_multiple_flows_all_returned() -> None:
    prober = _dom_prober(
        flows=[
            {"source": "location.hash", "sink": "innerHTML"},
            {"source": "postMessage", "sink": "eval"},
        ]
    )
    result = detect_xss(prober)
    assert result.confirmed is True
    assert len(result.flows) == 2


# === Stored XSS detector ======================================================


def _stored_prober(
    *,
    dom_flows: list[dict] | None = None,
    tag_in_body: bool = False,
    tag: str = "xss-tag-deadbeef",
) -> XssProber:
    """Prober with both DOM (no flows by default) and stored callbacks."""
    dom_result = BrowserFireResult(
        url="http://target/page",
        identity="user",
        flows=tuple(
            TaintFlow(source=f["source"], sink=f["sink"], url="http://target/page")
            for f in (dom_flows or [])
        ),
        shim_installed=True,
    )

    def fire_dom() -> DomProbe:
        return DomProbe(result=dom_result)

    def fire_stored() -> StoredProbe:
        body = f"<p>{tag}</p>" if tag_in_body else "<p>safe</p>"
        return StoredProbe(payload_tag=tag, readback_body=body, write_logged=True)

    return XssProber(fire_dom=fire_dom, fire_stored=fire_stored)


def test_stored_xss_confirms_when_tag_in_readback() -> None:
    prober = _stored_prober(tag_in_body=True)
    result = detect_xss(prober, evidence_ref="xss/stored/1")
    assert result.confirmed is True
    assert result.xss_type == "stored"


def test_stored_xss_clean_readback_finds_nothing() -> None:
    prober = _stored_prober(tag_in_body=False)
    result = detect_xss(prober, evidence_ref="xss/stored/clean")
    assert result.confirmed is False
    assert result.xss_type is None


def test_dom_confirmed_skips_stored_path() -> None:
    """Read-only-first (§10): stored write must not fire when DOM already confirmed."""
    stored_fired: list[bool] = []

    dom_result = BrowserFireResult(
        url="http://t/p",
        identity="u",
        flows=(TaintFlow(source="location.hash", sink="innerHTML", url="http://t/p"),),
        shim_installed=True,
    )

    def fire_dom() -> DomProbe:
        return DomProbe(result=dom_result)

    def fire_stored() -> StoredProbe:
        stored_fired.append(True)
        return StoredProbe(payload_tag="t", readback_body="<p>t</p>", write_logged=True)

    prober = XssProber(fire_dom=fire_dom, fire_stored=fire_stored)
    result = detect_xss(prober)
    assert result.confirmed is True
    assert result.xss_type == "dom"
    assert stored_fired == []  # write never fired


def test_no_stored_callback_dom_only_mode() -> None:
    """When no write callback supplied, stored path is skipped entirely."""
    prober = _dom_prober(flows=[])  # no stored callback
    result = detect_xss(prober)
    assert result.confirmed is False


# === Chain Solver enables edge ================================================


def _committed_finding(graph: ReachabilityGraph, vuln_class: str, ref: str) -> str:
    """Write a confirmed finding directly into the graph and return its id."""
    finding = Finding(
        vuln_class=vuln_class,
        severity="high",
        oracle_used=OracleMechanism.EXECUTION_CONFIRMATION,
        evidence_ref=ref,
        status=FindingStatus.CONFIRMED_VIOLATION,
    )
    return graph.add_finding(finding)


def test_chain_solver_enables_edge_xss_to_ssrf() -> None:
    """XSS finding enables downstream SSRF finding; chain_paths returns connected path."""
    from reachagent.graph.chain_solver import ChainSolver

    graph = ReachabilityGraph()
    xss_id = _committed_finding(graph, "xss", "xss/stored/chain-test")
    ssrf_id = _committed_finding(graph, "ssrf", "ssrf/metadata/chain-test")

    solver = ChainSolver(graph)
    solver.link(xss_id, ssrf_id)

    edges = graph.enables_edges()
    assert (xss_id, ssrf_id) in edges

    paths = graph.chain_paths(xss_id)
    assert len(paths) == 1
    assert paths[0] == (xss_id, ssrf_id)


def test_chain_paths_empty_when_no_enables_edge() -> None:
    graph = ReachabilityGraph()
    xss_id = _committed_finding(graph, "xss", "xss/dom/isolated")
    paths = graph.chain_paths(xss_id)
    assert paths == []
