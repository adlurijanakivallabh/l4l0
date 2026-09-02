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

from reachagent.browser.shim import BrowserFireResult, TaintFlow
from reachagent.graph.nodes import Finding, FindingStatus
from reachagent.graph.store import ReachabilityGraph
from reachagent.oracles import OracleMechanism
from reachagent.xss.detector import DomProbe, StoredProbe, XssProber, detect_xss
from tests._oracle_test_support import CONFIRMS, INCONCLUSIVE, fixed_oracle_runner

# === DOM XSS detector =========================================================
#
# v3 (CLAUDE.md): decide() is gone — confirmation is now an LLM judgment, not
# something a hermetic test can re-derive deterministically. These tests now
# assert on DETECTOR WIRING (does it correctly relay a fixed verdict into
# `.confirmed`/`.xss_type`) via an injected `oracle_runner`, not on judgment
# itself.


def _dom_prober(flows: list[dict] | None = None, *, status=CONFIRMS) -> XssProber:
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

    return XssProber(fire_dom=fire_dom, oracle_runner=fixed_oracle_runner(status))


def test_dom_xss_confirms_on_taint_flow() -> None:
    prober = _dom_prober(flows=[{"source": "location.hash", "sink": "innerHTML"}], status=CONFIRMS)
    result = detect_xss(prober, evidence_ref="xss/dom/1")
    assert result.confirmed is True
    assert result.xss_type == "dom"
    assert len(result.flows) == 1
    assert result.flows[0].sink == "innerHTML"


def test_dom_xss_clean_target_finds_nothing() -> None:
    # Full discovery path: shim installed, navigation happened, no flows.
    prober = _dom_prober(flows=[], status=INCONCLUSIVE)
    result = detect_xss(prober, evidence_ref="xss/dom/clean")
    assert result.confirmed is False
    assert result.xss_type is None
    assert result.flows == ()


def test_dom_xss_multiple_flows_all_returned() -> None:
    prober = _dom_prober(
        flows=[
            {"source": "location.hash", "sink": "innerHTML"},
            {"source": "postMessage", "sink": "eval"},
        ],
        status=CONFIRMS,
    )
    result = detect_xss(prober)
    assert result.confirmed is True
    assert len(result.flows) == 2


# === Stored XSS detector ======================================================


def _dom_then_stored_runner(stored_status):
    """Oracle runner that never confirms DOM evidence but returns ``stored_status``
    for stored (payload_tag) evidence.

    ``fixed_oracle_runner`` alone can't express this: the DOM probe and the
    stored probe share one ``oracle_runner`` field, so a single fixed status
    would confirm (or deny) both calls identically. Dispatching on
    ``evidence.payload_tag`` (only stored evidence sets it) lets the DOM leg
    behave as it would with no taint flows (never confirmed) while the stored
    leg's verdict is the one under test.
    """
    dom_runner = fixed_oracle_runner(INCONCLUSIVE)
    stored_runner = fixed_oracle_runner(stored_status)

    def _runner(mechanism, evidence):
        if evidence.payload_tag:
            return stored_runner(mechanism, evidence)
        return dom_runner(mechanism, evidence)

    return _runner


def _stored_prober(
    *,
    dom_flows: list[dict] | None = None,
    tag_in_body: bool = False,
    tag: str = "xss-tag-deadbeef",
    status=CONFIRMS,
) -> XssProber:
    """Prober with both DOM (no flows by default) and stored callbacks.

    ``status`` is the fixed oracle verdict for the stored probe; the DOM probe
    (no flows by default) always comes back inconclusive.
    """
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

    return XssProber(
        fire_dom=fire_dom, fire_stored=fire_stored, oracle_runner=_dom_then_stored_runner(status)
    )


def test_stored_xss_confirms_when_tag_in_readback() -> None:
    prober = _stored_prober(tag_in_body=True, status=CONFIRMS)
    result = detect_xss(prober, evidence_ref="xss/stored/1")
    assert result.confirmed is True
    assert result.xss_type == "stored"


def test_stored_xss_clean_readback_finds_nothing() -> None:
    prober = _stored_prober(tag_in_body=False, status=INCONCLUSIVE)
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

    prober = XssProber(
        fire_dom=fire_dom, fire_stored=fire_stored, oracle_runner=fixed_oracle_runner(CONFIRMS)
    )
    result = detect_xss(prober)
    assert result.confirmed is True
    assert result.xss_type == "dom"
    assert stored_fired == []  # write never fired


def test_no_stored_callback_dom_only_mode() -> None:
    """When no write callback supplied, stored path is skipped entirely."""
    prober = _dom_prober(flows=[], status=INCONCLUSIVE)  # no stored callback
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
