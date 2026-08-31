"""Hermetic E2E for the subdomain-takeover driver: dangling-CNAME fingerprint
match against a single read-only GET to the CNAME target.

Uses httpx.MockTransport directly (not RequestFirer) since run_subdomain_takeover
deliberately probes a third-party host outside the scanned target's own scope —
see the docstring in orchestrator.py for why.
"""

from __future__ import annotations

import httpx

from reachagent.graph.nodes import Host
from reachagent.graph.store import ReachabilityGraph
from reachagent.scan.orchestrator import _ValidatorSeam, run_subdomain_takeover

_MARKER = "The specified bucket does not exist"


def _graph_with_cname(cname: str | None) -> ReachabilityGraph:
    graph = ReachabilityGraph()
    graph.add_host(
        Host(address="forgotten.target.test", hostname="forgotten.target.test", cname=cname)
    )
    return graph


def _run(handler: object, graph: ReachabilityGraph) -> list:
    seam = _ValidatorSeam(graph)
    run_subdomain_takeover(
        graph=graph,
        seam=seam,
        events=[],
        transport=httpx.MockTransport(handler),  # type: ignore[arg-type]
    )
    return graph.findings()


def test_dangling_cname_with_matching_fingerprint_confirms_a_finding() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text=f"<Error>{_MARKER}</Error>")

    graph = _graph_with_cname("forgotten-bucket.s3.amazonaws.com")
    findings = _run(handler, graph)
    classes = {f.vuln_class for _fid, f in findings}
    assert "subdomain_takeover" in classes
    assert all(f.status.value == "confirmed_violation" for _fid, f in findings)


def test_claimed_cname_target_is_not_confirmed() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="<html>a real, claimed bucket site</html>")

    graph = _graph_with_cname("claimed-bucket.s3.amazonaws.com")
    assert _run(handler, graph) == []


def test_cname_target_with_no_known_fingerprint_never_fires_a_probe() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError("must not probe a CNAME target with no known fingerprint")

    graph = _graph_with_cname("api.some-unrelated-vendor.example.com")
    assert _run(handler, graph) == []


def test_no_hosts_have_a_cname_is_not_applicable_and_never_crashes() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError("must not probe anything when no host has a CNAME")

    graph = _graph_with_cname(None)
    assert _run(handler, graph) == []
