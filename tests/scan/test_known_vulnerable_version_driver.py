"""Hermetic E2E for the known-vulnerable-version driver: fingerprinted
Host.technology/detected_version -> (mocked) NVD lookup -> live re-probe
confirms the version string is still genuinely present.

lookup_cves/enrich_with_epss are monkeypatched — this driver's own network
behavior is covered by tests/cve_intel/test_nvd_client.py; this file only
proves the orchestrator wiring (graph read, not-applicable paths, oracle
gate, metadata/severity derivation).
"""

from __future__ import annotations

import httpx

from reachagent.cve_intel.nvd_client import CveMatch
from reachagent.execution import RequestFirer, ScopeGuard
from reachagent.graph.nodes import Host
from reachagent.graph.store import ReachabilityGraph
from reachagent.scan.orchestrator import _ValidatorSeam, run_known_vulnerable_version

_HOST = "kvv.test"
_MATCHES = (
    CveMatch(
        cve_id="CVE-2019-0232",
        cvss_score=9.8,
        severity="critical",
        summary="x",
        epss_score=0.9,
    ),
)


def _firer(handler: object) -> RequestFirer:
    client = httpx.Client(transport=httpx.MockTransport(handler))  # type: ignore[arg-type]
    return RequestFirer(client, ScopeGuard.from_hosts([_HOST]))


def _graph(technology: str = "Apache Tomcat", version: str = "7.0.92") -> ReachabilityGraph:
    graph = ReachabilityGraph()
    graph.add_host(
        Host(address=_HOST, hostname=_HOST, technology=technology, detected_version=version)
    )
    return graph


def _run(handler: object, graph: ReachabilityGraph, monkeypatch, matches=_MATCHES) -> list:  # noqa: ANN001
    monkeypatch.setattr(
        "reachagent.cve_intel.nvd_client.lookup_cves", lambda *a, **kw: list(matches)
    )
    monkeypatch.setattr(
        "reachagent.cve_intel.nvd_client.enrich_with_epss", lambda ms, **kw: list(ms)
    )
    seam = _ValidatorSeam(graph)
    run_known_vulnerable_version(
        graph=graph,
        firer=_firer(handler),
        base_url=f"http://{_HOST}",
        identity="anon",
        seam=seam,
        events=[],
    )
    return graph.findings()


def test_version_string_present_in_live_response_confirms_a_finding(monkeypatch) -> None:  # noqa: ANN001
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, text="<h1>404</h1><address>Apache Tomcat/7.0.92</address>")

    findings = _run(handler, _graph(), monkeypatch)
    assert len(findings) == 1
    _fid, finding = findings[0]
    assert finding.vuln_class == "known_vulnerable_version"
    assert finding.severity == "critical"
    assert "CVE-2019-0232" in finding.metadata["cve_ids"]
    assert "0.900" in finding.metadata["epss_scores"]


def test_version_string_absent_from_live_response_yields_no_finding(monkeypatch) -> None:  # noqa: ANN001
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="server has been patched")

    assert _run(handler, _graph(), monkeypatch) == []


def test_no_cve_matches_yields_no_finding_and_no_probe(monkeypatch) -> None:  # noqa: ANN001
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(200, text="Apache Tomcat/7.0.92")

    assert _run(handler, _graph(), monkeypatch, matches=()) == []
    assert calls["n"] == 0


def test_no_fingerprint_in_graph_yields_no_finding_and_no_lookup(monkeypatch) -> None:  # noqa: ANN001
    calls = {"n": 0}
    monkeypatch.setattr(
        "reachagent.cve_intel.nvd_client.lookup_cves",
        lambda *a, **kw: (calls.__setitem__("n", calls["n"] + 1), [])[1],
    )

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="ok")

    graph = ReachabilityGraph()  # no Host at all
    seam = _ValidatorSeam(graph)
    run_known_vulnerable_version(
        graph=graph,
        firer=_firer(handler),
        base_url=f"http://{_HOST}",
        identity="anon",
        seam=seam,
        events=[],
    )
    assert graph.findings() == []
    assert calls["n"] == 0


def test_lower_cvss_score_maps_to_lower_severity(monkeypatch) -> None:  # noqa: ANN001
    medium_matches = (
        CveMatch(cve_id="CVE-2020-0001", cvss_score=5.0, severity="medium", summary="x"),
    )

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="Apache Tomcat/7.0.92")

    findings = _run(handler, _graph(), monkeypatch, matches=medium_matches)
    assert len(findings) == 1
    _fid, finding = findings[0]
    assert finding.severity == "medium"
