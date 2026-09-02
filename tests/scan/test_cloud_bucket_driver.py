"""Hermetic E2E for the cloud-bucket-exposure driver: generated bucket-name
guesses against a single read-only GET per candidate.

Uses httpx.MockTransport directly (not RequestFirer) since
run_cloud_bucket_exposure deliberately probes third-party hosts outside the
scanned target's own scope — see the docstring in orchestrator.py, same
reasoning as run_subdomain_takeover.
"""

from __future__ import annotations

import httpx

from reachagent.graph.nodes import Host
from reachagent.graph.store import ReachabilityGraph
from reachagent.scan.orchestrator import _ValidatorSeam, run_cloud_bucket_exposure
from tests._oracle_test_support import CONFIRMS, FixedJudgmentClient

_S3_MARKER = "<ListBucketResult"


def _graph_with_host(hostname: str) -> ReachabilityGraph:
    graph = ReachabilityGraph()
    graph.add_host(Host(address=hostname, hostname=hostname))
    return graph


def _run(handler: object, graph: ReachabilityGraph) -> list:
    seam = _ValidatorSeam(graph)
    run_cloud_bucket_exposure(
        graph=graph,
        seam=seam,
        events=[],
        transport=httpx.MockTransport(handler),  # type: ignore[arg-type]
    )
    return graph.findings()


def test_a_publicly_listable_generated_bucket_confirms_a_finding(monkeypatch) -> None:  # noqa: ANN001
    """Confirmation is now an LLM judgment (v3, CLAUDE.md) rather than a fixed
    decide(); _ValidatorSeam.run calls tools.validator.run_oracle with no
    client= passthrough, so pin the verdict by monkeypatching the client
    builder it constructs internally."""
    import reachagent.oracles.llm_judgment as _llm_judgment

    monkeypatch.setattr(
        _llm_judgment, "build_openai_compatible_client", lambda: FixedJudgmentClient(CONFIRMS.value)
    )

    def handler(request: httpx.Request) -> httpx.Response:
        if "testfire" in request.url.host and request.url.host.endswith("s3.amazonaws.com"):
            return httpx.Response(200, text=f"<?xml?>{_S3_MARKER}<Name>testfire</Name>")
        return httpx.Response(404, text="<Error><Code>NoSuchBucket</Code></Error>")

    graph = _graph_with_host("demo.testfire.net")
    findings = _run(handler, graph)
    classes = {f.vuln_class for _fid, f in findings}
    assert "cloud_bucket_exposure" in classes
    assert all(f.status.value == "confirmed_violation" for _fid, f in findings)


def test_no_exposed_bucket_yields_no_findings() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, text="<Error><Code>NoSuchBucket</Code></Error>")

    graph = _graph_with_host("demo.testfire.net")
    assert _run(handler, graph) == []


def test_no_hosts_in_graph_never_crashes() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError("must not probe anything when the graph has no hosts")

    assert _run(handler, ReachabilityGraph()) == []
