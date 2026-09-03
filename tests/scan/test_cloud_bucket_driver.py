"""Hermetic E2E for the cloud-bucket-exposure driver: generated bucket-name
guesses against a single read-only GET per candidate.

Uses httpx.MockTransport directly (not RequestFirer) since
run_cloud_bucket_exposure deliberately probes third-party hosts outside the
scanned target's own scope — see the docstring in orchestrator.py, same
reasoning as run_subdomain_takeover.
"""

from __future__ import annotations

import httpx

import reachagent.scan.orchestrator as _orchestrator
from reachagent.detection.oracle_gateway import OracleOutcome
from reachagent.graph.nodes import Host
from reachagent.graph.store import ReachabilityGraph
from reachagent.oracles.base import OracleVerdict
from reachagent.scan.orchestrator import _ValidatorSeam, run_cloud_bucket_exposure
from tests._oracle_test_support import CONFIRMS, INCONCLUSIVE, FixedJudgmentClient

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
    # v3 V3: the corroborating delayed re-read sleeps a real
    # _CLOUD_BUCKET_REREAD_DELAY_S before firing — zero it out so this test
    # pays no wall-clock cost for a delay whose only purpose is real-scan
    # realism, not test correctness.
    monkeypatch.setattr(_orchestrator, "_CLOUD_BUCKET_REREAD_DELAY_S", 0.0)

    def handler(request: httpx.Request) -> httpx.Response:
        if "testfire" in request.url.host and request.url.host.endswith("s3.amazonaws.com"):
            return httpx.Response(200, text=f"<?xml?>{_S3_MARKER}<Name>testfire</Name>")
        return httpx.Response(404, text="<Error><Code>NoSuchBucket</Code></Error>")

    graph = _graph_with_host("demo.testfire.net")
    findings = _run(handler, graph)
    classes = {f.vuln_class for _fid, f in findings}
    assert "cloud_bucket_exposure" in classes
    assert all(f.status.value == "confirmed_violation" for _fid, f in findings)
    assert all(f.metadata.get("corroborated") == "1" for _fid, f in findings)


def _lockout_free_run(self: _ValidatorSeam, mechanism: object, evidence: object) -> OracleOutcome:
    """v3 V3: judges on whether the S3 marker is present in the evidence's own
    response_body — lets a test give the immediate probe and the delayed
    re-read genuinely different verdicts (the immediate probe always sees the
    marker; the re-read's body is injected per-test)."""
    body = getattr(evidence, "response_body", "") or ""
    status = CONFIRMS if _S3_MARKER in body else INCONCLUSIVE
    ref = str(getattr(evidence, "evidence_ref", "") or "")
    verdict = OracleVerdict(mechanism=mechanism, status=status, evidence_ref=ref, reason="test")
    self._last = verdict
    return OracleOutcome(verdict)


def test_delayed_reread_confirms_the_exposure_persists(monkeypatch) -> None:  # noqa: ANN001
    monkeypatch.setattr(_ValidatorSeam, "run", _lockout_free_run)
    monkeypatch.setattr(_orchestrator, "_CLOUD_BUCKET_REREAD_DELAY_S", 0.0)

    def handler(request: httpx.Request) -> httpx.Response:
        if "testfire" in request.url.host and request.url.host.endswith("s3.amazonaws.com"):
            return httpx.Response(200, text=f"<?xml?>{_S3_MARKER}<Name>testfire</Name>")
        return httpx.Response(404, text="<Error><Code>NoSuchBucket</Code></Error>")

    graph = _graph_with_host("demo.testfire.net")
    findings = _run(handler, graph)
    [(_fid, finding)] = findings
    assert finding.vuln_class == "cloud_bucket_exposure"
    assert finding.metadata.get("corroborated") == "1"


def test_delayed_reread_no_longer_exposed_fails_closed(monkeypatch) -> None:  # noqa: ANN001
    """A candidate that was exposed on the first probe but locked down by the
    delayed re-read must NOT be confirmed — the whole point of this
    corroboration is ruling out a transient exposure window."""
    monkeypatch.setattr(_ValidatorSeam, "run", _lockout_free_run)
    monkeypatch.setattr(_orchestrator, "_CLOUD_BUCKET_REREAD_DELAY_S", 0.0)
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        if "testfire" in request.url.host and request.url.host.endswith("s3.amazonaws.com"):
            calls["n"] += 1
            if calls["n"] == 1:
                return httpx.Response(200, text=f"<?xml?>{_S3_MARKER}<Name>testfire</Name>")
            return httpx.Response(403, text="<Error><Code>AccessDenied</Code></Error>")
        return httpx.Response(404, text="<Error><Code>NoSuchBucket</Code></Error>")

    graph = _graph_with_host("demo.testfire.net")
    assert _run(handler, graph) == []


def test_no_exposed_bucket_yields_no_findings() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, text="<Error><Code>NoSuchBucket</Code></Error>")

    graph = _graph_with_host("demo.testfire.net")
    assert _run(handler, graph) == []


def test_no_hosts_in_graph_never_crashes() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError("must not probe anything when the graph has no hosts")

    assert _run(handler, ReachabilityGraph()) == []
