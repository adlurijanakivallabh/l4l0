"""Hermetic E2E for the structural-headers driver's CORS corroboration (v3 V3).

No dedicated driver test existed for run_structural_headers before — the
three classes it confirms (clickjacking, csrf_missing_protection,
cors_misconfig) were only exercised indirectly via test_orchestrator.py's
broader all-classes integration test. This file targets the CORS
technique-diversity corroboration specifically: a real HTTP-response-driven
oracle stand-in (mirroring test_jwt_forgery_driver.py's _real_evidence_run
pattern) so the test asserts on genuine ACAO-reflection wiring, not a
blanket fixed verdict that would confirm regardless of which origin was
actually reflected.
"""

from __future__ import annotations

import httpx

from reachagent.detection.oracle_gateway import OracleOutcome
from reachagent.execution import RequestFirer, ScopeGuard
from reachagent.graph.nodes import Endpoint
from reachagent.graph.store import ReachabilityGraph
from reachagent.oracles.base import OracleVerdict
from reachagent.oracles.structural import StructuralCheckType
from reachagent.scan.orchestrator import _ValidatorSeam, run_structural_headers
from tests._oracle_test_support import CONFIRMS, INCONCLUSIVE

_BASE = "http://headers.test"


def _real_cors_evidence_run(
    self: _ValidatorSeam, mechanism: object, evidence: object
) -> OracleOutcome:
    """Judges CORS_MISCONFIG evidence on its real acao/probe_origin reflection;
    denies clickjacking/csrf so only the CORS path under test ever confirms."""
    if getattr(evidence, "check_type", None) == StructuralCheckType.CORS_MISCONFIG:
        reflected = evidence.acao == evidence.probe_origin and evidence.acac.lower() == "true"  # type: ignore[attr-defined]
        status = CONFIRMS if reflected else INCONCLUSIVE
    else:
        status = INCONCLUSIVE
    ref = str(getattr(evidence, "evidence_ref", "") or "")
    verdict = OracleVerdict(
        mechanism=mechanism, status=status, evidence_ref=ref, reason="test-fixed-verdict"
    )
    self._last = verdict
    return OracleOutcome(verdict)


def _graph() -> ReachabilityGraph:
    graph = ReachabilityGraph()
    graph.add_endpoint(Endpoint(method="GET", path="/", content_type="text/html"))
    return graph


def _firer(handler: object) -> RequestFirer:
    client = httpx.Client(transport=httpx.MockTransport(handler))  # type: ignore[arg-type]
    return RequestFirer(client, ScopeGuard.from_hosts(["headers.test"]))


def _run(handler: object) -> list:
    graph = _graph()
    seam = _ValidatorSeam(graph)
    run_structural_headers(
        graph=graph,
        firer=_firer(handler),
        base_url=_BASE,
        identity="anon",
        auth_headers={},
        seam=seam,
        events=[],
    )
    return graph.findings()


def test_both_origins_reflected_corroborates(monkeypatch) -> None:  # noqa: ANN001
    monkeypatch.setattr(_ValidatorSeam, "run", _real_cors_evidence_run)

    def handler(request: httpx.Request) -> httpx.Response:
        origin = request.headers.get("origin", "")
        headers = {"content-type": "text/html"}
        if origin:
            headers["access-control-allow-origin"] = origin
            headers["access-control-allow-credentials"] = "true"
        return httpx.Response(200, text="<html></html>", headers=headers)

    findings = _run(handler)
    classes = {f.vuln_class for _fid, f in findings}
    assert "cors_misconfig" in classes


def test_second_origin_not_reflected_fails_closed(monkeypatch) -> None:  # noqa: ANN001
    """A server that happens to reflect exactly ONE hardcoded allowlisted
    origin (not genuine arbitrary-origin reflection) must NOT confirm — the
    second, different attacker origin correctly gets refused."""
    monkeypatch.setattr(_ValidatorSeam, "run", _real_cors_evidence_run)
    first_seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        origin = request.headers.get("origin", "")
        headers = {"content-type": "text/html"}
        if origin and not first_seen:
            # Reflect only the FIRST distinct attacker origin ever seen —
            # simulates a hardcoded single-entry allowlist coincidentally
            # matching the first probe.
            first_seen.append(origin)
        if origin and origin == (first_seen[0] if first_seen else None):
            headers["access-control-allow-origin"] = origin
            headers["access-control-allow-credentials"] = "true"
        return httpx.Response(200, text="<html></html>", headers=headers)

    findings = _run(handler)
    classes = {f.vuln_class for _fid, f in findings}
    assert "cors_misconfig" not in classes


def test_no_origin_reflected_no_finding(monkeypatch) -> None:  # noqa: ANN001
    monkeypatch.setattr(_ValidatorSeam, "run", _real_cors_evidence_run)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="<html></html>", headers={"content-type": "text/html"})

    findings = _run(handler)
    assert not any(f.vuln_class == "cors_misconfig" for _fid, f in findings)
