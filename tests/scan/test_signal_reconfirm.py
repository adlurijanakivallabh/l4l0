"""Hermetic tests for the signal-gated reconfirm seam (§9 W5/D3).

Exercises the ``reconfirm`` callback ``run_signal_tools`` calls per candidate
directly (same code path, without also standing up a live signal-gated tool
run). Mirrors the driver-test harness used throughout tests/scan/: real
ReachabilityGraph, httpx.MockTransport-backed RequestFirer, real oracle
registry via reachagent.tools.validator.
"""

from __future__ import annotations

import uuid as _uuid

import httpx

import reachagent.oob.collaborator as _collab_mod
from reachagent.execution import RequestFirer, ScopeGuard
from reachagent.graph.nodes import Endpoint, Parameter
from reachagent.graph.store import ReachabilityGraph
from reachagent.oracles import OracleMechanism
from reachagent.oracles import llm_judgment as _llm_judgment
from reachagent.scan import orchestrator as _orchestrator
from reachagent.scan.orchestrator import _make_signal_reconfirm
from reachagent.tools.candidate import Candidate, ResponseSignal
from tests._oracle_test_support import CONFIRMS, FixedJudgmentClient

_BASE = "http://reconfirm.test"
_SIGNAL = ResponseSignal(status_code=200, body_length=10, elapsed_seconds=0.01)


def _stub_confirms(monkeypatch) -> None:  # noqa: ANN001
    """Make the reconfirm-path run_oracle call return a fixed confirmed verdict.

    ``_make_signal_reconfirm`` wires ``run_oracle=validator.run_oracle`` straight
    through (no ``client=`` call site reachable from here), so — per the v3
    LLM-judgment model — the injection seam is the ``build_openai_compatible_client``
    factory ``llm_judgment.judge`` falls back to when no client is passed.
    """
    monkeypatch.setattr(
        _llm_judgment,
        "build_openai_compatible_client",
        lambda **kw: FixedJudgmentClient(CONFIRMS.value),
    )


def _graph() -> ReachabilityGraph:
    return ReachabilityGraph()


def _firer(handler: object) -> RequestFirer:
    client = httpx.Client(transport=httpx.MockTransport(handler))  # type: ignore[arg-type]
    return RequestFirer(client, ScopeGuard.from_hosts(["reconfirm.test"]))


def _reconfirm(graph: ReachabilityGraph, handler: object, *, auth_headers: dict | None = None):
    return _make_signal_reconfirm(
        graph=graph,
        firer=_firer(handler),
        base_url=_BASE,
        identity="anon",
        auth_headers=auth_headers or {},
        events=[],
    )


def test_unmapped_pair_is_a_complete_noop() -> None:
    """A claim outside the narrow MVP set is dropped -- no request ever fires."""
    graph = _graph()
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.method)
        return httpx.Response(200, text="ok")

    reconfirm = _reconfirm(graph, handler)
    candidate = Candidate(
        identity="nuclei",
        endpoint_node="endpoint:1",
        param_node=None,
        vuln_class="ssti",
        suggested_oracle=OracleMechanism.EXECUTION_CONFIRMATION,
        payload_ref=None,
        signal=_SIGNAL,
    )
    assert reconfirm(candidate) is None
    assert seen == []
    assert graph.findings() == []


def test_jwt_forgery_confirms_when_forged_token_accepted(monkeypatch) -> None:  # noqa: ANN001
    _stub_confirms(monkeypatch)
    graph = _graph()
    ep = graph.add_endpoint(Endpoint(method="GET", path="/api/admin/users"))

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="ok")

    reconfirm = _reconfirm(graph, handler, auth_headers={"Authorization": "Bearer real-token"})
    candidate = Candidate(
        identity="jwt_tool",
        endpoint_node=ep,
        param_node=None,
        vuln_class="jwt_forgery",
        suggested_oracle=OracleMechanism.STRUCTURAL,
        payload_ref=None,
        signal=_SIGNAL,
    )
    node_id = reconfirm(candidate)
    assert node_id is not None
    classes = {f.vuln_class for _fid, f in graph.findings()}
    assert "jwt_forgery" in classes


def test_jwt_forgery_denied_when_forged_token_refused() -> None:
    graph = _graph()
    ep = graph.add_endpoint(Endpoint(method="GET", path="/api/admin/users"))

    def handler(request: httpx.Request) -> httpx.Response:
        auth = request.headers.get("authorization", "")
        if "real-token" in auth:
            return httpx.Response(200, text="ok")
        return httpx.Response(401, text="unauthorized")

    reconfirm = _reconfirm(graph, handler, auth_headers={"Authorization": "Bearer real-token"})
    candidate = Candidate(
        identity="jwt_tool",
        endpoint_node=ep,
        param_node=None,
        vuln_class="jwt_forgery",
        suggested_oracle=OracleMechanism.STRUCTURAL,
        payload_ref=None,
        signal=_SIGNAL,
    )
    assert reconfirm(candidate) is None
    assert graph.findings() == []


def test_jwt_forgery_no_bearer_token_never_fires() -> None:
    graph = _graph()
    ep = graph.add_endpoint(Endpoint(method="GET", path="/api/admin/users"))
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.method)
        return httpx.Response(200, text="ok")

    reconfirm = _reconfirm(graph, handler, auth_headers={})
    candidate = Candidate(
        identity="jwt_tool",
        endpoint_node=ep,
        param_node=None,
        vuln_class="jwt_forgery",
        suggested_oracle=OracleMechanism.STRUCTURAL,
        payload_ref=None,
        signal=_SIGNAL,
    )
    assert reconfirm(candidate) is None
    assert seen == []


def test_xss_reflected_confirms_when_tag_reflects(monkeypatch) -> None:  # noqa: ANN001
    _stub_confirms(monkeypatch)
    graph = _graph()
    ep = graph.add_endpoint(Endpoint(method="GET", path="/search"))
    param = graph.add_parameter(ep, Parameter(name="q", location="query"))

    def handler(request: httpx.Request) -> httpx.Response:
        value = request.url.params.get("q", "")
        return httpx.Response(200, text=f"<p>results for {value}</p>")

    reconfirm = _reconfirm(graph, handler)
    candidate = Candidate(
        identity="dalfox",
        endpoint_node=ep,
        param_node=param,
        vuln_class="xss_reflected",
        suggested_oracle=OracleMechanism.EXECUTION_CONFIRMATION,
        payload_ref=None,
        signal=_SIGNAL,
    )
    node_id = reconfirm(candidate)
    assert node_id is not None
    classes = {f.vuln_class for _fid, f in graph.findings()}
    assert "xss_reflected" in classes


def test_xss_reflected_no_finding_when_encoded() -> None:
    graph = _graph()
    ep = graph.add_endpoint(Endpoint(method="GET", path="/search"))
    param = graph.add_parameter(ep, Parameter(name="q", location="query"))

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="<p>results for &lt;script&gt;safe&lt;/script&gt;</p>")

    reconfirm = _reconfirm(graph, handler)
    candidate = Candidate(
        identity="dalfox",
        endpoint_node=ep,
        param_node=param,
        vuln_class="xss_reflected",
        suggested_oracle=OracleMechanism.EXECUTION_CONFIRMATION,
        payload_ref=None,
        signal=_SIGNAL,
    )
    assert reconfirm(candidate) is None
    assert graph.findings() == []


def test_sqli_confirms_on_error_signature(monkeypatch) -> None:  # noqa: ANN001
    _stub_confirms(monkeypatch)
    graph = _graph()
    ep = graph.add_endpoint(Endpoint(method="GET", path="/products"))
    param = graph.add_parameter(ep, Parameter(name="id", location="query"))

    def handler(request: httpx.Request) -> httpx.Response:
        value = request.url.params.get("id", "")
        if "'" in value:
            return httpx.Response(500, text="You have an error in your SQL syntax")
        return httpx.Response(200, text="ok")

    reconfirm = _reconfirm(graph, handler)
    candidate = Candidate(
        identity="sqlmap",
        endpoint_node=ep,
        param_node=param,
        vuln_class="sqli",
        suggested_oracle=OracleMechanism.DIFFERENTIAL,
        payload_ref=None,
        signal=_SIGNAL,
    )
    node_id = reconfirm(candidate)
    assert node_id is not None
    classes = {f.vuln_class for _fid, f in graph.findings()}
    assert "sqli" in classes


def test_sqli_no_finding_when_clean() -> None:
    graph = _graph()
    ep = graph.add_endpoint(Endpoint(method="GET", path="/products"))
    param = graph.add_parameter(ep, Parameter(name="id", location="query"))

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="ok")

    reconfirm = _reconfirm(graph, handler)
    candidate = Candidate(
        identity="sqlmap",
        endpoint_node=ep,
        param_node=param,
        vuln_class="sqli",
        suggested_oracle=OracleMechanism.DIFFERENTIAL,
        payload_ref=None,
        signal=_SIGNAL,
    )
    assert reconfirm(candidate) is None
    assert graph.findings() == []


class _FakeCollaborator:
    hit: bool = False

    def __init__(self, *args: object, **kwargs: object) -> None:
        self._base_domain = "oob.test"

    def observed_nonces(self) -> frozenset[str]:
        return frozenset({_FIXED_NONCE}) if self.hit else frozenset()


_FIXED_UUID = _uuid.UUID(int=0xC0FFEE)
_FIXED_NONCE = "ra" + _FIXED_UUID.hex[:12]


def test_command_injection_skipped_without_oob_domain(monkeypatch) -> None:  # noqa: ANN001
    monkeypatch.delenv("REACHAGENT_OOB_BASE_DOMAIN", raising=False)
    graph = _graph()
    ep = graph.add_endpoint(Endpoint(method="GET", path="/ping"))
    param = graph.add_parameter(ep, Parameter(name="host", location="query"))
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.method)
        return httpx.Response(200, text="ok")

    reconfirm = _reconfirm(graph, handler)
    candidate = Candidate(
        identity="commix",
        endpoint_node=ep,
        param_node=param,
        vuln_class="command_injection",
        suggested_oracle=OracleMechanism.OOB_CALLBACK,
        payload_ref=None,
        signal=_SIGNAL,
    )
    assert reconfirm(candidate) is None
    assert seen == []


def test_information_exposure_confirms_on_known_stack_trace_marker(monkeypatch) -> None:  # noqa: ANN001
    _stub_confirms(monkeypatch)
    graph = _graph()
    ep = graph.add_endpoint(Endpoint(method="GET", path="/index.jsp"))

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            500, text="HTTP Status 500\norg.apache.jasper.JasperException\nApache Tomcat/7.0.92"
        )

    reconfirm = _reconfirm(graph, handler)
    candidate = Candidate(
        identity="nikto",
        endpoint_node=ep,
        param_node=None,
        vuln_class="information_exposure",
        suggested_oracle=OracleMechanism.STRUCTURAL,
        payload_ref=None,
        signal=_SIGNAL,
    )
    node_id = reconfirm(candidate)
    assert node_id is not None
    findings = dict(graph.findings())
    assert findings[node_id].vuln_class == "information_exposure"
    assert findings[node_id].severity == "informational"


def test_information_exposure_no_finding_on_a_plain_error_page() -> None:
    graph = _graph()
    ep = graph.add_endpoint(Endpoint(method="GET", path="/index.jsp"))

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, text="<html>Internal Server Error</html>")

    reconfirm = _reconfirm(graph, handler)
    candidate = Candidate(
        identity="nikto",
        endpoint_node=ep,
        param_node=None,
        vuln_class="information_exposure",
        suggested_oracle=OracleMechanism.STRUCTURAL,
        payload_ref=None,
        signal=_SIGNAL,
    )
    assert reconfirm(candidate) is None
    assert graph.findings() == []


def test_command_injection_confirms_when_callback_observed(monkeypatch) -> None:  # noqa: ANN001
    _stub_confirms(monkeypatch)
    monkeypatch.setenv("REACHAGENT_OOB_BASE_DOMAIN", "oob.test")
    monkeypatch.setattr(_orchestrator.uuid, "uuid4", lambda: _FIXED_UUID)
    _FakeCollaborator.hit = True
    monkeypatch.setattr(_collab_mod, "InteractshCollaborator", _FakeCollaborator)

    graph = _graph()
    ep = graph.add_endpoint(Endpoint(method="GET", path="/ping"))
    param = graph.add_parameter(ep, Parameter(name="host", location="query"))

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="ok")

    reconfirm = _reconfirm(graph, handler)
    candidate = Candidate(
        identity="commix",
        endpoint_node=ep,
        param_node=param,
        vuln_class="command_injection",
        suggested_oracle=OracleMechanism.OOB_CALLBACK,
        payload_ref=None,
        signal=_SIGNAL,
    )
    node_id = reconfirm(candidate)
    assert node_id is not None
    classes = {f.vuln_class for _fid, f in graph.findings()}
    assert "command_injection" in classes
