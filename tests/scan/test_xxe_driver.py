"""Hermetic E2E for the blind-XXE driver: OOB callback confirmation only.

Mirrors the mass_assignment/xss_stored driver harness, but the confirming
signal is out-of-band (§7 oob_callback), so the collaborator itself is faked
rather than the HTTP responses. Proves: (1) the class is skipped entirely
without REACHAGENT_OOB_BASE_DOMAIN, (2) only endpoints declaring an XML
request body are probed, (3) the write only fires after its own read-only
preflight, and (4) confirmation requires the probe's own nonce to appear in
the collaborator's observed set.
"""

from __future__ import annotations

import uuid as _uuid

import httpx

import reachagent.oob.collaborator as _collab_mod
from reachagent.execution import RequestFirer, ScopeGuard
from reachagent.graph.nodes import Endpoint, Parameter
from reachagent.graph.store import ReachabilityGraph
from reachagent.scan import orchestrator as _orchestrator
from reachagent.scan.orchestrator import _ValidatorSeam, run_xxe
from tests._oracle_test_support import CONFIRMS, FixedJudgmentClient

_BASE = "http://xxe.test"
_FIXED_UUID = _uuid.UUID(int=0xABCDEF)
_FIXED_NONCE = "ra" + _FIXED_UUID.hex[:12]


class _FakeCollaborator:
    """Stands in for InteractshCollaborator — no real network polling."""

    hit: bool = False

    def __init__(self, *args: object, **kwargs: object) -> None:
        self._base_domain = "oob.test"

    def observed_nonces(self) -> frozenset[str]:
        return frozenset({_FIXED_NONCE}) if self.hit else frozenset()


def _graph() -> ReachabilityGraph:
    graph = ReachabilityGraph()
    ep = graph.add_endpoint(
        Endpoint(method="POST", path="/api/import", content_type="application/xml")
    )
    graph.add_parameter(ep, Parameter(name="payload", location="body"))
    return graph


def _firer(handler: object) -> RequestFirer:
    client = httpx.Client(transport=httpx.MockTransport(handler))  # type: ignore[arg-type]
    return RequestFirer(client, ScopeGuard.from_hosts(["xxe.test"]))


def _run(handler: object, graph: ReachabilityGraph | None = None) -> list:
    graph = graph or _graph()
    seam = _ValidatorSeam(graph)
    run_xxe(
        graph=graph,
        firer=_firer(handler),
        base_url=_BASE,
        identity="anon",
        auth_headers={},
        seam=seam,
        events=[],
    )
    return graph.findings()


def _default_handler(request: httpx.Request) -> httpx.Response:
    if request.method in ("OPTIONS", "GET"):
        return httpx.Response(200, text="ok")
    return httpx.Response(200, text="accepted")


def test_skipped_entirely_without_oob_domain_configured(monkeypatch) -> None:  # noqa: ANN001
    monkeypatch.delenv("REACHAGENT_OOB_BASE_DOMAIN", raising=False)
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.method)
        return httpx.Response(200, text="ok")

    assert _run(handler) == []
    assert seen == []  # never even reached the preflight


def test_confirms_when_probe_nonce_observed(monkeypatch) -> None:  # noqa: ANN001
    """Confirmation is now an LLM judgment (v3, CLAUDE.md) rather than a fixed
    decide(); _ValidatorSeam.run calls tools.validator.run_oracle with no
    client= passthrough, so pin the verdict by monkeypatching the client
    builder it constructs internally.
    """
    import reachagent.oracles.llm_judgment as _llm_judgment

    monkeypatch.setenv("REACHAGENT_OOB_BASE_DOMAIN", "oob.test")
    monkeypatch.setattr(_orchestrator.uuid, "uuid4", lambda: _FIXED_UUID)
    _FakeCollaborator.hit = True
    monkeypatch.setattr(_collab_mod, "InteractshCollaborator", _FakeCollaborator)
    monkeypatch.setattr(
        _llm_judgment, "build_openai_compatible_client", lambda: FixedJudgmentClient(CONFIRMS.value)
    )

    findings = _run(_default_handler)
    classes = {f.vuln_class for _fid, f in findings}
    assert "xxe" in classes
    assert all(f.status.value == "confirmed_violation" for _fid, f in findings)


def test_no_callback_observed_no_finding(monkeypatch) -> None:  # noqa: ANN001
    monkeypatch.setenv("REACHAGENT_OOB_BASE_DOMAIN", "oob.test")
    monkeypatch.setattr(_orchestrator.uuid, "uuid4", lambda: _FIXED_UUID)
    _FakeCollaborator.hit = False
    monkeypatch.setattr(_collab_mod, "InteractshCollaborator", _FakeCollaborator)

    assert _run(_default_handler) == []


def test_no_xml_endpoint_never_probed(monkeypatch) -> None:  # noqa: ANN001
    monkeypatch.setenv("REACHAGENT_OOB_BASE_DOMAIN", "oob.test")
    _FakeCollaborator.hit = True
    monkeypatch.setattr(_collab_mod, "InteractshCollaborator", _FakeCollaborator)

    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.method)
        return httpx.Response(200, text="ok")

    graph = ReachabilityGraph()
    ep = graph.add_endpoint(
        Endpoint(method="POST", path="/api/create", content_type="application/json")
    )
    graph.add_parameter(ep, Parameter(name="name", location="json"))

    assert _run(handler, graph=graph) == []
    assert seen == []  # no XML request body declared — never probed


def test_no_read_only_clearance_never_fires_the_xml_body(monkeypatch) -> None:  # noqa: ANN001
    monkeypatch.setenv("REACHAGENT_OOB_BASE_DOMAIN", "oob.test")
    _FakeCollaborator.hit = True
    monkeypatch.setattr(_collab_mod, "InteractshCollaborator", _FakeCollaborator)

    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.method)
        if request.method in ("OPTIONS", "GET"):
            return httpx.Response(404, text="not found")  # no clearance
        return httpx.Response(200, text="accepted")

    assert _run(handler) == []
    assert "POST" not in seen  # the XML body genuinely never fired


def test_sequencing_is_preflight_then_xml_body(monkeypatch) -> None:  # noqa: ANN001
    monkeypatch.setenv("REACHAGENT_OOB_BASE_DOMAIN", "oob.test")
    _FakeCollaborator.hit = False
    monkeypatch.setattr(_collab_mod, "InteractshCollaborator", _FakeCollaborator)

    seen: list[tuple[str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append((request.method, request.url.path))
        if request.method in ("OPTIONS", "GET"):
            return httpx.Response(200, text="ok")
        return httpx.Response(200, text="accepted")

    _run(handler)
    methods = [m for m, _p in seen]
    assert methods[0] in ("OPTIONS", "GET")  # preflight first
    assert "POST" in methods
