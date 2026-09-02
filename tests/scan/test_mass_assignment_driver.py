"""Hermetic E2E for the mass-assignment driver: write + independent reread.

Proves the two properties the whole investigation turned on: (1) the write only
fires after its own read-only-first clearance, and (2) confirmation reads an
INDEPENDENT re-fetch of the resource, not the write's own response body.
"""

from __future__ import annotations

import json

import httpx

from reachagent.execution import RequestFirer, ScopeGuard
from reachagent.graph.nodes import Endpoint, Parameter
from reachagent.graph.store import ReachabilityGraph
from reachagent.scan.orchestrator import _ValidatorSeam, run_mass_assignment
from tests._oracle_test_support import CONFIRMS, FixedJudgmentClient

_BASE = "http://ma.test"


def _graph() -> ReachabilityGraph:
    graph = ReachabilityGraph()
    write_ep = graph.add_endpoint(Endpoint(method="POST", path="/users/v1/register"))
    graph.add_parameter(write_ep, Parameter(name="username", location="json"))
    graph.add_parameter(write_ep, Parameter(name="password", location="json"))
    graph.add_endpoint(Endpoint(method="GET", path="/users/v1/{username}"))
    return graph


def _firer(handler: object) -> RequestFirer:
    client = httpx.Client(transport=httpx.MockTransport(handler))  # type: ignore[arg-type]
    return RequestFirer(client, ScopeGuard.from_hosts(["ma.test"]))


def _run(handler: object) -> list:
    graph = _graph()
    seam = _ValidatorSeam(graph)
    run_mass_assignment(
        graph=graph,
        firer=_firer(handler),
        base_url=_BASE,
        identity="anon",
        auth_headers={},
        seam=seam,
        events=[],
    )
    return graph.findings()


def test_confirms_when_privileged_field_persists(monkeypatch) -> None:  # noqa: ANN001
    """Confirmation is now an LLM judgment (v3, CLAUDE.md) rather than a fixed
    decide(); _ValidatorSeam.run calls tools.validator.run_oracle with no
    client= passthrough, so pin the verdict by monkeypatching the client
    builder it constructs internally.
    """
    import reachagent.oracles.llm_judgment as _llm_judgment

    monkeypatch.setattr(
        _llm_judgment, "build_openai_compatible_client", lambda: FixedJudgmentClient(CONFIRMS.value)
    )

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method in ("OPTIONS", "GET") and request.url.path == "/users/v1/register":
            return httpx.Response(200, text="ok")
        if request.method == "POST":
            return httpx.Response(200, json={"status": "created"})
        if request.method == "GET":
            # Independent reread: the injected admin flag stuck.
            return httpx.Response(200, json={"username": "ra-x", "admin": True})
        return httpx.Response(404)

    findings = _run(handler)
    classes = {f.vuln_class for _fid, f in findings}
    assert "mass_assignment" in classes
    assert all(f.status.value == "confirmed_violation" for _fid, f in findings)


def test_secure_target_strips_privileged_field_no_finding() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method in ("OPTIONS", "GET") and request.url.path == "/users/v1/register":
            return httpx.Response(200, text="ok")
        if request.method == "POST":
            return httpx.Response(200, json={"status": "created"})
        if request.method == "GET":
            # The server stripped the unauthorized field before persisting.
            return httpx.Response(200, json={"username": "ra-x"})
        return httpx.Response(404)

    assert _run(handler) == []


def test_no_read_only_clearance_never_fires_the_write() -> None:
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.method)
        if request.method in ("OPTIONS", "GET"):
            return httpx.Response(404, text="not found")  # no clearance
        return httpx.Response(200, json={"status": "created"})

    assert _run(handler) == []
    assert "POST" not in seen  # the write genuinely never fired


def test_no_sibling_read_endpoint_skips_without_firing() -> None:
    graph = ReachabilityGraph()
    write_ep = graph.add_endpoint(Endpoint(method="POST", path="/users/v1/register"))
    graph.add_parameter(write_ep, Parameter(name="username", location="json"))
    # No sibling GET endpoint anywhere in the graph.

    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.method)
        return httpx.Response(200, text="ok")

    seam = _ValidatorSeam(graph)
    run_mass_assignment(
        graph=graph,
        firer=_firer(handler),
        base_url=_BASE,
        identity="anon",
        auth_headers={},
        seam=seam,
        events=[],
    )
    assert graph.findings() == []
    assert seen == []  # never even reached the preflight


def test_sequencing_is_preflight_then_write_then_independent_reread() -> None:
    seen: list[tuple[str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append((request.method, request.url.path))
        if request.method in ("OPTIONS", "GET") and request.url.path == "/users/v1/register":
            return httpx.Response(200, text="ok")
        if request.method == "POST":
            return httpx.Response(200, json={"status": "created"})
        return httpx.Response(200, json={"username": "ra-x", "admin": True})

    _run(handler)
    methods = [m for m, _p in seen]
    assert methods[0] in ("OPTIONS", "GET")  # preflight first
    assert "POST" in methods
    assert methods.index("POST") < len(methods) - 1  # a reread follows the write
    # The reread is a genuinely separate GET, not the write's own response.
    write_index = methods.index("POST")
    assert methods[write_index + 1] == "GET"
    assert seen[write_index + 1][1] != "/users/v1/register"


def test_json_body_matches_the_resolved_payload_template() -> None:
    captured: list[dict] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method in ("OPTIONS", "GET") and request.url.path == "/users/v1/register":
            return httpx.Response(200, text="ok")
        if request.method == "POST":
            captured.append(json.loads(request.content))
            return httpx.Response(200, json={"status": "created"})
        return httpx.Response(200, json={"username": "ra-x"})

    _run(handler)
    assert captured
    body = captured[0]
    assert "username" in body and "password" in body  # legitimate fields present
    assert body.get("admin") is True  # the injected privileged field
