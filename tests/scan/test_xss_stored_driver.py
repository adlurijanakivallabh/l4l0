"""Hermetic E2E for the stored-XSS driver: write + independent reread.

Mirrors test_mass_assignment_driver.py's harness. Proves: (1) the write only
fires after its own read-only-first clearance, and (2) confirmation reads an
INDEPENDENT re-fetch of the resource — the tag must appear there, not merely
in the write's own response body.
"""

from __future__ import annotations

import json

import httpx

from reachagent.execution import RequestFirer, ScopeGuard
from reachagent.graph.nodes import Endpoint, Parameter
from reachagent.graph.store import ReachabilityGraph
from reachagent.scan.orchestrator import _ValidatorSeam, run_xss_stored

_BASE = "http://xs.test"


def _graph() -> ReachabilityGraph:
    graph = ReachabilityGraph()
    write_ep = graph.add_endpoint(Endpoint(method="POST", path="/comments"))
    graph.add_parameter(write_ep, Parameter(name="username", location="json"))
    graph.add_parameter(write_ep, Parameter(name="body", location="json"))
    graph.add_endpoint(Endpoint(method="GET", path="/comments/{id}"))
    return graph


def _firer(handler: object) -> RequestFirer:
    client = httpx.Client(transport=httpx.MockTransport(handler))  # type: ignore[arg-type]
    return RequestFirer(client, ScopeGuard.from_hosts(["xs.test"]))


def _run(handler: object) -> list:
    graph = _graph()
    seam = _ValidatorSeam(graph)
    run_xss_stored(
        graph=graph,
        firer=_firer(handler),
        base_url=_BASE,
        identity="anon",
        auth_headers={},
        seam=seam,
        events=[],
    )
    return graph.findings()


def test_confirms_when_tag_reflects_in_independent_reread() -> None:
    captured: list[dict] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method in ("OPTIONS", "GET") and request.url.path == "/comments":
            return httpx.Response(200, text="ok")
        if request.method == "POST":
            captured.append(json.loads(request.content))
            return httpx.Response(200, json={"status": "created"})
        if request.method == "GET":
            # Independent reread: the injected script tag reflects unencoded.
            injected = captured[0]["body"]
            return httpx.Response(200, text=f"<p>{injected}</p>")
        return httpx.Response(404)

    findings = _run(handler)
    classes = {f.vuln_class for _fid, f in findings}
    assert "xss_stored" in classes
    assert all(f.status.value == "confirmed_violation" for _fid, f in findings)


def test_secure_target_encodes_payload_no_finding() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method in ("OPTIONS", "GET") and request.url.path == "/comments":
            return httpx.Response(200, text="ok")
        if request.method == "POST":
            return httpx.Response(200, json={"status": "created"})
        if request.method == "GET":
            # The server HTML-encoded the payload before persisting/rendering.
            return httpx.Response(200, text="<p>&lt;script&gt;safe&lt;/script&gt;</p>")
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
    write_ep = graph.add_endpoint(Endpoint(method="POST", path="/comments"))
    graph.add_parameter(write_ep, Parameter(name="body", location="json"))
    # No sibling GET endpoint anywhere in the graph.

    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.method)
        return httpx.Response(200, text="ok")

    seam = _ValidatorSeam(graph)
    run_xss_stored(
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
        if request.method in ("OPTIONS", "GET") and request.url.path == "/comments":
            return httpx.Response(200, text="ok")
        if request.method == "POST":
            return httpx.Response(200, json={"status": "created"})
        return httpx.Response(200, text="<script>reflected</script>")

    _run(handler)
    methods = [m for m, _p in seen]
    assert methods[0] in ("OPTIONS", "GET")  # preflight first
    assert "POST" in methods
    write_index = methods.index("POST")
    assert write_index < len(methods) - 1  # a reread follows the write
    # The reread is a genuinely separate GET, not the write's own response.
    assert methods[write_index + 1] == "GET"
    assert seen[write_index + 1][1] != "/comments"


def test_json_body_carries_the_resolved_canary_payload() -> None:
    captured: list[dict] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method in ("OPTIONS", "GET") and request.url.path == "/comments":
            return httpx.Response(200, text="ok")
        if request.method == "POST":
            captured.append(json.loads(request.content))
            return httpx.Response(200, json={"status": "created"})
        return httpx.Response(200, text="<p>safe</p>")

    _run(handler)
    assert captured
    payload_body = captured[0]
    # The non-identifier field (body) carries the <script>{canary}</script> payload;
    # username stays legit — it's what the reread URL is resolved from.
    assert payload_body["body"].startswith("<script>") and payload_body["body"].endswith(
        "</script>"
    )
    assert "username" in payload_body  # the identifier field is untouched
