"""Hermetic E2E for the default-credentials driver (§7, Build Order 0).

Real ReachabilityGraph, httpx.MockTransport-backed RequestFirer, real oracle
registry via reachagent.tools.validator — same harness as
tests/scan/test_signal_reconfirm.py.
"""

from __future__ import annotations

import httpx

from reachagent.execution import RequestFirer, ScopeGuard
from reachagent.graph.store import ReachabilityGraph
from reachagent.scan.orchestrator import _ValidatorSeam, run_default_credentials

_LOGIN_PAGE = """
<html><body>
<form method="POST" action="/login">
  <input name="username" type="text">
  <input name="password" type="password">
</form>
</body></html>
"""


def _firer(handler: object) -> RequestFirer:
    client = httpx.Client(transport=httpx.MockTransport(handler))  # type: ignore[arg-type]
    return RequestFirer(client, ScopeGuard.from_hosts(["default-creds.test"]))


def _run(handler: object) -> list:
    graph = ReachabilityGraph()
    seam = _ValidatorSeam(graph)
    run_default_credentials(
        graph=graph,
        firer=_firer(handler),
        base_url="http://default-creds.test",
        identity="anon",
        seam=seam,
        events=[],
    )
    return graph.findings()


def test_admin_admin_confirms_a_finding_when_it_authenticates() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/login" and request.method == "POST":
            body = request.content.decode()
            if "username=admin&password=admin" in body:
                return httpx.Response(200, headers={"set-cookie": "session=abc123"}, text="welcome")
            return httpx.Response(401, text="invalid credentials")
        return httpx.Response(200, text=_LOGIN_PAGE)

    findings = _run(handler)
    classes = {f.vuln_class for _fid, f in findings}
    assert "default_credentials" in classes
    assert all(f.severity == "high" for _fid, f in findings)


def test_no_matching_pair_yields_no_finding() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/login" and request.method == "POST":
            return httpx.Response(401, text="invalid credentials")
        return httpx.Response(200, text=_LOGIN_PAGE)

    assert _run(handler) == []


def test_no_login_form_is_not_applicable_and_never_crashes() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="<html>no form here</html>")

    assert _run(handler) == []
