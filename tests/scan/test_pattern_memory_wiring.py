"""_ValidatorSeam.write() -> pattern memory wiring ("My additions").

Mirrors tests/scan/test_default_credentials_driver.py's harness — a real
ReachabilityGraph, httpx.MockTransport-backed RequestFirer, real oracle
registry — plus a Host node carrying a technology fingerprint, since that
is the one additional fact record_confirmed_pattern needs.

record_confirmed_pattern is monkeypatched to a spy rather than round-tripped
through a real file — the file-layer behavior (round trip, corrupt-line
skip, trim) is already covered by tests/memory/test_pattern_db.py. This
file verifies the WIRING: called with the right arguments exactly when (and
only when) a Finding is actually committed, from the already-oracle-
confirmed fields — never from an unconfirmed candidate.
"""

from __future__ import annotations

import httpx

import reachagent.scan.orchestrator as orchestrator_module
from reachagent.execution import RequestFirer, ScopeGuard
from reachagent.graph.nodes import Host
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


def _confirming_handler(request: httpx.Request) -> httpx.Response:
    if request.url.path == "/login" and request.method == "POST":
        body = request.content.decode()
        if "username=admin&password=admin" in body:
            return httpx.Response(200, headers={"set-cookie": "session=abc123"}, text="welcome")
        return httpx.Response(401, text="invalid credentials")
    return httpx.Response(200, text=_LOGIN_PAGE)


def _clean_handler(request: httpx.Request) -> httpx.Response:
    if request.url.path == "/login" and request.method == "POST":
        return httpx.Response(401, text="invalid credentials")
    return httpx.Response(200, text=_LOGIN_PAGE)


def test_confirmed_finding_records_a_pattern_with_the_tech_signal(monkeypatch) -> None:  # noqa: ANN001
    calls: list[tuple[str, str, str, str]] = []
    monkeypatch.setattr(
        "reachagent.memory.pattern_db.record_confirmed_pattern",
        lambda vuln_class, technology, oracle_used, severity, **_kw: calls.append(
            (vuln_class, technology, oracle_used, severity)
        ),
    )

    graph = ReachabilityGraph()
    graph.add_host(
        Host(address="1.2.3.4", hostname="default-creds.test", technology="WordPress, PHP")
    )
    seam = _ValidatorSeam(graph)
    run_default_credentials(
        graph=graph,
        firer=_firer(_confirming_handler),
        base_url="http://default-creds.test",
        identity="anon",
        seam=seam,
        events=[],
    )

    assert graph.findings()  # the confirmation actually happened
    assert len(calls) == 1
    vuln_class, technology, oracle_used, severity = calls[0]
    assert vuln_class == "default_credentials"
    assert technology == "WordPress, PHP"
    assert severity == "high"
    assert oracle_used  # populated from the real verdict's mechanism, never blank


def test_no_pattern_recorded_when_nothing_is_confirmed(monkeypatch) -> None:  # noqa: ANN001
    calls: list[tuple[str, str, str, str]] = []
    monkeypatch.setattr(
        "reachagent.memory.pattern_db.record_confirmed_pattern",
        lambda *args, **kwargs: calls.append(args),
    )

    graph = ReachabilityGraph()
    graph.add_host(Host(address="1.2.3.4", hostname="default-creds.test", technology="WordPress"))
    seam = _ValidatorSeam(graph)
    run_default_credentials(
        graph=graph,
        firer=_firer(_clean_handler),
        base_url="http://default-creds.test",
        identity="anon",
        seam=seam,
        events=[],
    )

    assert graph.findings() == []
    assert calls == []


def test_no_pattern_recorded_when_graph_has_no_technology_signal(monkeypatch) -> None:  # noqa: ANN001
    calls: list[tuple[str, str, str, str]] = []
    monkeypatch.setattr(
        "reachagent.memory.pattern_db.record_confirmed_pattern",
        lambda *args, **kwargs: calls.append(args),
    )

    graph = ReachabilityGraph()  # no Host node at all — nothing to correlate against
    seam = _ValidatorSeam(graph)
    run_default_credentials(
        graph=graph,
        firer=_firer(_confirming_handler),
        base_url="http://default-creds.test",
        identity="anon",
        seam=seam,
        events=[],
    )

    assert graph.findings()  # still a real, valid finding
    assert calls == []  # just nothing advisory recorded for it


def test_seam_write_never_calls_pattern_memory_when_verdict_is_not_a_violation() -> None:
    # Direct unit check on the seam itself, mirroring the existing
    # "verdict is None or not is_violation -> return None" contract.
    graph = ReachabilityGraph()
    seam = orchestrator_module._ValidatorSeam(graph)
    assert seam.write("sqli", None) is None
    assert graph.findings() == []
