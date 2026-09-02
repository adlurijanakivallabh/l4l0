"""Hermetic E2E for cross-host credential reuse (v3 plan V4).

Same harness shape as test_default_credentials_driver.py: real
ReachabilityGraph, httpx.MockTransport-backed RequestFirer, real oracle path
via reachagent.tools.validator with a pinned LLM-judgment client.
"""

from __future__ import annotations

import json

import httpx

from reachagent.execution import RequestFirer, ScopeGuard
from reachagent.graph.nodes import Finding, FindingStatus, Host
from reachagent.graph.store import ReachabilityGraph
from reachagent.scan.cross_host_reuse import (
    extract_credential_pairs,
    run_cross_host_credential_reuse,
)
from reachagent.scan.orchestrator import _ValidatorSeam
from tests._oracle_test_support import CONFIRMS, FixedJudgmentClient

_OTHER_LOGIN_PAGE = """
<html><body>
<form method="POST" action="/login">
  <input name="username" type="text">
  <input name="password" type="password">
</form>
</body></html>
"""


def _seed_confirmed_finding_with_credential_pair(
    graph: ReachabilityGraph, username: str, password: str
) -> None:
    body = f'{{"username": "{username}", "password": "{password}"}}'
    graph.add_finding(
        Finding(
            vuln_class="sqli",
            severity="high",
            oracle_used="differential",
            evidence_ref="orchestrator/sqli/a.test/dump",
            status=FindingStatus.CONFIRMED_VIOLATION,
            metadata={"evidence_metadata": json.dumps({"body_projection": body})},
        )
    )


def _firer(handler: object) -> RequestFirer:
    client = httpx.Client(transport=httpx.MockTransport(handler))  # type: ignore[arg-type]
    return RequestFirer(client, ScopeGuard.from_hosts(["a.test", "b.test"]))


# --- extract_credential_pairs: pure unit tests, no LLM/network needed --------


def test_extract_credential_pairs_finds_a_clean_json_pair() -> None:
    body = '{"id": 1, "username": "admin", "password": "hunter2"}'
    assert extract_credential_pairs(body) == [("admin", "hunter2")]


def test_extract_credential_pairs_returns_empty_for_non_credential_json() -> None:
    assert extract_credential_pairs('{"id": 1, "name": "widget"}') == []


def test_extract_credential_pairs_returns_empty_for_empty_body() -> None:
    assert extract_credential_pairs("") == []


# --- run_cross_host_credential_reuse: full driver E2E ------------------------


def test_captured_pair_confirms_a_finding_on_another_in_scope_host(monkeypatch) -> None:  # noqa: ANN001
    """Confirmation is an LLM judgment (v3, CLAUDE.md); seam.run calls
    tools.validator.run_oracle with no client= passthrough, so pin the verdict
    by monkeypatching the client builder it constructs internally."""
    import reachagent.oracles.llm_judgment as _llm_judgment

    monkeypatch.setattr(
        _llm_judgment, "build_openai_compatible_client", lambda: FixedJudgmentClient(CONFIRMS.value)
    )

    graph = ReachabilityGraph()
    _seed_confirmed_finding_with_credential_pair(graph, "admin", "s3cret")
    graph.add_host(Host(address="b.test", hostname="b.test"))

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "b.test":
            if request.url.path == "/login" and request.method == "POST":
                body = request.content.decode()
                if "username=admin&password=s3cret" in body:
                    return httpx.Response(
                        200, headers={"set-cookie": "session=xyz789"}, text="welcome"
                    )
                return httpx.Response(401, text="invalid credentials")
            return httpx.Response(200, text=_OTHER_LOGIN_PAGE)
        return httpx.Response(404)

    seam = _ValidatorSeam(graph)
    found = run_cross_host_credential_reuse(
        graph=graph,
        firer=_firer(handler),
        base_url="http://a.test",
        identity="anon",
        seam=seam,
        events=[],
    )
    assert found
    classes = {f.vuln_class for _fid, f in graph.findings()}
    assert "credential_reuse" in classes


def test_no_extractable_pair_yields_no_attempt_and_no_finding() -> None:
    graph = ReachabilityGraph()
    graph.add_host(Host(address="b.test", hostname="b.test"))

    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.path)
        return httpx.Response(200, text=_OTHER_LOGIN_PAGE)

    seam = _ValidatorSeam(graph)
    found = run_cross_host_credential_reuse(
        graph=graph,
        firer=_firer(handler),
        base_url="http://a.test",
        identity="anon",
        seam=seam,
        events=[],
    )
    assert found == []
    assert calls == []  # no candidate pair at all — never even fires a probe


def test_wrong_password_on_other_host_yields_no_finding() -> None:
    graph = ReachabilityGraph()
    _seed_confirmed_finding_with_credential_pair(graph, "admin", "s3cret")
    graph.add_host(Host(address="b.test", hostname="b.test"))

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "b.test":
            if request.url.path == "/login" and request.method == "POST":
                return httpx.Response(401, text="invalid credentials")
            return httpx.Response(200, text=_OTHER_LOGIN_PAGE)
        return httpx.Response(404)

    seam = _ValidatorSeam(graph)
    found = run_cross_host_credential_reuse(
        graph=graph,
        firer=_firer(handler),
        base_url="http://a.test",
        identity="anon",
        seam=seam,
        events=[],
    )
    assert found == []
    assert graph.findings() == [] or all(
        f.vuln_class != "credential_reuse" for _fid, f in graph.findings()
    )


def test_own_host_is_never_treated_as_another_host() -> None:
    """The scan's own primary host must never appear as a "cross-host" reuse
    target — it would just be re-testing the host the credential came from."""
    graph = ReachabilityGraph()
    _seed_confirmed_finding_with_credential_pair(graph, "admin", "s3cret")
    graph.add_host(Host(address="a.test", hostname="a.test"))  # the primary host itself

    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.path)
        return httpx.Response(200, text=_OTHER_LOGIN_PAGE)

    seam = _ValidatorSeam(graph)
    found = run_cross_host_credential_reuse(
        graph=graph,
        firer=_firer(handler),
        base_url="http://a.test",
        identity="anon",
        seam=seam,
        events=[],
    )
    assert found == []
    assert calls == []
