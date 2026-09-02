"""Hermetic E2E for the rate-limit-absence driver (§7, Build Order 0).

Real ReachabilityGraph, httpx.MockTransport-backed RequestFirer, real oracle
registry via reachagent.tools.validator — same harness as
tests/scan/test_default_credentials_driver.py.
"""

from __future__ import annotations

import httpx

from reachagent.execution import RequestFirer, ScopeGuard
from reachagent.graph.store import ReachabilityGraph
from reachagent.scan.orchestrator import _ValidatorSeam, run_rate_limit_absence
from tests._oracle_test_support import CONFIRMS, FixedJudgmentClient

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
    return RequestFirer(client, ScopeGuard.from_hosts(["rate-limit.test"]))


def _run(handler: object) -> list:
    graph = ReachabilityGraph()
    seam = _ValidatorSeam(graph)
    run_rate_limit_absence(
        graph=graph,
        firer=_firer(handler),
        base_url="http://rate-limit.test",
        identity="anon",
        seam=seam,
        events=[],
    )
    return graph.findings()


def test_no_lockout_across_burst_confirms_a_finding(monkeypatch) -> None:  # noqa: ANN001
    """Confirmation is now an LLM judgment (v3, CLAUDE.md) rather than a fixed
    decide(); _ValidatorSeam.run calls tools.validator.run_oracle with no
    client= passthrough, so pin the verdict by monkeypatching the client
    builder it constructs internally."""
    import reachagent.oracles.llm_judgment as _llm_judgment

    monkeypatch.setattr(
        _llm_judgment, "build_openai_compatible_client", lambda: FixedJudgmentClient(CONFIRMS.value)
    )

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/login" and request.method == "POST":
            return httpx.Response(401, text="invalid username or password")
        return httpx.Response(200, text=_LOGIN_PAGE)

    findings = _run(handler)
    classes = {f.vuln_class for _fid, f in findings}
    assert "rate_limit_absence" in classes
    assert all(f.severity == "medium" for _fid, f in findings)


def test_lockout_signal_yields_no_finding() -> None:
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/login" and request.method == "POST":
            calls["n"] += 1
            if calls["n"] >= 3:
                return httpx.Response(429, text="too many requests")
            return httpx.Response(401, text="invalid username or password")
        return httpx.Response(200, text=_LOGIN_PAGE)

    assert _run(handler) == []


def test_no_login_form_is_not_applicable_and_never_crashes() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="<html>no form here</html>")

    assert _run(handler) == []
