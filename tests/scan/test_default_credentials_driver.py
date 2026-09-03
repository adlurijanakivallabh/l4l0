"""Hermetic E2E for the default-credentials driver (§7, Build Order 0).

Real ReachabilityGraph, httpx.MockTransport-backed RequestFirer, real oracle
registry via reachagent.tools.validator — same harness as
tests/scan/test_signal_reconfirm.py.
"""

from __future__ import annotations

import httpx

from reachagent.execution import RequestFirer, ScopeGuard
from reachagent.graph.store import ReachabilityGraph
from reachagent.identity.store import Credential, IdentityStore
from reachagent.scan.orchestrator import _ValidatorSeam, run_default_credentials
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


def test_admin_admin_confirms_a_finding_when_it_authenticates(monkeypatch) -> None:  # noqa: ANN001
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


def _run_with_identities(handler: object, *, identities: IdentityStore | None) -> list:
    graph = ReachabilityGraph()
    seam = _ValidatorSeam(graph)
    run_default_credentials(
        graph=graph,
        firer=_firer(handler),
        base_url="http://default-creds.test",
        identity="anon",
        seam=seam,
        events=[],
        identities=identities,
    )
    return graph.findings()


def test_corroboration_confirms_when_the_control_pair_is_refused(monkeypatch) -> None:  # noqa: ANN001
    import reachagent.oracles.llm_judgment as _llm_judgment

    monkeypatch.setattr(
        _llm_judgment, "build_openai_compatible_client", lambda: FixedJudgmentClient(CONFIRMS.value)
    )

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/login" and request.method == "POST":
            body = request.content.decode()
            if "username=admin&password=admin" in body:
                return httpx.Response(200, headers={"set-cookie": "session=abc123"}, text="welcome")
            return httpx.Response(401, text="invalid credentials")  # incl. the control pair
        return httpx.Response(200, text=_LOGIN_PAGE)

    findings = _run(handler)
    [(_fid, finding)] = findings
    assert finding.vuln_class == "default_credentials"
    assert finding.metadata.get("corroborated") == "1"


def test_corroboration_fails_closed_when_the_control_pair_also_succeeds(monkeypatch) -> None:  # noqa: ANN001
    """A form that grants a session to ANY credentials (the control pair
    included) doesn't actually discriminate — the original match is not
    trusted, ruling out the exact false-positive class this corroboration
    exists to catch."""
    import reachagent.oracles.llm_judgment as _llm_judgment

    monkeypatch.setattr(
        _llm_judgment, "build_openai_compatible_client", lambda: FixedJudgmentClient(CONFIRMS.value)
    )

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/login" and request.method == "POST":
            return httpx.Response(200, headers={"set-cookie": "session=abc123"}, text="welcome")
        return httpx.Response(200, text=_LOGIN_PAGE)

    assert _run(handler) == []


def test_corroboration_skipped_when_control_username_collides_with_a_seeded_identity(
    monkeypatch,  # noqa: ANN001
) -> None:
    import reachagent.oracles.llm_judgment as _llm_judgment

    monkeypatch.setattr(
        _llm_judgment, "build_openai_compatible_client", lambda: FixedJudgmentClient(CONFIRMS.value)
    )
    identities = IdentityStore()
    identities.add(Credential("real_user", "reachagent-refutation-probe", "realpw", "user"))

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/login" and request.method == "POST":
            body = request.content.decode()
            if "username=admin&password=admin" in body:
                return httpx.Response(200, headers={"set-cookie": "session=abc123"}, text="welcome")
            return httpx.Response(401, text="invalid credentials")
        return httpx.Response(200, text=_LOGIN_PAGE)

    findings = _run_with_identities(handler, identities=identities)
    [(_fid, finding)] = findings
    assert finding.vuln_class == "default_credentials"
    # Collision → corroboration skipped entirely, single-attempt result stands.
    assert finding.metadata.get("corroborated") != "1"
