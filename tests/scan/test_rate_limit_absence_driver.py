"""Hermetic E2E for the rate-limit-absence driver (§7, Build Order 0).

Real ReachabilityGraph, httpx.MockTransport-backed RequestFirer, real oracle
registry via reachagent.tools.validator — same harness as
tests/scan/test_default_credentials_driver.py.
"""

from __future__ import annotations

import httpx

from reachagent.detection.oracle_gateway import OracleOutcome
from reachagent.execution import RequestFirer, ScopeGuard
from reachagent.graph.store import ReachabilityGraph
from reachagent.identity.store import Credential, IdentityStore
from reachagent.oracles.base import OracleVerdict
from reachagent.scan.orchestrator import _ValidatorSeam, run_rate_limit_absence
from tests._oracle_test_support import CONFIRMS, INCONCLUSIVE, FixedJudgmentClient

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


def _lockout_aware_run(self: _ValidatorSeam, mechanism: object, evidence: object) -> OracleOutcome:
    """v3 V3: judges on the real ``lockout_signal_observed`` evidence field —
    needed so the two bursts (each its own StructuralEvidence) can genuinely
    diverge in a test, instead of a flat client confirming both alike."""
    lockout = bool(getattr(evidence, "lockout_signal_observed", False))
    status = INCONCLUSIVE if lockout else CONFIRMS
    ref = str(getattr(evidence, "evidence_ref", "") or "")
    verdict = OracleVerdict(mechanism=mechanism, status=status, evidence_ref=ref, reason="test")
    self._last = verdict
    return OracleOutcome(verdict)


def _run_with_corroboration(
    handler: object,
    *,
    second_handler: object | None = None,
    identities: IdentityStore | None = None,
) -> tuple[list, _ValidatorSeam]:
    graph = ReachabilityGraph()
    seam = _ValidatorSeam(graph)
    posts = {"n": 0}

    def _dispatch(request: httpx.Request) -> httpx.Response:
        is_login_post = request.url.path == "/login" and request.method == "POST"
        if is_login_post:
            posts["n"] += 1
        # First 6 POSTs (the fixed burst size) go to the primary handler; any
        # further POST belongs to the corroborating second burst.
        active = second_handler if (second_handler is not None and posts["n"] > 6) else handler
        return active(request)

    run_rate_limit_absence(
        graph=graph,
        firer=_firer(_dispatch),
        base_url="http://rate-limit.test",
        identity="anon",
        seam=seam,
        events=[],
        identities=identities,
    )
    return graph.findings(), seam


def _no_lockout_handler(request: httpx.Request) -> httpx.Response:
    if request.url.path == "/login" and request.method == "POST":
        return httpx.Response(401, text="invalid username or password")
    return httpx.Response(200, text=_LOGIN_PAGE)


def _lockout_handler(request: httpx.Request) -> httpx.Response:
    if request.url.path == "/login" and request.method == "POST":
        return httpx.Response(429, text="too many requests")
    return httpx.Response(200, text=_LOGIN_PAGE)


def test_flag_off_by_default_never_fires_a_second_burst(monkeypatch) -> None:  # noqa: ANN001
    """No REACHAGENT_RATE_LIMIT_CORROBORATION set — behavior stays single-burst
    even when an IdentityStore is passed in (opt-in, never on by default)."""
    monkeypatch.setattr(_ValidatorSeam, "run", _lockout_aware_run)
    identities = IdentityStore()
    identities.add(Credential("anon", "anon", "pw", "user"))

    findings, _seam = _run_with_corroboration(_no_lockout_handler, identities=identities)
    classes = {f.vuln_class for _fid, f in findings}
    assert "rate_limit_absence" in classes
    assert all(f.metadata.get("corroborated") != "1" for _fid, f in findings)


def test_corroboration_confirms_when_both_bursts_show_no_lockout(monkeypatch) -> None:  # noqa: ANN001
    monkeypatch.setenv("REACHAGENT_RATE_LIMIT_CORROBORATION", "1")
    monkeypatch.setattr(_ValidatorSeam, "run", _lockout_aware_run)
    import reachagent.rate_limit.detector as _detector

    monkeypatch.setattr(_detector, "_COOLDOWN_S", 0.0)

    findings, _seam = _run_with_corroboration(_no_lockout_handler)
    [(_fid, finding)] = findings
    assert finding.vuln_class == "rate_limit_absence"
    assert finding.metadata.get("corroborated") == "1"


def test_corroboration_fails_closed_when_second_burst_shows_lockout(monkeypatch) -> None:  # noqa: ANN001
    monkeypatch.setenv("REACHAGENT_RATE_LIMIT_CORROBORATION", "1")
    monkeypatch.setattr(_ValidatorSeam, "run", _lockout_aware_run)
    import reachagent.rate_limit.detector as _detector

    monkeypatch.setattr(_detector, "_COOLDOWN_S", 0.0)

    findings, _seam = _run_with_corroboration(_no_lockout_handler, second_handler=_lockout_handler)
    assert findings == []


def test_corroboration_skipped_when_probe_username_collides_with_seeded_identity(
    monkeypatch,  # noqa: ANN001
) -> None:
    """The probe username (_RATE_LIMIT_PROBE_CREDENTIAL) must never collide with
    a real seeded identity's own login username — corroborating with a burst
    against a real account would defeat the never-a-real-credential guarantee."""
    monkeypatch.setenv("REACHAGENT_RATE_LIMIT_CORROBORATION", "1")
    monkeypatch.setattr(_ValidatorSeam, "run", _lockout_aware_run)
    import reachagent.rate_limit.detector as _detector

    monkeypatch.setattr(_detector, "_COOLDOWN_S", 0.0)

    identities = IdentityStore()
    identities.add(Credential("real_user", "ra-probe-user", "realpw", "user"))

    findings, _seam = _run_with_corroboration(_no_lockout_handler, identities=identities)
    [(_fid, finding)] = findings
    assert finding.vuln_class == "rate_limit_absence"
    # Collision → corroboration skipped entirely, single-burst result stands.
    assert finding.metadata.get("corroborated") != "1"
