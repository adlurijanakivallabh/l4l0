"""Guardian advisor wired into RequestFirer.fire() (Build Order 3).

Confirms the "add-on, never override" contract at the actual gate: the
advisor is consulted only for state-changing requests (never a plain GET —
structural isolation from target content, since no response exists yet at
this point either way, but also a deliberate performance boundary), it can
only add a denial on top of an already-passed ScopeGuard check, and it
fails open so a disabled/unavailable advisor never blocks legitimate
testing.
"""

from __future__ import annotations

import httpx
import pytest

from reachagent.execution import RequestFirer, ScopeGuard
from reachagent.execution.firer import GuardianRefusedError
from reachagent.guardian import advisor as _advisor_module


def _firer(handler: object) -> RequestFirer:
    client = httpx.Client(transport=httpx.MockTransport(handler))  # type: ignore[arg-type]
    return RequestFirer(client, ScopeGuard.from_hosts(["target.test"]))


def test_flag_off_state_changing_fire_never_calls_the_llm_client(monkeypatch) -> None:  # noqa: ANN001
    # Real (unpatched) advise_on_action — proves the flag check itself, not
    # a mocked-away decision, is what keeps a normal scan from ever touching
    # an LLM provider for this gate when the operator hasn't opted in.
    monkeypatch.delenv("REACHAGENT_GUARDIAN_ADVISOR", raising=False)
    client_calls: list[str] = []

    class _SpyClient:
        def propose(self, action: dict[str, str]) -> dict[str, object]:
            client_calls.append("called")
            return {"allow": False, "reason": "should never be reached"}

    monkeypatch.setattr(
        _advisor_module,
        "OpenAIGuardianClient",
        lambda **_kw: _SpyClient(),  # noqa: ARG005
    )

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="ok")

    firer = _firer(handler)
    firer.fire("anon", "GET", "http://target.test/submit", state_changing=False)
    result = firer.fire("anon", "POST", "http://target.test/submit", state_changing=True)
    assert result.status_code == 200
    assert client_calls == []


def test_read_only_get_never_consults_the_advisor(monkeypatch) -> None:  # noqa: ANN001
    monkeypatch.setenv("REACHAGENT_GUARDIAN_ADVISOR", "1")
    calls: list[str] = []

    def _spy_advise(*args: object, **kwargs: object) -> object:
        calls.append("called")
        return _advisor_module.GuardianDecision(allow=False, reason="should never be asked")

    monkeypatch.setattr(_advisor_module, "advise_on_action", _spy_advise)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="ok")

    firer = _firer(handler)
    result = firer.fire("anon", "GET", "http://target.test/", state_changing=False)
    assert result.status_code == 200
    assert calls == []


def test_flag_on_advisor_deny_blocks_a_state_changing_fire_before_any_io(
    monkeypatch,  # noqa: ANN001
) -> None:
    monkeypatch.setenv("REACHAGENT_GUARDIAN_ADVISOR", "1")

    def _deny(*args: object, **kwargs: object) -> object:
        return _advisor_module.GuardianDecision(allow=False, reason="looks destructive")

    monkeypatch.setattr(_advisor_module, "advise_on_action", _deny)

    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.method)
        return httpx.Response(200, text="ok")

    # First establish read-only clearance so the block below is attributable
    # to the guardian, not read-only-first.
    firer = _firer(handler)
    firer.fire("anon", "GET", "http://target.test/submit", state_changing=False)
    seen.clear()

    with pytest.raises(GuardianRefusedError):
        firer.fire("anon", "POST", "http://target.test/submit", state_changing=True)
    assert seen == []  # no packet left the process
    entries = list(firer.audit.entries)
    assert any(e.outcome == "refused_by_guardian" for e in entries)


def test_flag_on_advisor_allow_fires_normally(monkeypatch) -> None:  # noqa: ANN001
    monkeypatch.setenv("REACHAGENT_GUARDIAN_ADVISOR", "1")

    def _allow(*args: object, **kwargs: object) -> object:
        return _advisor_module.GuardianDecision(allow=True, reason="ordinary test traffic")

    monkeypatch.setattr(_advisor_module, "advise_on_action", _allow)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="ok")

    firer = _firer(handler)
    firer.fire("anon", "GET", "http://target.test/submit", state_changing=False)
    result = firer.fire("anon", "POST", "http://target.test/submit", state_changing=True)
    assert result.status_code == 200


def test_advisor_runs_only_after_scope_gate_not_before(monkeypatch) -> None:  # noqa: ANN001
    # Out-of-scope must still be refused by ScopeGuard alone — the guardian
    # is never even reached for a host it wasn't already going to allow.
    monkeypatch.setenv("REACHAGENT_GUARDIAN_ADVISOR", "1")
    calls: list[str] = []

    def _spy(*args: object, **kwargs: object) -> object:
        calls.append("called")
        return _advisor_module.GuardianDecision(allow=True)

    monkeypatch.setattr(_advisor_module, "advise_on_action", _spy)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="ok")

    firer = _firer(handler)
    from reachagent.execution.scope import OutOfScopeError

    with pytest.raises(OutOfScopeError):
        firer.fire("anon", "POST", "http://out-of-scope.test/submit", state_changing=True)
    assert calls == []


def test_authentication_login_bypasses_the_guardian_gate(monkeypatch) -> None:  # noqa: ANN001
    # A configured login POST is an explicit, audited exception to
    # read-only-first already — the guardian must not add friction there.
    monkeypatch.setenv("REACHAGENT_GUARDIAN_ADVISOR", "1")

    def _deny(*args: object, **kwargs: object) -> object:
        return _advisor_module.GuardianDecision(allow=False, reason="should not be asked")

    monkeypatch.setattr(_advisor_module, "advise_on_action", _deny)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="ok")

    firer = _firer(handler)
    result = firer.fire(
        "anon", "POST", "http://target.test/login", state_changing=True, authentication=True
    )
    assert result.status_code == 200
