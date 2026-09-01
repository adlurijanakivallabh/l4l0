"""Operator checkpoint wired into RequestFirer.fire() ("My additions").

The scan's very first state-changing (non-read-only, non-authentication)
request calls the checkpoint hook exactly once, before Gate 1.5's guardian
and Gate 2's read-only-first check — then never again for this firer,
whether that first request is ultimately cleared or refused.
"""

from __future__ import annotations

import httpx
import pytest

from reachagent.execution import RequestFirer, ScopeGuard


def _firer(handler: object, checkpoint: object) -> RequestFirer:
    client = httpx.Client(transport=httpx.MockTransport(handler))  # type: ignore[arg-type]
    return RequestFirer(
        client,
        ScopeGuard.from_hosts(["target.test"]),
        first_state_change_checkpoint=checkpoint,
    )


def test_no_checkpoint_configured_is_a_no_op() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="ok")

    firer = _firer(handler, None)
    firer.fire("anon", "GET", "http://target.test/", state_changing=False)
    result = firer.fire("anon", "POST", "http://target.test/", state_changing=True)
    assert result.status_code == 200


def test_read_only_get_never_triggers_the_checkpoint() -> None:
    calls: list[tuple[str, str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="ok")

    firer = _firer(handler, lambda m, t, i: calls.append((m, t, i)))
    firer.fire("anon", "GET", "http://target.test/", state_changing=False)
    assert calls == []


def test_authentication_login_never_triggers_the_checkpoint() -> None:
    calls: list[tuple[str, str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="ok")

    firer = _firer(handler, lambda m, t, i: calls.append((m, t, i)))
    firer.fire("anon", "POST", "http://target.test/login", state_changing=True, authentication=True)
    assert calls == []


def test_first_state_changing_request_triggers_checkpoint_once() -> None:
    calls: list[tuple[str, str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="ok")

    firer = _firer(handler, lambda m, t, i: calls.append((m, t, i)))
    firer.fire("anon", "GET", "http://target.test/submit", state_changing=False)
    firer.fire("anon", "POST", "http://target.test/submit", state_changing=True)
    assert len(calls) == 1
    assert calls[0][0] == "POST"
    assert "target.test" in calls[0][1]


def test_checkpoint_never_fires_again_after_the_first_mutation() -> None:
    calls: list[tuple[str, str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="ok")

    firer = _firer(handler, lambda m, t, i: calls.append((m, t, i)))
    firer.fire("anon", "GET", "http://target.test/a", state_changing=False)
    firer.fire("anon", "POST", "http://target.test/a", state_changing=True)
    firer.fire("anon", "GET", "http://target.test/b", state_changing=False)
    firer.fire("anon", "POST", "http://target.test/b", state_changing=True)
    assert len(calls) == 1


def test_checkpoint_runs_before_scope_and_read_only_first_are_bypassed() -> None:
    # Confirms ordering: the checkpoint must not itself act as a bypass for
    # read-only-first — a rejected first mutation attempt (no clearance yet)
    # still calls the checkpoint (it is a Gate ahead of Gate 2, not instead
    # of it), and the request still never reaches the network either way.
    calls: list[tuple[str, str, str]] = []
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.method)
        return httpx.Response(200, text="ok")

    firer = _firer(handler, lambda m, t, i: calls.append((m, t, i)))
    from reachagent.execution.firer import ReadOnlyFirstError

    with pytest.raises(ReadOnlyFirstError):
        firer.fire("anon", "POST", "http://target.test/submit", state_changing=True)
    assert len(calls) == 1
    assert seen == []


def test_checkpoint_raising_aborts_the_fire_without_sending() -> None:
    # Mirrors a cancel-during-pause: the GUI's checkpoint callback raises
    # when the operator cancels while blocked. No packet may leave.
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.method)
        return httpx.Response(200, text="ok")

    def _cancel(method: str, target: str, identity: str) -> None:
        raise RuntimeError("scan cancelled during operator checkpoint")

    firer = _firer(handler, _cancel)
    firer.fire("anon", "GET", "http://target.test/submit", state_changing=False)
    seen.clear()
    with pytest.raises(RuntimeError, match="cancelled"):
        firer.fire("anon", "POST", "http://target.test/submit", state_changing=True)
    assert seen == []
