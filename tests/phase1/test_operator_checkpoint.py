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


# === Concurrent specialists (Build Order 2c) — the checkpoint must be a real
# barrier, not just a "notified once" flag, when multiple threads share one
# firer. Adversarial-review finding: a second thread must never fall through
# just because the first already flipped "notified" while still paused.


def test_second_thread_blocks_until_the_first_threads_checkpoint_resolves() -> None:
    import threading
    import time

    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.method)
        return httpx.Response(200, text="ok")

    release = threading.Event()
    checkpoint_entered = threading.Event()

    def _checkpoint(method: str, target: str, identity: str) -> None:
        checkpoint_entered.set()
        release.wait(timeout=5)  # simulates the operator not having resumed yet

    firer = _firer(handler, _checkpoint)
    firer.fire("anon", "GET", "http://target.test/a", state_changing=False)
    firer.fire("anon", "GET", "http://target.test/b", state_changing=False)
    seen.clear()

    results: list[str] = []

    def _fire_a() -> None:
        firer.fire("anon", "POST", "http://target.test/a", state_changing=True)
        results.append("a")

    def _fire_b() -> None:
        firer.fire("anon", "POST", "http://target.test/b", state_changing=True)
        results.append("b")

    thread_a = threading.Thread(target=_fire_a)
    thread_b = threading.Thread(target=_fire_b)
    thread_a.start()
    assert checkpoint_entered.wait(timeout=5)  # thread_a is now the checkpoint owner
    thread_b.start()

    # While the operator hasn't resumed, NEITHER thread may have sent a
    # packet yet — thread_b must be blocked at the barrier, not skipping
    # through because "notified" was already true.
    time.sleep(0.1)
    assert seen == []
    assert results == []

    release.set()
    thread_a.join(timeout=5)
    thread_b.join(timeout=5)

    assert sorted(seen) == ["POST", "POST"]
    assert sorted(results) == ["a", "b"]


def test_second_thread_reraises_the_first_threads_cancellation() -> None:
    import threading

    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.method)
        return httpx.Response(200, text="ok")

    checkpoint_entered = threading.Event()

    def _cancel(method: str, target: str, identity: str) -> None:
        checkpoint_entered.set()
        raise RuntimeError("scan cancelled during operator checkpoint")

    firer = _firer(handler, _cancel)
    firer.fire("anon", "GET", "http://target.test/a", state_changing=False)
    firer.fire("anon", "GET", "http://target.test/b", state_changing=False)
    seen.clear()

    errors: list[BaseException] = []
    started = threading.Barrier(2, timeout=5)

    def _fire(path: str) -> None:
        started.wait()
        try:
            firer.fire("anon", "POST", f"http://target.test/{path}", state_changing=True)
        except BaseException as exc:  # noqa: BLE001 - captured for the assertion below
            errors.append(exc)

    thread_a = threading.Thread(target=_fire, args=("a",))
    thread_b = threading.Thread(target=_fire, args=("b",))
    thread_a.start()
    thread_b.start()
    thread_a.join(timeout=5)
    thread_b.join(timeout=5)

    # Both threads must abort — the second must never fire just because it
    # wasn't the one that hit the (cancelled) checkpoint first.
    assert len(errors) == 2
    assert all("cancelled" in str(e) for e in errors)
    assert seen == []
