"""Thread-safety of TokenStore/IdentityStore (Build Order 2c prerequisite).

Concurrent specialist children can call RequestFirer.fire() for the SAME
identity from multiple threads at once. Before this fix, TokenStore's
refresh path and IdentityStore's registration dicts were entirely unlocked
-- these tests exercise the exact races that would previously corrupt state
or double-invoke a refresh callback, using real threads (not mocked locks),
so a regression to unlocked access would show up as a flaky/failing test.
"""

from __future__ import annotations

import threading

from reachagent.graph.nodes import AuthState, Provenance
from reachagent.identity.store import Credential, IdentityStore, SessionMaterial, TokenStore


def _expired_material(refresh_token: str = "refresh-1") -> SessionMaterial:  # noqa: S107
    from datetime import UTC, datetime, timedelta

    return SessionMaterial(
        kind="bearer",
        token="stale-token",
        expires_at=datetime.now(UTC) - timedelta(seconds=1),
        refresh_token=refresh_token,
    )


def test_concurrent_refresh_never_invokes_the_callback_more_than_once() -> None:
    import time

    store = TokenStore("victim")
    store.set_material(_expired_material())
    call_count = {"n": 0}

    def _refresh(_refresh_token: str) -> SessionMaterial:
        # A real (small) delay widens the race window an unlocked version
        # would need to double-invoke this callback across threads.
        time.sleep(0.05)
        call_count["n"] += 1
        return SessionMaterial(kind="bearer", token=f"fresh-{call_count['n']}")

    store.set_refresh_callback(_refresh)

    results: list[str | None] = []
    lock = threading.Lock()

    def _worker() -> None:
        token = store.get_token()
        with lock:
            results.append(token)

    threads = [threading.Thread(target=_worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=5)

    # All 8 threads see the same expired token at once, but the lock inside
    # refresh_if_needed() must serialize the actual refresh: exactly one
    # thread wins and refreshes; every other thread's own `expired` check,
    # taken fresh under the same lock, then sees the already-refreshed
    # material and skips the callback entirely.
    assert call_count["n"] == 1
    assert all(r == "fresh-1" for r in results)


def test_concurrent_identity_add_never_corrupts_the_registry() -> None:
    store = IdentityStore()
    errors: list[Exception] = []

    def _add(index: int) -> None:
        try:
            store.add(
                Credential(
                    identity=f"derived-{index}",
                    username=f"user{index}",
                    password="x",  # noqa: S106 - test fixture, not a real secret
                    role="user",
                    auth_state=AuthState.USER,
                ),
                provenance=Provenance.DERIVED,
            )
        except Exception as exc:  # noqa: BLE001 - captured for the assertion below
            errors.append(exc)

    threads = [threading.Thread(target=_add, args=(i,)) for i in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=5)

    assert errors == []
    assert sorted(store.names()) == sorted(f"derived-{i}" for i in range(20))
    # Every identity got its own isolated TokenStore -- no cross-identity bleed.
    for i in range(20):
        assert store.token_store(f"derived-{i}").identity == f"derived-{i}"


def test_concurrent_names_read_during_add_never_raises() -> None:
    store = IdentityStore()
    stop = threading.Event()
    read_errors: list[Exception] = []

    def _reader() -> None:
        while not stop.is_set():
            try:
                list(store.names())
                list(store)
            except Exception as exc:  # noqa: BLE001 - captured for the assertion below
                read_errors.append(exc)

    def _writer() -> None:
        for i in range(200):
            store.add(
                Credential(
                    identity=f"id-{i}",
                    username=f"user{i}",
                    password="x",  # noqa: S106 - test fixture, not a real secret
                    role="user",
                    auth_state=AuthState.USER,
                )
            )

    readers = [threading.Thread(target=_reader) for _ in range(4)]
    for r in readers:
        r.start()
    writer = threading.Thread(target=_writer)
    writer.start()
    writer.join(timeout=10)
    stop.set()
    for r in readers:
        r.join(timeout=5)

    assert read_errors == []
