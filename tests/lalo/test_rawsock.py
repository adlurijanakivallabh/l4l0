"""Tests for scoped, pinned-IP raw-TCP send/recv against a local echo server."""

from __future__ import annotations

import socket
import threading

from lalo.execution.rawsock import tcp_send_recv
from lalo.execution.scope import ScopeGuard
from lalo.execution.target import Engagement


def _start_echo_server() -> int:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]

    def serve() -> None:
        try:
            conn, _ = srv.accept()
            with conn:
                data = conn.recv(1024)
                conn.sendall(data)
        finally:
            srv.close()

    threading.Thread(target=serve, daemon=True).start()
    return port


def _scope_localhost() -> ScopeGuard:
    eng = Engagement.from_specs(["127.0.0.1"])
    return ScopeGuard(engagement=eng)


def test_tcp_echo_roundtrip() -> None:
    port = _start_echo_server()
    result = tcp_send_recv(_scope_localhost(), "127.0.0.1", port, b"ping", timeout=2.0)
    assert result.fired is True
    assert result.data == b"ping"
    assert result.error is None


def test_out_of_engagement_tcp_is_skipped() -> None:
    eng = Engagement.from_specs(["127.0.0.1"])
    scope = ScopeGuard(engagement=eng)
    result = tcp_send_recv(scope, "10.9.9.9", 9999, b"x", timeout=0.5)
    assert result.fired is False
    assert result.scope_reason == "out_of_engagement"


def test_tcp_dns_resolution_failure_does_not_connect_blind() -> None:
    scope = ScopeGuard(
        engagement=Engagement.from_specs(["nowhere.invalid"]), resolver=lambda h: frozenset()
    )
    result = tcp_send_recv(scope, "nowhere.invalid", 80, timeout=0.5)
    assert result.fired is False
    assert result.error == "dns_resolution_failed"
