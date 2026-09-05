"""Tests for the self-hosted OAST server (HTTP + DNS callbacks)."""

from __future__ import annotations

import socket
import struct

import httpx

from lalo.oast import OASTServer


def _dns_query(name: str) -> bytes:
    header = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    qname = (
        b"".join(bytes([len(label)]) + label.encode("ascii") for label in name.split(".")) + b"\x00"
    )
    return header + qname + struct.pack(">HH", 1, 1)  # type A, class IN


def test_http_callback_correlates_to_probe() -> None:
    with OASTServer() as oast:
        token = oast.issue_token(probe_ref="fire-42")
        httpx.get(oast.callback_url(token), timeout=5.0)
        hits = oast.poll(token)
        assert len(hits) == 1
        assert hits[0].kind == "http"
        assert oast.probe_ref(token) == "fire-42"


def test_dns_callback_recorded() -> None:
    with OASTServer() as oast:
        token = oast.issue_token(probe_ref="fire-7")
        name = oast.dns_name(token)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(5.0)
        sock.sendto(_dns_query(name), (oast.host, oast.dns_port))
        try:
            sock.recvfrom(4096)
        except OSError:
            pass
        sock.close()
        hits = oast.poll(token)
        assert len(hits) == 1
        assert hits[0].kind == "dns"
        assert token in hits[0].detail


def test_stop_before_start_does_not_deadlock() -> None:
    # HTTPServer.shutdown() blocks on an Event only set from inside
    # serve_forever()'s own loop -- calling it when that loop never started
    # used to hang forever instead of returning.
    oast = OASTServer()
    oast.stop()  # must return promptly, not hang


def test_dns_answers_use_advertise_host_not_the_wildcard_bind_address() -> None:
    # Binding to 0.0.0.0 is what makes the listener reachable from a real
    # scanned target, but answering DNS queries with 0.0.0.0 itself is not a
    # usable destination for anything -- advertise_host must be used instead.
    with OASTServer(host="0.0.0.0", advertise_host="203.0.113.5") as oast:  # noqa: S104 - this test is specifically about the 0.0.0.0-bind case
        token = oast.issue_token()
        name = oast.dns_name(token)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(5.0)
        sock.sendto(_dns_query(name), ("127.0.0.1", oast.dns_port))
        data, _addr = sock.recvfrom(4096)
        sock.close()
        assert data[-4:] == bytes([203, 0, 113, 5])


def test_advertise_host_defaults_to_host_when_unset() -> None:
    with OASTServer(host="127.0.0.1") as oast:
        assert oast.advertise_host == "127.0.0.1"


def test_no_cross_token_leakage() -> None:
    with OASTServer() as oast:
        t1 = oast.issue_token()
        t2 = oast.issue_token()
        httpx.get(oast.callback_url(t1), timeout=5.0)
        assert len(oast.poll(t1)) == 1
        assert oast.poll(t2) == []
