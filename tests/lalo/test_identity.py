"""Tests for identity store, session mirroring, JWT tampering, login, role matrix."""

from __future__ import annotations

import http.server
import threading

from lalo.execution.firer import HttpFirer
from lalo.execution.scope import ScopeGuard
from lalo.execution.target import Engagement
from lalo.graph.schema import NodeType
from lalo.graph.store import ReachGraph
from lalo.identity import (
    IdentityStore,
    SessionMaterial,
    build_role_matrix,
    decode_jwt,
    form_login,
    json_login,
    tamper_alg_none,
    tamper_claim,
)

# alg=HS256, {"sub":"user","role":"user"} — signature is a dummy for tests.
_JWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyIiwicm9sZSI6InVzZXIifQ.c2ln"


def test_session_mirrors_onto_graph_by_construction() -> None:
    graph = ReachGraph()
    store = IdentityStore(graph)
    store.register("alice", role="user")
    store.ensure_session("alice", SessionMaterial(headers={"Authorization": "Bearer x"}))
    assert len(list(graph.nodes_of_type(NodeType.SESSION))) == 1
    assert store.store("alice").material.is_usable()  # type: ignore[union-attr]


def test_token_store_isolation_and_apply() -> None:
    graph = ReachGraph()
    store = IdentityStore(graph)
    store.ensure_session("a", SessionMaterial(headers={"Authorization": "Bearer AAA"}))
    store.ensure_session("b", SessionMaterial(cookies={"session": "BBB"}))
    a = store.store("a").apply()  # type: ignore[union-attr]
    b = store.store("b").apply()  # type: ignore[union-attr]
    assert a["Authorization"] == "Bearer AAA"
    assert "Authorization" not in b
    assert b["Cookie"] == "session=BBB"


def test_jwt_decode_and_tamper() -> None:
    header, payload = decode_jwt(_JWT)
    assert header["alg"] == "HS256"
    assert payload["role"] == "user"
    none_token = tamper_alg_none(_JWT)
    assert decode_jwt(none_token)[0]["alg"] == "none"
    assert none_token.endswith(".")
    admin = tamper_claim(_JWT, role="admin")
    assert decode_jwt(admin)[1]["role"] == "admin"


def test_build_role_matrix() -> None:
    cells = build_role_matrix(["/a", "/b"], ["alice", "bob"])
    assert len(cells) == 4
    assert any(c.endpoint == "/a" and c.identity == "bob" for c in cells)


class _LoginHandler(http.server.BaseHTTPRequestHandler):
    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", "0"))
        self.rfile.read(length)
        if self.path == "/login-json":
            body = b'{"token":"jwt-abc"}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(200)
            self.send_header("Set-Cookie", "session=cookieval; Path=/; HttpOnly")
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"ok")

    def log_message(self, *args: object) -> None:
        return


def _login_server() -> tuple[http.server.HTTPServer, str]:
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _LoginHandler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}"


def _firer() -> HttpFirer:
    return HttpFirer(ScopeGuard(engagement=Engagement.from_specs(["127.0.0.1"])))


def test_json_and_form_login() -> None:
    srv, base = _login_server()
    firer = _firer()
    try:
        jm = json_login(firer, f"{base}/login-json", {"user": "a", "pass": "b"})
        fm = form_login(firer, f"{base}/login-form", {"user": "a", "pass": "b"})
    finally:
        srv.shutdown()
    assert jm.headers["Authorization"] == "Bearer jwt-abc"
    assert fm.cookies["session"] == "cookieval"
