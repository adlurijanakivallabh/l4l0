"""Reference-informed hardening: metadata hostnames + per-hop redirect re-check."""

from __future__ import annotations

import http.server
import threading

from lalo.execution.firer import HttpFirer
from lalo.execution.scope import Decision, ScopeGuard
from lalo.execution.target import Engagement


def test_metadata_hostname_denied() -> None:
    guard = ScopeGuard(
        engagement=Engagement.from_specs(["metadata.google.internal"]),
        resolver=lambda h: frozenset({"10.0.0.5"}),  # resolves to a non-metadata IP...
    )
    # ...but the well-known metadata *hostname* is denied regardless of resolution.
    decision = guard.check("http://metadata.google.internal/computeMetadata/")
    assert decision.decision is Decision.DENIED


class _RedirectHandler(http.server.BaseHTTPRequestHandler):
    external = "http://evil.example/"

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/in":
            self.send_response(302)
            self.send_header("Location", "/final")
            self.send_header("Content-Length", "0")
            self.end_headers()
        elif self.path == "/final":
            self._body("<html>final</html>")
        elif self.path == "/out":
            self.send_response(302)
            self.send_header("Location", self.external)
            self.send_header("Content-Length", "0")
            self.end_headers()
        else:
            self._body("ok")

    def _body(self, text: str) -> None:
        data = text.encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args: object) -> None:
        return


def _server() -> tuple[http.server.HTTPServer, str]:
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _RedirectHandler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}"


def _firer() -> HttpFirer:
    return HttpFirer(ScopeGuard(engagement=Engagement.from_specs(["127.0.0.1"])))


def test_in_scope_redirect_is_followed() -> None:
    srv, base = _server()
    firer = _firer()
    try:
        chain = firer.fire_redirects("GET", f"{base}/in")
    finally:
        srv.shutdown()
    assert len(chain) == 2
    assert chain[0].status == 302
    assert chain[-1].status == 200
    assert b"final" in chain[-1].body


def test_out_of_scope_redirect_is_not_followed() -> None:
    srv, base = _server()
    firer = _firer()
    try:
        chain = firer.fire_redirects("GET", f"{base}/out")
    finally:
        srv.shutdown()
    # First hop is the 302; the redirect target (evil.example) is out of engagement,
    # so the next hop is skipped, not fired.
    assert chain[0].status == 302
    assert chain[-1].fired is False
    assert chain[-1].scope_reason == "out_of_engagement"
