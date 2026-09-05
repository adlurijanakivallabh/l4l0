"""End-to-end scan slice: scripted agent + REAL firer against a local server.

Proves the whole pipeline wires up (scope -> firer -> capture -> record_finding ->
confidence scoring -> graph) without needing an LLM key or Docker. A real-LLM run
uses the same run_scan with a live provider.
"""

from __future__ import annotations

import http.server
import threading
from urllib.parse import parse_qs, urlsplit

from lalo.core.model_router import CompletionRequest, CompletionResponse, ModelRouter
from lalo.scan import run_scan


class _ReflectingHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 - stdlib handler name
        q = parse_qs(urlsplit(self.path).query).get("q", [""])[0]
        body = f"<html>results for {q}</html>".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args: object) -> None:  # silence test server
        return


def _start_server() -> tuple[http.server.HTTPServer, int]:
    server = http.server.HTTPServer(("127.0.0.1", 0), _ReflectingHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, server.server_address[1]


class _ScriptedProvider:
    name = "scripted"

    def __init__(self, responses: list[str]) -> None:
        self._responses = responses
        self.calls = 0

    def complete(self, request: CompletionRequest) -> CompletionResponse:
        text = self._responses[min(self.calls, len(self._responses) - 1)]
        self.calls += 1
        return CompletionResponse(text=text, provider=self.name, model="scripted")


def test_end_to_end_reflected_xss_slice() -> None:
    server, port = _start_server()
    try:
        payload = "<script>lalo</script>"
        encoded = "%3Cscript%3Elalo%3C%2Fscript%3E"
        base = f"http://127.0.0.1:{port}"
        responses = [
            f'{{"tool":"http","args":{{"method":"GET","url":"{base}/?q={encoded}"}}}}',
            (
                '{"tool":"record_finding","args":{"title":"Reflected XSS in q",'
                '"vuln_class":"xss","severity":"high","target":"' + base + '/",'
                '"evidence":[{"kind":"structural","summary":"payload reflected unencoded",'
                '"fire_ref":"fire0","observed":"' + payload + '"}]}}'
            ),
            '{"tool":"finish","args":{"summary":"found reflected xss"}}',
        ]
        router = ModelRouter(
            providers={"scripted": _ScriptedProvider(responses)},
            routes={"reasoning": ("scripted",)},
        )

        result = run_scan(
            targets=["127.0.0.1"],
            objective="find reflected XSS in the q parameter",
            router=router,
        )
    finally:
        server.shutdown()

    assert result.stop_reason == "finished"
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.vuln_class == "xss"
    assert finding.confidence is not None and finding.confidence > 0
    # Evidence really was captured from the target -> provenance verified, not flagged.
    assert "evidence_unverified" not in finding.metadata.get("confidence_flags", [])
    # The endpoint was recorded in the graph.
    assert result.graph.summary().get("endpoint", 0) >= 1
