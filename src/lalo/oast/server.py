"""OAST server: HTTP + DNS callback listeners with per-probe token correlation."""

from __future__ import annotations

import http.server
import socket
import threading
import time
import uuid
from dataclasses import dataclass, field

from ..core.logging import get_logger

_log = get_logger("lalo.oast")


@dataclass
class Interaction:
    token: str
    kind: str  # "http" | "dns"
    source: str
    detail: str
    at: float = field(default_factory=time.time)


class _Registry:
    """Issued tokens (+ the probe that owns each) and recorded interactions."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._tokens: dict[str, str | None] = {}
        self._interactions: list[Interaction] = []

    def issue(self, probe_ref: str | None) -> str:
        token = uuid.uuid4().hex[:16]
        with self._lock:
            self._tokens[token] = probe_ref
        return token

    def match_token(self, text: str) -> str | None:
        lowered = text.lower()
        with self._lock:
            for token in self._tokens:
                if token in lowered:
                    return token
        return None

    def record(self, interaction: Interaction) -> None:
        with self._lock:
            self._interactions.append(interaction)
        _log.info(
            "oast %s interaction for token %s from %s",
            interaction.kind,
            interaction.token,
            interaction.source,
        )

    def poll(self, token: str) -> list[Interaction]:
        with self._lock:
            return [i for i in self._interactions if i.token == token]

    def all(self) -> list[Interaction]:
        with self._lock:
            return list(self._interactions)

    def probe_ref(self, token: str) -> str | None:
        with self._lock:
            return self._tokens.get(token)


def _make_http_handler(registry: _Registry) -> type[http.server.BaseHTTPRequestHandler]:
    class _Handler(http.server.BaseHTTPRequestHandler):
        def _handle(self) -> None:
            host = self.headers.get("Host", "")
            token = registry.match_token(self.path) or registry.match_token(host)
            if token is not None:
                registry.record(
                    Interaction(
                        token=token,
                        kind="http",
                        source=self.client_address[0],
                        detail=f"{self.command} {self.path} Host:{host}",
                    )
                )
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"ok")

        do_GET = _handle
        do_POST = _handle

        def log_message(self, *args: object) -> None:
            return

    return _Handler


def _parse_qname(data: bytes) -> tuple[str, int]:
    """Return (qname, offset_after_question) for a DNS query, best-effort."""
    idx = 12
    labels: list[str] = []
    while idx < len(data):
        length = data[idx]
        idx += 1
        if length == 0:
            break
        labels.append(data[idx : idx + length].decode("ascii", "replace"))
        idx += length
    return ".".join(labels), idx + 4  # + qtype(2) + qclass(2)


def _dns_response(query: bytes, question_end: int, ip: str = "127.0.0.1") -> bytes:
    header = query[0:2] + b"\x81\x80" + query[4:6] + b"\x00\x01" + b"\x00\x00\x00\x00"
    question = query[12:question_end]
    answer = (
        b"\xc0\x0c"  # pointer to the question name
        + b"\x00\x01"  # type A
        + b"\x00\x01"  # class IN
        + b"\x00\x00\x00\x3c"  # TTL 60
        + b"\x00\x04"  # rdlength 4
        + bytes(int(o) for o in ip.split("."))
    )
    return header + question + answer


class OASTServer:
    """Runs the HTTP + DNS callback listeners on ephemeral (or fixed) ports."""

    def __init__(
        self,
        host: str = "127.0.0.1",
        http_port: int = 0,
        dns_port: int = 0,
        *,
        advertise_host: str | None = None,
    ) -> None:
        self.host = host
        # The address DNS answers resolve callbacks to, distinct from the bind
        # address: binding to a wildcard (0.0.0.0) is what actually makes the
        # listener reachable from a real scanned target, but answering with
        # 0.0.0.0 itself is not a usable destination for anything. Defaults to
        # `host` unchanged for the common case (bound to a real/loopback IP).
        self.advertise_host = advertise_host or host
        self._registry = _Registry()
        self._http = http.server.ThreadingHTTPServer(
            (host, http_port), _make_http_handler(self._registry)
        )
        self.http_port = self._http.server_address[1]
        self._dns_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._dns_sock.bind((host, dns_port))
        self.dns_port = self._dns_sock.getsockname()[1]
        self._threads: list[threading.Thread] = []
        self._running = False
        self._started = False

    def start(self) -> None:
        self._running = True
        self._started = True
        http_thread = threading.Thread(target=self._http.serve_forever, daemon=True)
        dns_thread = threading.Thread(target=self._dns_loop, daemon=True)
        http_thread.start()
        dns_thread.start()
        self._threads = [http_thread, dns_thread]

    def _dns_loop(self) -> None:
        self._dns_sock.settimeout(0.5)
        while self._running:
            try:
                data, addr = self._dns_sock.recvfrom(4096)
            except (TimeoutError, OSError):
                continue
            qname, question_end = _parse_qname(data)
            token = self._registry.match_token(qname)
            if token is not None:
                self._registry.record(
                    Interaction(token=token, kind="dns", source=addr[0], detail=qname)
                )
            try:
                self._dns_sock.sendto(_dns_response(data, question_end, self.advertise_host), addr)
            except OSError:
                pass

    def stop(self) -> None:
        # Each step wrapped independently, matching runtime/container.py's
        # own established per-step try/except-and-log-not-raise cleanup
        # pattern: an audit found that if any one step here raised, every
        # step after it was skipped - shutdown() failing left server_close()
        # never called (the listening socket never released) and dns_sock
        # never closed (a leaked bound UDP socket), both silently, since
        # nothing here caught or logged anything.
        self._running = False
        if self._started:
            try:
                # HTTPServer.shutdown() blocks on an internal Event that only
                # gets set from inside serve_forever()'s own loop — calling it
                # when that loop was never started (start() never called)
                # deadlocks forever instead of returning.
                self._http.shutdown()
            except Exception:  # noqa: BLE001 - cleanup must not skip the steps after it
                _log.warning("shutting down the OAST HTTP server failed", exc_info=True)
        try:
            self._http.server_close()
        except Exception:  # noqa: BLE001 - cleanup must not skip the steps after it
            _log.warning("closing the OAST HTTP server socket failed", exc_info=True)
        try:
            self._dns_sock.close()
        except Exception:  # noqa: BLE001 - last step, but stay consistent with the others
            _log.warning("closing the OAST DNS socket failed", exc_info=True)

    # --- token / callback API ---------------------------------------------
    def issue_token(self, probe_ref: str | None = None) -> str:
        return self._registry.issue(probe_ref)

    def callback_url(self, token: str) -> str:
        return f"http://{self.host}:{self.http_port}/{token}"

    def dns_name(self, token: str) -> str:
        return f"{token}.oast.local"

    def poll(self, token: str) -> list[Interaction]:
        return self._registry.poll(token)

    def all_interactions(self) -> list[Interaction]:
        return self._registry.all()

    def probe_ref(self, token: str) -> str | None:
        return self._registry.probe_ref(token)

    def __enter__(self) -> OASTServer:
        self.start()
        return self

    def __exit__(self, *_exc: object) -> None:
        self.stop()
