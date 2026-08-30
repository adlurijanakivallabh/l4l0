"""Allowlisted firing transports and their shared execution guard.

Transport selection is deliberately boring: it chooses where evidence is
collected, not how evidence is interpreted.  HTTP and proxy requests are sent
through :class:`RequestFirer`; browser callers use ``prepare_browser`` and
``record_browser`` around their Playwright operation.  No class in this module
imports an oracle or creates a finding.
"""

from __future__ import annotations

import threading
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Literal

from reachagent.execution.firer import FireResult, RequestFirer

TransportKind = Literal["http", "browser", "proxy"]
TRANSPORTS: tuple[TransportKind, ...] = ("http", "browser", "proxy")


class TransportCancelledError(RuntimeError):
    """Raised before/after a transport operation when cancellation was requested."""


@dataclass(frozen=True)
class ToolAnnotation:
    """Safety metadata exposed to MCP clients for one operation."""

    read_only: bool
    idempotent: bool
    destructive: bool


TOOL_ANNOTATIONS: Mapping[str, ToolAnnotation] = {
    "fingerprint_parameter": ToolAnnotation(True, True, False),
    "get_payloads": ToolAnnotation(True, True, False),
    # These tools can carry a mutating method; annotate conservatively even
    # though the execution layer still requires read-only clearance first.
    "fire_request": ToolAnnotation(False, False, True),
    "fire_browser": ToolAnnotation(True, True, False),
    "fire_browser_form": ToolAnnotation(False, False, True),
    "fire_proxy_request": ToolAnnotation(False, False, True),
    "classify_response": ToolAnnotation(True, True, False),
    "run_oracle": ToolAnnotation(True, True, False),
    "write_finding": ToolAnnotation(False, True, True),
    "mark_inconclusive": ToolAnnotation(False, True, True),
}


@dataclass(frozen=True)
class ProgressEvent:
    """A bounded progress projection safe for GUI/MCP consumers."""

    operation_id: str
    stage: str
    completed: int
    total: int
    transport: TransportKind
    status: str = "running"


ProgressCallback = Callable[[ProgressEvent], None]


@dataclass
class TransportControl:
    """Cancellation and progress seam shared by browser/proxy operations."""

    operation_id: str = "transport"
    cancel_event: threading.Event = field(default_factory=threading.Event)
    progress: ProgressCallback | None = None

    def check(self) -> None:
        if self.cancel_event.is_set():
            raise TransportCancelledError(f"operation {self.operation_id!r} cancelled")

    def emit(
        self,
        stage: str,
        *,
        completed: int,
        total: int,
        transport: TransportKind,
        status: str = "running",
    ) -> None:
        if self.progress is None:
            return
        self.progress(
            ProgressEvent(
                operation_id=self.operation_id,
                stage=stage[:80],
                completed=max(0, completed),
                total=max(1, total),
                transport=transport,
                status=status,
            )
        )


@dataclass(frozen=True)
class TransportRequest:
    """One request independent of its selected evidence transport."""

    identity: str
    url: str
    method: str = "GET"
    state_changing: bool = False
    kwargs: Mapping[str, object] = field(default_factory=dict)


class TransportDispatcher:
    """Route HTTP/proxy fires through one :class:`RequestFirer` gate."""

    def __init__(self, firer: RequestFirer) -> None:
        self.firer = firer

    def fire(
        self,
        request: TransportRequest,
        transport: TransportKind = "http",
        *,
        proxy_url: str | None = None,
        control: TransportControl | None = None,
    ) -> FireResult:
        """Send an HTTP or proxy request; unknown transports fail closed."""
        if transport not in TRANSPORTS or transport == "browser":
            raise ValueError("TransportDispatcher.fire accepts only http or proxy")
        if transport == "proxy" and not proxy_url:
            raise ValueError("proxy transport requires REACHAGENT_PROXY_URL or proxy_url")
        ctl = control or TransportControl()
        ctl.check()
        ctl.emit("dispatch", completed=0, total=1, transport=transport)
        result = self.firer.fire(
            request.identity,
            request.method,
            request.url,
            state_changing=request.state_changing,
            proxy_url=proxy_url if transport == "proxy" else None,
            transport=transport,
            **dict(request.kwargs),
        )
        ctl.check()
        ctl.emit("response", completed=1, total=1, transport=transport, status="complete")
        return result

    def prepare_browser(
        self,
        identity: str,
        url: str,
        *,
        method: str = "GET",
        state_changing: bool = False,
        control: TransportControl | None = None,
    ) -> None:
        """Run scope/read-only-first preflight before Playwright sends traffic."""
        ctl = control or TransportControl()
        ctl.check()
        self.firer.scope.enforce(url)
        # A browser navigation is an external transport, so establish the same
        # read-only clearance that an HTTP fire would establish.  This is a real
        # GET and therefore is audited by RequestFirer before the page opens.
        self.firer.fire(identity, "GET", url, state_changing=False)
        self.firer.authorize_external(
            identity,
            method,
            url,
            state_changing=state_changing,
        )
        ctl.emit("preflight", completed=1, total=2, transport="browser")

    def record_browser(
        self,
        identity: str,
        url: str,
        *,
        method: str,
        status_code: int | None,
        control: TransportControl | None = None,
        error: str | None = None,
    ) -> None:
        """Record browser evidence after Playwright completes; never judge it."""
        ctl = control or TransportControl()
        ctl.check()
        self.firer.scope.enforce(url)
        self.firer.record_transport_result(
            identity,
            method,
            url,
            status_code,
            transport="browser",
            error=error,
        )
        ctl.emit(
            "response" if error is None else "error",
            completed=2,
            total=2,
            transport="browser",
            status="complete" if error is None else "error",
        )


__all__ = [
    "TRANSPORTS",
    "TOOL_ANNOTATIONS",
    "ProgressEvent",
    "ToolAnnotation",
    "TransportCancelledError",
    "TransportControl",
    "TransportDispatcher",
    "TransportKind",
    "TransportRequest",
]
