"""Shared MCP session helpers — single source for harness + juice + bola (Phase 1 dedup).

All three eval/bola detectors previously duplicated _SharedState / _session_as /
_mcp_for / _call / _read_only_fire. This module is the one helper verified at
three call sites. It adds no detection logic; it only binds a RequestFirer +
ScopeGuard + ExplorerContext + server._Session plus the McpCaller handle
indirection fire_ref/verdict_ref that payload_chain.call_tool_sync wraps.

No per-target payload/endpoint literals live here — only transport + graph
binding. Target config (base_url, host, surface) stays in the caller.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from itertools import count
from typing import TYPE_CHECKING

import httpx

from reachagent.execution.audit import AuditLog
from reachagent.execution.firer import RequestFirer
from reachagent.execution.scope import ScopeGuard
from reachagent.graph.nodes import Endpoint, Parameter
from reachagent.graph.store import ReachabilityGraph
from reachagent.mcp import server
from reachagent.payloads import PayloadLibrary
from reachagent.tools.explorer_context import ExplorerContext

if TYPE_CHECKING:
    from reachagent.execution.firer import FireResult
    from reachagent.oracles.base import OracleVerdict

_HTTP_TIMEOUT = 10.0


@dataclass
class SharedState:
    """One graph + handle registries shared across per-identity sessions.

    Each identity fires through its own token-authenticated firer (isolated
    sessions per §10), but all fires/verdicts land in one registry/graph so
    run_oracle can diff responses obtained under different identities.
    """

    graph: ReachabilityGraph = field(default_factory=ReachabilityGraph)
    fires: dict[str, FireResult] = field(default_factory=dict)
    verdicts: dict[str, OracleVerdict] = field(default_factory=dict)
    fire_seq: count[int] = field(default_factory=count)
    verdict_seq: count[int] = field(default_factory=count)


def session_as(
    base_url_or_target: str | object,
    host_or_token: str | None = None,
    token_or_shared: str | None | SharedState = None,
    shared_or_transport: SharedState | httpx.BaseTransport | None = None,
    transport: httpx.BaseTransport | None = None,
) -> server._Session:
    """Bound MCP session whose firer authenticates as one identity (§10, §13).

    Two call shapes (drop-in compat):

    * New: ``session_as(base_url: str, host: str, token: str|None, shared, transport?)``
    * Legacy: ``session_as(VampiTarget, token: str|None, shared)`` — where
      VampiTarget carries ``.api`` / ``.host`` (harness.py, juiceshop_live.py,
      bola/detector.py legacy call sites).
    """
    # Legacy detection: first arg is a target object with .api / .host, second is
    # token, third is shared. New shape has plain strings in first two positions.
    if hasattr(base_url_or_target, "api") and hasattr(base_url_or_target, "host"):
        target = base_url_or_target
        base_url: str = target.api
        host: str = target.host or ""
        token: str | None = host_or_token
        shared: SharedState = token_or_shared  # type: ignore[assignment]
        transport = shared_or_transport  # type: ignore[assignment]
    else:
        base_url = base_url_or_target  # type: ignore[assignment]
        host = host_or_token or ""
        token = token_or_shared  # type: ignore[assignment]
        shared = shared_or_transport  # type: ignore[assignment]
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    client = httpx.Client(headers=headers, timeout=_HTTP_TIMEOUT, transport=transport)
    firer = RequestFirer(client, ScopeGuard.from_hosts([host]), AuditLog())
    ctx = ExplorerContext(
        graph=shared.graph,
        firer=firer,
        library=PayloadLibrary.from_file(),
        base_url=base_url.rstrip("/"),
    )
    return server._Session(
        ctx=ctx,
        _fires=shared.fires,
        _verdicts=shared.verdicts,
        _fire_seq=shared.fire_seq,
        _verdict_seq=shared.verdict_seq,
    )


def mcp_for(sess: server._Session) -> object:
    """Register role-bounded tools on a fresh FastMCP bound to sess."""
    from mcp.server.fastmcp import FastMCP

    mcp = FastMCP("reachagent-eval")
    server.register_tools(mcp, sess)
    return mcp


def mcp_call(mcp: object, name: str, **arguments: object) -> dict[str, object]:
    """Invoke tool through real mcp.call_tool boundary; return structured dict."""
    _content, structured = asyncio.run(mcp.call_tool(name, arguments))  # type: ignore[attr-defined]
    return dict(structured)


def read_only_fire(
    mcp: object,
    sess: server._Session,
    identity: str,
    path: str,
) -> str:
    """Seed endpoint/param, fingerprint, fire GET via MCP; return fire_ref."""
    ep = sess.graph.add_endpoint(Endpoint(method="GET", path=path))
    param = sess.graph.add_parameter(ep, Parameter(name="probe", location="query"))
    mcp_call(mcp, "fingerprint_parameter", identity=identity, endpoint_node=ep, param_node=param)
    fired = mcp_call(
        mcp,
        "fire_request",
        identity=identity,
        endpoint_node=ep,
        param_node=param,
        payload="",
        method="GET",
    )
    return str(fired["fire_ref"])
