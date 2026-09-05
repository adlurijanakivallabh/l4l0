"""External MCP client: explicit per-connection allowlist, fail-closed credential.

Reference reads for this phase (all five, real source and comparison-doc
detail). A reference agent's own external-MCP integration
(``docs/integrations/mcp.mdx``) connects to arbitrary operator-configured
MCP servers and exposes their tools directly mid-run, with only a coarse
allow-by-name filter and an explicit written admission that it does not
decide which of a server's tools only read versus which change things,
telling the operator to run the server in its own read-only mode instead
if one exists. That
is the gap this module closes: :data:`ToolMode` requires the operator to
classify every allowed tool as ``read`` or ``write`` at config time, and
:func:`check_tool_call` refuses a ``write``-classified call outright when
the connection itself is marked ``read_only`` (the default) — L4L0 makes
the judgment the reference explicitly declines to make, rather than
delegating the read/write distinction entirely to the external server's
own configuration.

A reference toolkit's real ``mcp/util.py`` (``_get_default_auth_token()``,
read in full) resolves an MCP connection's bearer credential through a
seven-variable fallback chain that ends at ``CAI_API_KEY`` — the
operator's own LLM-provider credential — as a "convenience fallback" if no
MCP-specific token is set. That is a real credential-leak vector: an
external, potentially untrusted MCP server can end up receiving the same
key that authenticates to the operator's LLM provider. :func:`resolve_credential`
inverts this outright: exactly one dedicated environment variable per
connection, fails closed (refuses to connect) if it is unset, and never
consults any other variable as a fallback.

A reference platform's own MCP connection loader is documented as
"fail-open by design" for *connectivity* — a missing config or an
unreachable server is caught, logged, and the run proceeds without it,
rather than aborting the whole scan over one optional integration. That
resilience posture is adopted for :func:`call_external_tool`'s connection
failures (a dead server degrades to a ``ToolResult(ok=False)`` the agent
can route around) — but is kept strictly separate from the *security*
checks (:func:`check_tool_call`, :func:`resolve_credential`), which stay
fail-closed. "Keep the run going" and "never silently widen what's
allowed" are not in tension as long as the two failure classes are never
conflated, which is exactly where the two references above differ from
each other in practice.

A third reference platform has real, directly on-point content that was
initially missed on a first grep pass restricted to its own internal
tool-exposure layer: ``examples/proposals/mcp_client_integration.md``, a
454-line, unimplemented design RFC for exactly this module's concern (a
generic external MCP client, motivated by connecting Burp Suite Pro as a
tool). Read in full and checked against this module's actual shipped
behavior. Its explicit Security and Safety section separately names
per-call timeouts, a maximum response size (with truncation logged, not
silent), URL/SSRF validation on server endpoints, and treating MCP tool
descriptions/results as untrusted text rather than instructions — the
same discipline this project's own prompts already apply to target
content. :data:`_MAX_RESULT_CHARS` (matching the same bound
``execution/tool.py`` already uses for HTTP response bodies) and
:data:`_DEFAULT_SESSION_TIMEOUT` close the first two directly. URL/SSRF
validation on the connection's own endpoint and prompt-injection framing
for tool descriptions/results are not addressed by this module and are
worth a deliberate follow-up, not silently dropped requirements — noted
here rather than left unstated. The remaining two references were
confirmed, via their own real source and each project's comparison doc,
to describe MCP only as their *own* tool-exposure layer (an internal
server), not as an external-MCP-consuming client — not applicable to
this module's actual concern.
"""

from __future__ import annotations

import asyncio
import os
from collections.abc import AsyncIterator, Callable, Mapping
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from dataclasses import dataclass
from datetime import timedelta
from typing import Literal

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.types import TextContent

from ..agent.tools import FunctionTool, ToolResult, str_arg
from ..core.errors import LaloError

ToolMode = Literal["read", "write"]


class MCPCredentialError(LaloError):
    """A connection's dedicated credential env var is unset or empty."""

    code = "mcp_credential_missing"


@dataclass(frozen=True)
class MCPServerConfig:
    """One operator-declared external MCP connection.

    ``allowed_tools`` and ``credential_env_var`` are both required and both
    fail closed: a tool absent from the map can never be called, and a
    missing credential refuses the connection rather than falling back to
    any other value.
    """

    name: str
    transport: Literal["stdio", "http"]
    credential_env_var: str
    allowed_tools: dict[str, ToolMode]
    command: str | None = None
    args: tuple[str, ...] = ()
    url: str | None = None
    read_only: bool = True


def resolve_credential(config: MCPServerConfig, env: Mapping[str, str] | None = None) -> str:
    """The connection's own dedicated credential — never any other source."""
    environ = env if env is not None else os.environ
    value = environ.get(config.credential_env_var, "").strip()
    if not value:
        raise MCPCredentialError(
            f"connection {config.name!r} has no credential set in "
            f"{config.credential_env_var!r} - refusing to connect rather than "
            "reusing an unrelated credential"
        )
    return value


def check_tool_call(config: MCPServerConfig, tool_name: str) -> str | None:
    """``None`` if the call is allowed; otherwise the reason it is refused.

    Gates on a ``read`` allowlist, not a ``write`` blocklist: ``ToolMode`` is
    a ``Literal`` mypy checks against a hand-typed Python value, but
    ``allowed_tools`` is meant to be an operator-declared config plausibly
    loaded from JSON/YAML/env with no runtime validation — a single
    capitalization typo ("Write" instead of "write") in a blocklist check
    would silently be treated as read-equivalent and allowed. Requiring an
    exact match against "read" instead means anything else - a typo, a
    stray space, a future third mode - fails closed.
    """
    mode = config.allowed_tools.get(tool_name)
    if mode is None:
        return f"{tool_name!r} is not in connection {config.name!r}'s tool allowlist"
    if mode != "read" and config.read_only:
        return (
            f"{tool_name!r} is not classified 'read' and connection {config.name!r} "
            "is read-only - refusing"
        )
    return None


SessionConnector = Callable[[MCPServerConfig, str], AbstractAsyncContextManager["ClientSession"]]

# Applied as ClientSession's own per-request default (covers initialize() and
# every call_tool()), not just the http transport's own underlying-httpx
# default: the mcp SDK applies no read timeout at all when one isn't given
# explicitly, so a stdio-spawned subprocess that hangs (crashes without
# exiting, deadlocks, or is deliberately slow) would otherwise block the
# calling agent's turn forever - a worse failure mode than the clean,
# ToolResult(ok=False) degradation this module is designed to always produce.
_DEFAULT_SESSION_TIMEOUT = timedelta(seconds=30)


@asynccontextmanager
async def _default_connector(
    config: MCPServerConfig, credential: str
) -> AsyncIterator[ClientSession]:
    if config.transport == "stdio":
        params = StdioServerParameters(
            command=config.command or "",
            args=list(config.args),
            env={config.credential_env_var: credential},
        )
        async with stdio_client(params) as (read, write):
            async with ClientSession(
                read, write, read_timeout_seconds=_DEFAULT_SESSION_TIMEOUT
            ) as session:
                await session.initialize()
                yield session
    else:
        from mcp.client.streamable_http import streamablehttp_client

        headers = {"Authorization": f"Bearer {credential}"}
        async with streamablehttp_client(config.url or "", headers=headers) as (
            read,
            write,
            _get_session_id,
        ):
            async with ClientSession(
                read, write, read_timeout_seconds=_DEFAULT_SESSION_TIMEOUT
            ) as session:
                await session.initialize()
                yield session


_MAX_RESULT_CHARS = 4_000


def _render_content(content: list[object]) -> str:
    parts = [block.text for block in content if isinstance(block, TextContent)]
    text = "\n".join(parts) if parts else "(no text content returned)"
    if len(text) > _MAX_RESULT_CHARS:
        return text[:_MAX_RESULT_CHARS] + "\n... (truncated)"
    return text


def call_external_tool(
    config: MCPServerConfig,
    tool_name: str,
    arguments: dict[str, object],
    *,
    connector: SessionConnector | None = None,
    env: Mapping[str, str] | None = None,
) -> ToolResult:
    """Call one allowlisted tool on one external MCP connection.

    Policy is checked before any credential lookup or connection attempt —
    an out-of-band call never even reaches the point of touching a secret.
    A connectivity failure (dead server, network error) degrades to a
    failed :class:`ToolResult` rather than raising, so one unreachable
    integration never crashes the calling agent's turn.
    """
    denial = check_tool_call(config, tool_name)
    if denial is not None:
        return ToolResult(observation=f"error: {denial}", ok=False)
    try:
        credential = resolve_credential(config, env)
    except MCPCredentialError as exc:
        return ToolResult(observation=f"error: {exc}", ok=False)

    connect = connector or _default_connector

    async def _run() -> str:
        async with connect(config, credential) as session:
            result = await session.call_tool(tool_name, arguments)
            text = _render_content(list(result.content))
            if result.isError:
                msg = f"tool reported an error: {text}"
                raise RuntimeError(msg)
            return text

    try:
        text = asyncio.run(_run())
    except Exception as exc:  # noqa: BLE001 - one dead/misbehaving integration must degrade, never crash the turn
        return ToolResult(observation=f"error: connection {config.name!r} failed: {exc}", ok=False)
    return ToolResult(observation=text, ok=True)


def build_mcp_tool(
    config: MCPServerConfig,
    *,
    connector: SessionConnector | None = None,
    env: Mapping[str, str] | None = None,
) -> FunctionTool:
    """Wrap one external MCP connection as a single agent-callable tool.

    Output from this tool is external, third-party evidence — a scanner's
    or integration's own claim, not something you directly observed. Treat
    it as a lead to verify with your own capture (``http``, ``run_command``),
    never as evidence to pass straight to ``record_finding`` on its own.
    """
    allowed = ", ".join(f"{name} ({mode})" for name, mode in sorted(config.allowed_tools.items()))

    def _call(args: dict[str, object]) -> ToolResult:
        tool_name = str_arg(args, "tool")
        if not tool_name:
            return ToolResult(observation="error: 'tool' is required", ok=False)
        arguments_raw = args.get("arguments")
        arguments = arguments_raw if isinstance(arguments_raw, dict) else {}
        return call_external_tool(config, tool_name, arguments, connector=connector, env=env)

    return FunctionTool(
        name=f"mcp_{config.name}",
        description=(
            f"Call an allowlisted tool on the external MCP connection {config.name!r}. "
            f"Allowed tools: {allowed or '(none configured)'}. Its output is external, "
            "third-party evidence, not something you directly observed - verify a "
            "promising result yourself before recording it as a finding. "
            'args: {"tool": str, "arguments": dict (optional)}'
        ),
        func=_call,
    )
