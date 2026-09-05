"""Tests for the external MCP client: fail-closed credential, explicit allowlist.

Uses a real in-process MCP server (``FastMCP`` + the SDK's own
``create_connected_server_and_client_session`` in-memory transport) rather
than mocking the protocol — a genuine round trip through real
``list_tools``/``call_tool`` JSON-RPC handling, injected as this module's
own ``connector`` seam instead of spawning a subprocess or hitting a URL.
"""

from __future__ import annotations

import asyncio
from contextlib import AbstractAsyncContextManager
from datetime import timedelta

import pytest
from mcp import ClientSession
from mcp.server.fastmcp import FastMCP
from mcp.shared.memory import create_connected_server_and_client_session

from lalo.agent.tools import ToolRegistry
from lalo.integrations.mcp_client import (
    MCPCredentialError,
    MCPServerConfig,
    build_mcp_tool,
    call_external_tool,
    check_tool_call,
    resolve_credential,
)


def _test_server() -> FastMCP:
    server = FastMCP("test-server")

    @server.tool()
    def echo(text: str) -> str:
        return f"echo: {text}"

    @server.tool()
    def delete_everything() -> str:
        return "deleted"

    @server.tool()
    def always_fails() -> str:
        msg = "boom"
        raise RuntimeError(msg)

    @server.tool()
    def big_output() -> str:
        return "x" * 10_000

    @server.tool()
    async def hangs_forever() -> str:
        await asyncio.sleep(60)
        return "should never get here"

    return server


def _memory_connector(
    _config: MCPServerConfig, _credential: str
) -> AbstractAsyncContextManager[ClientSession]:
    return create_connected_server_and_client_session(_test_server())


def _config(**overrides: object) -> MCPServerConfig:
    base: dict[str, object] = {
        "name": "test",
        "transport": "stdio",
        "credential_env_var": "TEST_MCP_TOKEN",
        "allowed_tools": {"echo": "read", "delete_everything": "write"},
    }
    base.update(overrides)
    return MCPServerConfig(**base)  # type: ignore[arg-type]


# --- resolve_credential: fail-closed, no fallback chain ----------------------


def test_resolve_credential_reads_the_dedicated_env_var() -> None:
    config = _config()
    assert resolve_credential(config, env={"TEST_MCP_TOKEN": "secret"}) == "secret"


def test_resolve_credential_fails_closed_when_unset() -> None:
    config = _config()
    with pytest.raises(MCPCredentialError):
        resolve_credential(config, env={})


def test_resolve_credential_never_falls_back_to_an_unrelated_credential() -> None:
    """Inverts a real reference bug: falling back to the operator's own LLM
    provider key when no MCP-specific token is set. An unrelated credential
    being present must never satisfy this connection's requirement."""
    config = _config()
    env = {
        "ANTHROPIC_API_KEY": "sk-real-provider-key",
        "OPENAI_API_KEY": "sk-another-real-key",
    }
    with pytest.raises(MCPCredentialError):
        resolve_credential(config, env=env)


def test_resolve_credential_rejects_a_blank_value() -> None:
    config = _config()
    with pytest.raises(MCPCredentialError):
        resolve_credential(config, env={"TEST_MCP_TOKEN": "   "})


# --- check_tool_call: explicit allowlist + read/write ------------------------


def test_check_tool_call_allows_a_listed_read_tool() -> None:
    assert check_tool_call(_config(), "echo") is None


def test_check_tool_call_denies_an_unlisted_tool() -> None:
    reason = check_tool_call(_config(), "not_in_the_allowlist")
    assert reason is not None
    assert "not in connection" in reason


def test_check_tool_call_denies_a_write_tool_on_a_read_only_connection() -> None:
    reason = check_tool_call(_config(read_only=True), "delete_everything")
    assert reason is not None
    assert "read-only" in reason


def test_check_tool_call_fails_closed_on_a_malformed_mode_value() -> None:
    """allowed_tools is operator-declared config with no runtime validation of
    ToolMode - a typo'd/mistyped mode value must still be denied on a
    read-only connection, not silently treated as read-equivalent."""
    config = _config(allowed_tools={"delete_everything": "Write"}, read_only=True)  # type: ignore[arg-type]
    reason = check_tool_call(config, "delete_everything")
    assert reason is not None
    assert "read-only" in reason


def test_check_tool_call_allows_a_write_tool_when_read_only_is_disabled() -> None:
    assert check_tool_call(_config(read_only=False), "delete_everything") is None


# --- call_external_tool: policy checked before any credential/connection ----


def test_call_external_tool_denies_before_touching_the_credential() -> None:
    """An unrelated credential being present is irrelevant if the tool isn't
    even allowlisted - the allowlist check must run first, unconditionally."""
    result = call_external_tool(
        _config(),
        "not_in_the_allowlist",
        {},
        connector=_memory_connector,
        env={"TEST_MCP_TOKEN": "secret"},
    )
    assert result.ok is False
    assert "not in connection" in result.observation


def test_call_external_tool_denies_write_without_ever_connecting() -> None:
    result = call_external_tool(
        _config(read_only=True),
        "delete_everything",
        {},
        connector=_memory_connector,
        env={"TEST_MCP_TOKEN": "secret"},
    )
    assert result.ok is False
    assert "read-only" in result.observation


def test_call_external_tool_fails_closed_with_no_credential_configured() -> None:
    result = call_external_tool(
        _config(), "echo", {"text": "hi"}, connector=_memory_connector, env={}
    )
    assert result.ok is False
    assert "no credential set" in result.observation


def test_call_external_tool_real_round_trip_through_a_live_session() -> None:
    result = call_external_tool(
        _config(),
        "echo",
        {"text": "hello"},
        connector=_memory_connector,
        env={"TEST_MCP_TOKEN": "secret"},
    )
    assert result.ok is True
    assert result.observation == "echo: hello"


def test_call_external_tool_truncates_an_oversized_response() -> None:
    """A hostile or just chatty MCP server's response must not flow through
    unbounded into the calling agent's context - matching the same cap
    execution/tool.py already applies to HTTP response bodies."""
    config = _config(allowed_tools={"big_output": "read"})
    result = call_external_tool(
        config, "big_output", {}, connector=_memory_connector, env={"TEST_MCP_TOKEN": "secret"}
    )
    assert result.ok is True
    assert len(result.observation) < 10_000
    assert result.observation.endswith("(truncated)")


def test_call_external_tool_a_server_side_error_degrades_gracefully() -> None:
    config = _config(allowed_tools={"always_fails": "read"})
    result = call_external_tool(
        config, "always_fails", {}, connector=_memory_connector, env={"TEST_MCP_TOKEN": "secret"}
    )
    assert result.ok is False
    assert "failed" in result.observation


def test_call_external_tool_an_unreachable_connector_never_crashes() -> None:
    def _broken_connector(
        _cfg: MCPServerConfig, _credential: str
    ) -> AbstractAsyncContextManager[ClientSession]:
        raise ConnectionError("dead server")

    result = call_external_tool(
        _config(), "echo", {}, connector=_broken_connector, env={"TEST_MCP_TOKEN": "secret"}
    )
    assert result.ok is False
    assert "failed" in result.observation


def test_call_external_tool_a_hung_server_times_out_instead_of_hanging_forever() -> None:
    """A stdio-spawned server that never responds (crashed without exiting,
    deadlocked, or deliberately slow) must degrade to a failed ToolResult
    within a bounded time, never block the calling turn indefinitely."""

    def _short_timeout_connector(
        _cfg: MCPServerConfig, _credential: str
    ) -> AbstractAsyncContextManager[ClientSession]:
        return create_connected_server_and_client_session(
            _test_server(), read_timeout_seconds=timedelta(seconds=0.5)
        )

    config = _config(allowed_tools={"hangs_forever": "read"})
    result = call_external_tool(
        config,
        "hangs_forever",
        {},
        connector=_short_timeout_connector,
        env={"TEST_MCP_TOKEN": "secret"},
    )
    assert result.ok is False
    assert "failed" in result.observation


# --- build_mcp_tool: the agent-facing wiring --------------------------------


def test_build_mcp_tool_dispatches_through_the_registry() -> None:
    tool = build_mcp_tool(_config(), connector=_memory_connector, env={"TEST_MCP_TOKEN": "secret"})
    registry = ToolRegistry([tool])
    result = registry.dispatch("mcp_test", {"tool": "echo", "arguments": {"text": "hi"}})
    assert result.ok is True
    assert result.observation == "echo: hi"


def test_build_mcp_tool_requires_a_tool_name() -> None:
    tool = build_mcp_tool(_config(), connector=_memory_connector, env={"TEST_MCP_TOKEN": "secret"})
    result = tool.run({})
    assert result.ok is False
    assert "'tool' is required" in result.observation


def test_build_mcp_tool_requires_a_tool_name_even_as_explicit_json_null() -> None:
    tool = build_mcp_tool(_config(), connector=_memory_connector, env={"TEST_MCP_TOKEN": "secret"})
    result = tool.run({"tool": None})
    assert result.ok is False
    assert "'tool' is required" in result.observation


def test_build_mcp_tool_description_names_the_allowlist_and_evidence_discipline() -> None:
    tool = build_mcp_tool(_config())
    assert "echo (read)" in tool.description
    assert "delete_everything (write)" in tool.description
    assert "not something you directly observed" in tool.description
