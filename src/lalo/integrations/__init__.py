"""External integrations: MCP client (fail-closed credential, explicit allowlist)."""

from .mcp_client import (
    MCPCredentialError,
    MCPServerConfig,
    build_mcp_tool,
    call_external_tool,
    check_tool_call,
    resolve_credential,
)

__all__ = [
    "MCPCredentialError",
    "MCPServerConfig",
    "build_mcp_tool",
    "call_external_tool",
    "check_tool_call",
    "resolve_credential",
]
