"""External integrations: MCP client (fail-closed credential, explicit allowlist)
and CVE/EPSS enrichment (a prioritization fact only)."""

from .epss import EPSSResult, build_epss_tool, fetch_epss_score
from .mcp_client import (
    MCPCredentialError,
    MCPServerConfig,
    build_mcp_tool,
    call_external_tool,
    check_tool_call,
    resolve_credential,
    validate_server_url,
)

__all__ = [
    "EPSSResult",
    "MCPCredentialError",
    "MCPServerConfig",
    "build_epss_tool",
    "build_mcp_tool",
    "call_external_tool",
    "check_tool_call",
    "fetch_epss_score",
    "resolve_credential",
    "validate_server_url",
]
