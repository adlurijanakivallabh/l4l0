"""External MCP client config — fail-closed credential + per-connection allowlist.

Two hardening rules (inverting real disclosed weaknesses in reference clients):
- **fail closed on credentials**: a configured server with no dedicated credential
  is an error, never a silent fallback to an unrelated key.
- **explicit tool allowlist**: a server exposes only the tools named at config
  time, never its full surface by default.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field

from ..core.errors import ConfigError


@dataclass(frozen=True)
class ExternalMCPConfig:
    name: str
    url: str
    credential: str | None = None
    allowed_tools: frozenset[str] = field(default_factory=frozenset)

    def validate(self) -> None:
        if not self.credential:
            raise ConfigError(
                f"external MCP server {self.name!r} has no dedicated credential",
                code="config_error",
            )
        if not self.allowed_tools:
            raise ConfigError(
                f"external MCP server {self.name!r} must declare an explicit tool allowlist",
                code="config_error",
            )

    def is_tool_allowed(self, tool: str) -> bool:
        return tool in self.allowed_tools


class ExternalMCPClient:
    def __init__(self, config: ExternalMCPConfig) -> None:
        config.validate()  # fail closed at construction
        self.config = config

    def filter_tools(self, server_tools: Sequence[str]) -> list[str]:
        """Return only the server's tools that are on the explicit allowlist."""
        return [t for t in server_tools if self.config.is_tool_allowed(t)]
