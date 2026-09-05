"""Disposable per-scan runtime container.

This is the host-isolation boundary: the agent runs/installs anything it wants
*inside* a throwaway container, but that container has no host bind-mounts, no
Docker socket, dropped Linux capabilities (with hard-forbidden ones rejected at
the API level, not just documented), and no-new-privileges — so nothing it does
reaches the operator's machine. In-container root is fine (the agent needs to
install tools); the isolation that matters is the absence of a mount/socket and
the dropped caps.
"""

from .container import (
    ExecResult,
    ForbiddenCapabilityError,
    RuntimeConfig,
    RuntimeContainer,
    docker_available,
)
from .tool import CommandExecutor, build_run_command_tool

__all__ = [
    "CommandExecutor",
    "ExecResult",
    "ForbiddenCapabilityError",
    "RuntimeConfig",
    "RuntimeContainer",
    "build_run_command_tool",
    "docker_available",
]
