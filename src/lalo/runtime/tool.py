"""``run_command``: the agent-callable free shell over the disposable runtime container.

This is the actual point of contact between the agent's own tool-calling loop
(Phase 5) and the host-isolated container (Phase 1): everything the container
enforces — no host mounts, no Docker socket, dropped capabilities — is the
safety floor. Inside that container the agent has full command freedom, per
the project's own operating principle: freedom is inside the container,
isolation is that nothing escapes it. Recon (Phase 9) is the first real
consumer, since external tool wrapping is exactly what needs a free shell
rather than a bespoke per-tool client.
"""

from __future__ import annotations

from typing import Protocol

from ..agent.tools import FunctionTool, ToolResult


class CommandExecutor(Protocol):
    """The subset of :class:`~lalo.runtime.container.RuntimeContainer` this tool needs."""

    def exec(self, command: str | list[str], *, timeout: float = 120.0) -> object: ...


_MAX_OBSERVATION_CHARS = 8000
_DEFAULT_MAX_TIMEOUT_S = 600.0


def _parse_timeout(raw: object, *, default: float, max_timeout: float) -> float | str:
    """The effective timeout in seconds (capped at ``max_timeout``), or an error string."""
    if raw is None:
        return default
    # bool is a subclass of int in Python -- an agent-supplied {"timeout": true}
    # must not silently become a real 1.0s timeout.
    if isinstance(raw, bool) or not isinstance(raw, int | float):
        return "'timeout' must be a number of seconds"
    if raw <= 0:
        return "'timeout' must be positive"
    return min(float(raw), max_timeout)


def build_run_command_tool(
    container: CommandExecutor,
    *,
    timeout: float = 120.0,
    max_timeout: float = _DEFAULT_MAX_TIMEOUT_S,
) -> FunctionTool:
    def _run(args: dict[str, object]) -> ToolResult:
        command = args.get("command")
        if not isinstance(command, str) or not command.strip():
            return ToolResult(
                observation="error: 'command' (a non-empty string) is required", ok=False
            )
        effective_timeout = _parse_timeout(
            args.get("timeout"), default=timeout, max_timeout=max_timeout
        )
        if isinstance(effective_timeout, str):
            return ToolResult(observation=f"error: {effective_timeout}", ok=False)
        result = container.exec(command, timeout=effective_timeout)
        exit_code = getattr(result, "exit_code", None)
        stdout = getattr(result, "stdout", "")
        stderr = getattr(result, "stderr", "")
        ok = bool(getattr(result, "ok", exit_code == 0))
        prefix = (
            f"error: command timed out after {effective_timeout}s\n"
            if getattr(result, "timed_out", False)
            else ""
        )
        observation = f"{prefix}exit_code={exit_code}\nstdout:\n{stdout}\nstderr:\n{stderr}"
        return ToolResult(observation=observation[:_MAX_OBSERVATION_CHARS], ok=ok)

    return FunctionTool(
        name="run_command",
        description=(
            "Run a shell command inside your disposable sandbox container. Full freedom "
            "inside the container -- install anything, run anything -- but nothing here "
            'reaches the host. args: {"command": str, "timeout": number (optional, seconds, '
            f"default {timeout:g}, capped at {max_timeout:g} - raise it for a genuinely "
            "long-running command like a broad scan or a slow install)}"
        ),
        func=_run,
    )
