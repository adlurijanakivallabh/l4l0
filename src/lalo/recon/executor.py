"""Command executors for recon tools — run on the host or inside the container.

Decouples recon runners from *where* a tool runs. A missing binary makes a runner
a no-op (its signal is disabled), never a crash.
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from ..runtime.container import RuntimeContainer


@dataclass
class ExecOutput:
    exit_code: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.exit_code == 0


@runtime_checkable
class Executor(Protocol):
    def has_binary(self, name: str) -> bool: ...

    def run(self, argv: list[str], *, timeout: float = 120.0) -> ExecOutput: ...


class HostExecutor:
    """Runs recon tools on the host (used when there is no runtime container)."""

    def has_binary(self, name: str) -> bool:
        return shutil.which(name) is not None

    def run(self, argv: list[str], *, timeout: float = 120.0) -> ExecOutput:
        try:
            result = subprocess.run(  # noqa: S603 - authorized recon tooling, fixed argv
                argv, capture_output=True, text=True, timeout=timeout
            )
        except subprocess.TimeoutExpired:
            return ExecOutput(124, "", "timeout")
        except (OSError, subprocess.SubprocessError) as exc:
            return ExecOutput(1, "", str(exc))
        return ExecOutput(result.returncode, result.stdout, result.stderr)


class ContainerExecutor:
    """Runs recon tools inside the disposable runtime container."""

    def __init__(self, container: RuntimeContainer) -> None:
        self._container = container

    def has_binary(self, name: str) -> bool:
        return self._container.exec(["sh", "-c", f"command -v {name}"]).ok

    def run(self, argv: list[str], *, timeout: float = 120.0) -> ExecOutput:
        result = self._container.exec(argv, timeout=timeout)
        return ExecOutput(result.exit_code, result.stdout, result.stderr)
