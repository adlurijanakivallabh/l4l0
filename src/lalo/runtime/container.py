"""Per-scan disposable runtime container, managed via the ``docker`` CLI.

Host isolation is enforced by the run flags, not by trusting the workload:
``--cap-drop ALL`` (+ only explicitly requested caps), ``no-new-privileges``,
**no bind-mounts**, **no docker socket**, a pids/memory limit, and removal on
exit. The container is where the agent's free shell runs.
"""

from __future__ import annotations

import shutil
import subprocess
import uuid
from dataclasses import dataclass

from ..core.errors import ContainerError
from ..core.logging import get_logger

_log = get_logger("lalo.runtime")

# Keepalive that exists on both alpine (busybox) and debian-family bases.
_KEEPALIVE = ("tail", "-f", "/dev/null")


def _docker_bin() -> str:
    path = shutil.which("docker")
    if path is None:
        raise ContainerError("docker executable not found on PATH")
    return path


def docker_available() -> bool:
    """True if a working docker daemon is reachable (used to gate live tests)."""
    if shutil.which("docker") is None:
        return False
    try:
        result = subprocess.run(  # noqa: S603 - fixed argv, resolved binary
            [_docker_bin(), "info"], capture_output=True, timeout=10
        )
    except (subprocess.SubprocessError, OSError):
        return False
    return result.returncode == 0


@dataclass
class ExecResult:
    exit_code: int
    stdout: str
    stderr: str
    timed_out: bool = False

    @property
    def ok(self) -> bool:
        return self.exit_code == 0 and not self.timed_out


@dataclass
class RuntimeConfig:
    """How to launch the disposable container.

    ``user=None`` keeps the image's default user (root for the arsenal image —
    fine here, see the module docstring). ``cap_add`` is the *only* way caps come
    back after the blanket drop (e.g. ``("NET_RAW", "NET_ADMIN")`` for SYN scans).
    """

    image: str = "lalo-runtime:latest"
    network: str = "bridge"
    user: str | None = None
    workdir: str = "/work"
    memory: str = "3g"
    pids_limit: int = 1024
    cap_add: tuple[str, ...] = ()
    extra_run_args: tuple[str, ...] = ()


class RuntimeContainer:
    """Lifecycle wrapper for one disposable container."""

    def __init__(self, config: RuntimeConfig | None = None) -> None:
        self.config = config or RuntimeConfig()
        self._name = f"lalo-{uuid.uuid4().hex[:12]}"
        self._started = False

    @property
    def name(self) -> str:
        return self._name

    @property
    def started(self) -> bool:
        return self._started

    def _run(self, args: list[str], *, timeout: float = 60.0) -> subprocess.CompletedProcess[str]:
        return subprocess.run(  # noqa: S603 - resolved binary; workload isolation is the control
            [_docker_bin(), *args], capture_output=True, text=True, timeout=timeout
        )

    def _run_args(self) -> list[str]:
        args = [
            "run",
            "-d",
            "--name",
            self._name,
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--network",
            self.config.network,
            "--workdir",
            self.config.workdir,
            "--memory",
            self.config.memory,
            "--pids-limit",
            str(self.config.pids_limit),
        ]
        if self.config.user is not None:
            args += ["--user", self.config.user]
        for cap in self.config.cap_add:
            args += ["--cap-add", cap]
        # Deliberately NO -v/--mount (no host filesystem) and NO docker socket.
        args += list(self.config.extra_run_args)
        args += [self.config.image, *_KEEPALIVE]
        return args

    def start(self) -> None:
        result = self._run(self._run_args())
        if result.returncode != 0:
            raise ContainerError(f"container start failed: {result.stderr.strip()}")
        self._started = True
        if not self._is_running():
            tail = self._logs_tail()
            self.stop()
            raise ContainerError(f"container exited immediately; logs: {tail}")
        _log.info("runtime container %s started (image=%s)", self._name, self.config.image)

    def _is_running(self) -> bool:
        result = self._run(["inspect", "-f", "{{.State.Running}}", self._name], timeout=15)
        return result.returncode == 0 and result.stdout.strip() == "true"

    def _logs_tail(self, lines: int = 20) -> str:
        result = self._run(["logs", "--tail", str(lines), self._name], timeout=15)
        return (result.stdout + result.stderr).strip()[:2000]

    def exec(self, command: str | list[str], *, timeout: float = 120.0) -> ExecResult:
        """Run a command inside the container. A string is run via ``sh -c``."""
        if not self._started:
            raise ContainerError("cannot exec: container not started")
        if isinstance(command, str):
            argv = ["exec", self._name, "sh", "-c", command]
        else:
            argv = ["exec", self._name, *command]
        try:
            result = self._run(argv, timeout=timeout)
        except subprocess.TimeoutExpired:
            return ExecResult(exit_code=124, stdout="", stderr="timeout", timed_out=True)
        return ExecResult(exit_code=result.returncode, stdout=result.stdout, stderr=result.stderr)

    def stop(self) -> None:
        if self._started:
            self._run(["rm", "-f", self._name], timeout=30)
            self._started = False
            _log.info("runtime container %s removed", self._name)

    def __enter__(self) -> RuntimeContainer:
        self.start()
        return self

    def __exit__(self, *_exc: object) -> None:
        self.stop()
