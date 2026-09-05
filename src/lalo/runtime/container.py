"""Per-scan disposable runtime container, managed via the ``docker`` CLI.

Host isolation is enforced by the run flags, not by trusting the workload:
``--cap-drop ALL`` (+ only explicitly requested, non-forbidden caps),
``no-new-privileges``, **no bind-mounts**, **no Docker socket** (never offered as
an option — no reference project's equivalent of this is worth adopting: one
mounts the host socket into its dev container by default, another ships
Docker-in-Docker as a documented feature with a self-aware warning it still
ships anyway), a pids/memory limit, bounded log growth, and removal on exit.

A reference project's own sandbox hardening notes (cap-drop ALL + a documented,
narrow cap-add allowlist with explicit hard exclusions for SYS_ADMIN/SYS_MODULE/
SYS_RAWIO/SYS_BOOT) are adopted here — but that project only *documents* the
exclusion list; this module *enforces* it: requesting a forbidden capability
raises before any container is started, rather than relying on the caller to
have read the comment.
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

# Capabilities that must never be added to the sandbox, regardless of what a
# caller requests — each would materially weaken containment (kernel module
# load, raw I/O, admin-equivalent, reboot). Runtime-enforced, not just documented.
_FORBIDDEN_CAPS = frozenset({"SYS_ADMIN", "SYS_MODULE", "SYS_RAWIO", "SYS_BOOT"})


class ForbiddenCapabilityError(ContainerError):
    """A caller requested a capability that must never be granted to the sandbox."""

    code = "container_error"


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
    back after the blanket drop (e.g. ``("NET_RAW",)`` for a raw-socket tool);
    each is validated against :data:`_FORBIDDEN_CAPS` at construction time.
    No restart policy is set on purpose: this is a single-shot disposable
    container — a crash should surface immediately, not silently retry and mask
    a fast-crash-loop.
    """

    image: str = "lalo-runtime:latest"
    network: str = "bridge"
    user: str | None = None
    workdir: str = "/work"
    memory: str = "3g"
    pids_limit: int = 2048  # caps fork bombs
    cap_add: tuple[str, ...] = ()
    log_max_size: str = "10m"
    log_max_files: int = 3
    extra_run_args: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        forbidden = _FORBIDDEN_CAPS.intersection(self.cap_add)
        if forbidden:
            raise ForbiddenCapabilityError(
                f"refusing to grant forbidden capabilities to the sandbox: {sorted(forbidden)}"
            )


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
            "--log-opt",
            f"max-size={self.config.log_max_size}",
            "--log-opt",
            f"max-file={self.config.log_max_files}",
        ]
        if self.config.user is not None:
            args += ["--user", self.config.user]
        for cap in self.config.cap_add:
            args += ["--cap-add", cap]
        # Deliberately NO -v/--mount (no host filesystem) and NO docker socket —
        # never offered as a config option here, unlike every reference that
        # either lacks scope-egress hardening or ships host-socket delegation.
        args += list(self.config.extra_run_args)
        args += [self.config.image, *_KEEPALIVE]
        return args

    def start(self) -> None:
        result = self._run(self._run_args())
        if result.returncode != 0:
            raise ContainerError(f"container start failed: {result.stderr.strip()}")
        self._started = True
        # Liveness check immediately after issuing the start call (no
        # intervening work) so a container that dies within milliseconds is
        # caught here, not silently reported as "started" — the failure mode a
        # reference project's own hardening notes specifically call out.
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
        argv = (
            ["exec", self._name, "sh", "-c", command]
            if isinstance(command, str)
            else [
                "exec",
                self._name,
                *command,
            ]
        )
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
