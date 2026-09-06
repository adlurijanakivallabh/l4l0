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

Phase 1, pentagi pass: that same reference's cap-add allowlist grants
``SYS_PTRACE`` *unconditionally* (unlike its own ``NET_ADMIN``, which is gated
behind an explicit config flag) — reasoned as safe to always grant because
ptrace never crosses a container's own PID namespace boundary: it only ever
lets a process trace another process already inside the SAME container, never
the host or a sibling container. Adopted as an always-granted baseline here
too, for a concrete reason no caller in this codebase was actually closing:
the arsenal image unconditionally ships ``gdb``/``radare2`` for the in-mission
binary/pwn work L4L0's own mandate covers, but Docker's default seccomp
profile blocks the ``ptrace(2)`` syscall entirely unless ``CAP_SYS_PTRACE`` is
present — with no caller ever requesting it via ``cap_add``, every real scan's
own pre-installed debugger was silently unusable for anything beyond static
disassembly. Granted as a fixed baseline (like ``--cap-drop ALL`` itself)
rather than through ``cap_add``, since the agent's free-shell model means any
tool in the arsenal can be invoked unpredictably at any point in a scan — there
is no natural "this specific call needs debugging" moment for a caller to opt
in at.
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

# Granted unconditionally to every sandbox, never opt-in via `cap_add` — see
# the module docstring's Phase 1 pentagi-pass note for why SYS_PTRACE alone
# gets this treatment (never crosses the container's own PID namespace; the
# arsenal's own gdb/radare2 need it for anything beyond static analysis).
_BASELINE_CAPS = ("SYS_PTRACE",)


def _normalize_cap(cap: str) -> str:
    """Docker itself accepts a capability name case-insensitively and with an
    optional ``CAP_`` prefix (``sys_admin`` and ``CAP_SYS_ADMIN`` both grant the
    same real capability as ``SYS_ADMIN``) — normalize before comparing against
    :data:`_FORBIDDEN_CAPS`, or a caller can trivially bypass the check by
    varying case/prefix while Docker still grants the forbidden capability."""
    return cap.strip().upper().removeprefix("CAP_")


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
    fine here, see the module docstring). ``cap_add`` is how a caller opts a
    scan into anything BEYOND the fixed :data:`_BASELINE_CAPS` (e.g.
    ``("NET_RAW",)`` for a raw-socket tool); each is validated against
    :data:`_FORBIDDEN_CAPS` at construction time.
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
        normalized = {_normalize_cap(cap) for cap in self.cap_add}
        forbidden = _FORBIDDEN_CAPS.intersection(normalized)
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
        for cap in _BASELINE_CAPS:
            args += ["--cap-add", cap]
        for cap in self.config.cap_add:
            args += ["--cap-add", cap]
        # Deliberately NO -v/--mount (no host filesystem) and NO docker socket —
        # never offered as a config option here, unlike every reference that
        # either lacks scope-egress hardening or ships host-socket delegation.
        args += list(self.config.extra_run_args)
        args += [self.config.image, *_KEEPALIVE]
        return args

    def _best_effort_remove(self) -> None:
        """Try to remove a container that may or may not actually exist yet.

        Used when a docker call timed out client-side: the daemon may have
        finished creating/starting the container regardless, and leaving it
        behind would contradict this module's "removal on exit" guarantee.
        """
        try:
            self._run(["rm", "-f", self._name], timeout=30)
        except subprocess.TimeoutExpired:
            _log.warning("best-effort cleanup of %s also timed out; it may be orphaned", self._name)

    def start(self) -> None:
        try:
            result = self._run(self._run_args())
        except subprocess.TimeoutExpired as exc:
            # The client-side call timed out, but the daemon may have created
            # and started the container anyway — clean up before raising so
            # __enter__ raising (which skips __exit__/stop() entirely, per
            # Python's own context-manager protocol) can't leak it.
            self._best_effort_remove()
            raise ContainerError(f"container start timed out: {exc}") from exc
        if result.returncode != 0:
            raise ContainerError(f"container start failed: {result.stderr.strip()}")
        self._started = True
        # Liveness check immediately after issuing the start call (no
        # intervening work) so a container that dies within milliseconds is
        # caught here, not silently reported as "started" — the failure mode a
        # reference project's own hardening notes specifically call out.
        try:
            running = self._is_running()
        except subprocess.TimeoutExpired as exc:
            self._started = False
            self._best_effort_remove()
            raise ContainerError(f"liveness check timed out: {exc}") from exc
        if not running:
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
            try:
                self._run(["rm", "-f", self._name], timeout=30)
            except subprocess.TimeoutExpired:
                _log.warning("removal of %s timed out; it may be orphaned", self._name)
            # Either way, this wrapper no longer treats the container as usable —
            # a timed-out removal leaves its actual state unknown, and retrying
            # exec() against it would be worse than refusing further use.
            self._started = False
            _log.info("runtime container %s removed", self._name)

    def __enter__(self) -> RuntimeContainer:
        self.start()
        return self

    def __exit__(self, *_exc: object) -> None:
        self.stop()
