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

Phase 1, strix pass (closes Phase 1): that reference unconditionally appends
``NET_ADMIN``/``NET_RAW`` to every sandbox's caps, "required for `nmap -sS`
and other raw-socket recon tools" — its own comparison notes this as broad
and *not scoped or gated by target/scope config*, a fair critique of granting
it with no complementary control. L4L0 doesn't have that weakness: a scope
guard (:mod:`lalo.core.scope`, built in Phase 3) already governs what network
destinations any tool may actually reach regardless of raw-socket access
(:mod:`lalo.execution.scope`, built in Phase 3), so granting ``NET_RAW`` here
adds no new way to reach an out-of-engagement host — only a faster/stealthier
way to probe an already-in-scope one. Adopted
``NET_RAW`` alone (not ``NET_ADMIN`` — routing/interface manipulation is
unrelated to what any curated recon tool needs and is reserved for the
narrower, explicit :attr:`RuntimeConfig.enable_vpn` opt-in instead) as a
second baseline capability alongside ``SYS_PTRACE``: unlike VPN connectivity
(a rare, engagement-specific need), raw-socket recon (SYN scans, OS
fingerprinting) is routine for nearly every network-facing engagement, and —
like ptrace — never crosses the container's own network namespace. Before
this, :mod:`lalo.recon.scan`'s nmap invocation silently downgraded to a
connect scan (nmap auto-detects missing ``CAP_NET_RAW`` and falls back) even
though nothing in that module claimed to want one; no recon-module code
change was needed to fix this — nmap opportunistically upgrades to a SYN scan
on its own once the capability is actually present.
"""

from __future__ import annotations

import shutil
import subprocess
import threading
import uuid
from collections.abc import Callable
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
# the module docstring's Phase 1 pentagi/strix-pass notes: SYS_PTRACE (the
# arsenal's gdb/radare2 need it for anything beyond static analysis) and
# NET_RAW (routine raw-socket recon like nmap SYN scans) never cross the
# container's own PID/network namespace, and NET_RAW is further backstopped
# by the separate scope guard governing what any tool may actually reach.
_BASELINE_CAPS = ("SYS_PTRACE", "NET_RAW")


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
    :data:`_FORBIDDEN_CAPS` at construction time. ``enable_vpn`` is a separate,
    narrower opt-in (Phase 1, PentestGPT pass — its own ``docker-compose.yml``
    grants ``NET_ADMIN`` + a mounted ``/dev/net/tun`` specifically "for OpenVPN
    (HackTheBox/TryHackMe connectivity)"): many real engagements are only
    reachable via a client-provided OpenVPN/WireGuard config, and the sandbox
    had no path to that network at all before this. Off by default and kept
    separate from ``cap_add`` — NET_ADMIN is materially more powerful than
    anything else this module grants, so a scan opts into it explicitly rather
    than it riding along with some other capability request; ``/dev/net/tun``
    stays namespace-scoped (lets a process create a virtual interface inside
    its OWN network namespace only), so this doesn't touch the "no host
    bind-mounts" line — no host filesystem or host network state is exposed.
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
    enable_vpn: bool = False
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
        if self.config.enable_vpn:
            args += ["--cap-add", "NET_ADMIN", "--device", "/dev/net/tun:/dev/net/tun"]
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

    def exec_streaming(
        self,
        command: str | list[str],
        on_chunk: Callable[[str, str], None],
        *,
        timeout: float = 120.0,
    ) -> ExecResult:
        """Like :meth:`exec`, but calls ``on_chunk(stream, text)`` with output
        as it's produced instead of only returning once the command
        finishes. Returns the identical :class:`ExecResult` shape - the
        streaming is a side channel for a live viewer, never a replacement
        for the agent's own synchronous "run a command, get the final
        result" contract every existing caller of :meth:`exec` relies on.

        The ``on_chunk(stream, text)`` callback is synchronized across both
        stdout and stderr streams (never called concurrently), and exceptions
        raised by the callback are silently caught to prevent stalling the
        pump threads: the callback's fault (e.g., a GUI event-handler crash)
        must not prevent the command from completing or its output from being
        fully drained.
        """
        if not self._started:
            raise ContainerError("cannot exec: container not started")
        argv = (
            [_docker_bin(), "exec", self._name, "sh", "-c", command]
            if isinstance(command, str)
            else [_docker_bin(), "exec", self._name, *command]
        )
        try:
            process = subprocess.Popen(  # noqa: S603 - resolved binary; workload isolation is the control
                argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1
            )
        except OSError as exc:
            return ExecResult(exit_code=1, stdout="", stderr=str(exc))

        stdout_chunks: list[str] = []
        stderr_chunks: list[str] = []
        callback_lock = threading.Lock()

        def _pump(stream: object, sink: list[str], name: str) -> None:
            try:
                for line in stream:  # type: ignore[attr-defined]
                    sink.append(line)
                    with callback_lock:
                        try:
                            on_chunk(name, line)
                        except Exception as exc:
                            _log.exception("on_chunk raised in exec_streaming; continuing: %s", exc)
            except Exception as exc:
                _log.exception("pump thread raised in exec_streaming: %s", exc)

        stdout_thread = threading.Thread(
            target=_pump, args=(process.stdout, stdout_chunks, "stdout"), daemon=True
        )
        stderr_thread = threading.Thread(
            target=_pump, args=(process.stderr, stderr_chunks, "stderr"), daemon=True
        )
        stdout_thread.start()
        stderr_thread.start()
        try:
            process.wait(timeout=timeout)
            timed_out = False
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
            timed_out = True
        stdout_thread.join(timeout=5)
        stderr_thread.join(timeout=5)
        return ExecResult(
            exit_code=124 if timed_out else process.returncode,
            stdout="".join(stdout_chunks),
            stderr="".join(stderr_chunks),
            timed_out=timed_out,
        )

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
