"""Real command-execution sandbox for the autonomous loop (v4 R4).

One disposable Docker container per scan — the escape hatch for anything the
internal structured drivers (SQLi/BOLA/etc. detection logic) don't cover:
any external tool, any flags, genuinely no restrictions on what command
runs. No allowlist, no per-tool wrapper deciding what's "safe" — the
containment IS the safety boundary, not a restriction on what runs inside
it: no host filesystem mount beyond the container's own disposable
filesystem, never the operator's own credentials or machine, and (below)
network egress actually firewalled to the scan's own `ScopeGuard` allowlist
rather than left open on the bridge network. A target's own response content
can flow back into the loop as an observation and could attempt prompt
injection through it — even a successful injection can at worst make this
disposable container run an unwanted command inside itself, and that
command still cannot reach anything off the scan's own allowlist. That is
the concrete reason this boundary does not move.

**Network egress is firewalled, not just bridge-isolated.** Bridge
networking alone gives a container unrestricted outbound internet access
(and a path to the Docker host's own bridge-gateway IP) — that is not
"scoped to the allowlist," it is merely not `--network host`. To actually
hold CLAUDE.md's non-negotiable, the container is started with
`--cap-add=NET_ADMIN` and, immediately after it starts, an `iptables` OUTPUT
allowlist is installed *inside the container's own network namespace* (via
`docker exec`, so no host root/sudo is needed — the capability is scoped to
that one container): default-deny, loopback and DNS excepted, plus one
explicit ACCEPT per IP a `ScopeGuard` host resolves to. A command inside the
sandbox can still reach every in-scope target on any port (nmap/ffuf/hydra
etc. need that), but nothing else — not the internet at large, not the
Docker bridge gateway, not the operator's host. Known, disclosed limit:
wildcard scope entries (``*.example.com``) cannot back a fixed-IP allowlist
and are skipped (see `ScopeGuard.allowed_hosts`); a scan scoped only to a
wildcard gets an egress-locked sandbox (loopback/DNS only) until a concrete
host is also in scope.

Uses the `docker` CLI directly via `subprocess` (argument arrays, never
`shell=True`) — matching every other external-tool wrapper in this
codebase — rather than adding the `docker` Python SDK as a new dependency.
"""

from __future__ import annotations

import logging
import shutil
import socket
import subprocess
from dataclasses import dataclass

from reachagent.execution.scope import ScopeGuard

_log = logging.getLogger(__name__)

DEFAULT_IMAGE = "reachagent-agent-sandbox:latest"
_START_TIMEOUT_S = 60.0
_DEFAULT_COMMAND_TIMEOUT_S = 120.0
_STOP_TIMEOUT_S = 15.0
_MAX_OUTPUT_CHARS = 20_000  # bounded like every other tool output in this codebase

# Container resource caps — a command inside the sandbox (genuinely
# unrestricted, by design) must not be able to starve the operator's own
# host via a fork bomb or a memory hog; matches the same host-impact concern
# `recon/tools/base.py` already guards its own child processes against.
_MEMORY_LIMIT = "2g"
_PIDS_LIMIT = "512"
_CPU_LIMIT = "2"


class SandboxUnavailableError(RuntimeError):
    """The sandbox cannot be used at all — no `docker` binary, daemon down,
    image missing, or the container failed to start. Never raised by a
    command that ran and merely exited non-zero; that's a normal
    :class:`SandboxResult`, not an error."""


@dataclass(frozen=True)
class SandboxResult:
    """One command's real, bounded result — returned to the loop as an
    observation exactly like any other tool's output."""

    command: str
    exit_code: int
    output: str
    timed_out: bool = False


class AgentSandbox:
    """One disposable Docker container scoped to a single scan.

    `start()` once, `run_command()` any number of times, `stop()` once —
    matching a scan's own lifecycle (created at launch, torn down at end,
    the same "tear down after live work" discipline this project already
    applies to its own eval targets).
    """

    def __init__(
        self, scan_id: str, *, image: str = DEFAULT_IMAGE, scope: ScopeGuard | None = None
    ) -> None:
        self.container_name = f"reachagent-sandbox-{scan_id}"
        self._image = image
        self._scope = scope
        self._started = False

    def start(self) -> None:
        if shutil.which("docker") is None:
            raise SandboxUnavailableError("docker binary not found on PATH")
        # A fresh, disposable container: bridge networking (egress is then
        # locked down below, see _apply_network_scope), no host filesystem
        # mount, no published ports, auto-removed on stop, capped resources
        # so a command inside can't starve the host. --cap-add=NET_ADMIN is
        # scoped to this container's own network namespace only — it lets
        # the container manage its own iptables, not the host's. The image's
        # own CMD (sleep infinity) keeps it alive for `docker exec` calls.
        argv = [
            "docker",
            "run",
            "-d",
            "--name",
            self.container_name,
            "--network",
            "bridge",
            "--cap-add",
            "NET_ADMIN",
            "--memory",
            _MEMORY_LIMIT,
            "--pids-limit",
            _PIDS_LIMIT,
            "--cpus",
            _CPU_LIMIT,
            "--rm",
            self._image,
        ]
        try:
            completed = subprocess.run(  # noqa: S603 — array args, shell=False, no interpolation
                argv,
                capture_output=True,
                text=True,
                timeout=_START_TIMEOUT_S,
                check=False,
                shell=False,
            )
        except (subprocess.SubprocessError, OSError) as exc:
            self._force_remove_by_name()  # in case the daemon created it before failing
            raise SandboxUnavailableError(f"failed to start sandbox container: {exc}") from exc
        if completed.returncode != 0:
            raise SandboxUnavailableError(
                f"docker run failed ({completed.returncode}): {completed.stderr.strip()[:500]}"
            )
        self._started = True
        try:
            self._apply_network_scope()
        except SandboxUnavailableError:
            self.stop()  # fail closed — never leave a container with open egress running
            raise

    def _force_remove_by_name(self) -> None:
        """Best-effort cleanup for a container the daemon may have created
        before the `docker run` call itself failed/timed out (`--rm` never
        fires for a still-running `sleep infinity` container)."""
        argv = ["docker", "rm", "-f", self.container_name]
        try:
            subprocess.run(  # noqa: S603 — array args, shell=False
                argv, capture_output=True, timeout=_STOP_TIMEOUT_S, check=False, shell=False
            )
        except (subprocess.SubprocessError, OSError):
            pass

    def _apply_network_scope(self) -> None:
        """Lock the container's own OUTPUT chain (both `iptables` and
        `ip6tables` — a target resolving only over IPv6 must not bypass an
        IPv4-only allowlist) to loopback + DNS + the scan's in-scope hosts,
        resolved to IP. Runs inside the container's own network namespace
        via `docker exec` — no host root needed."""
        allowed_hosts = self._scope.allowed_hosts() if self._scope is not None else []
        if self._scope is None:
            _log.warning(
                "sandbox %s started with no ScopeGuard — egress locked to loopback/DNS only",
                self.container_name,
            )
        ipv4: set[str] = set()
        ipv6: set[str] = set()
        for host in allowed_hosts:
            try:
                for family, _type, _proto, _canon, sockaddr in socket.getaddrinfo(host, None):
                    if family == socket.AF_INET:
                        ipv4.add(sockaddr[0])
                    elif family == socket.AF_INET6:
                        ipv6.add(sockaddr[0])
            except OSError as exc:
                _log.warning("sandbox egress scope: could not resolve %r: %s", host, exc)

        def _rules(binary: str, ips: set[str]) -> list[str]:
            return [
                f"{binary} -F OUTPUT",
                f"{binary} -A OUTPUT -o lo -j ACCEPT",
                f"{binary} -A OUTPUT -p udp --dport 53 -j ACCEPT",
                f"{binary} -A OUTPUT -p tcp --dport 53 -j ACCEPT",
                *[f"{binary} -A OUTPUT -d {ip} -j ACCEPT" for ip in sorted(ips)],
                f"{binary} -P OUTPUT DROP",
            ]

        script = " && ".join([*_rules("iptables", ipv4), *_rules("ip6tables", ipv6)])
        result = self.run_command(script, timeout=_START_TIMEOUT_S)
        if result.exit_code != 0:
            raise SandboxUnavailableError(
                f"failed to apply sandbox network scope: {result.output[:500]}"
            )

    def run_command(
        self, command: str, *, timeout: float = _DEFAULT_COMMAND_TIMEOUT_S
    ) -> SandboxResult:
        """Execute ``command`` via ``sh -c`` inside the container — genuinely
        arbitrary, no allowlist, no flag parsing: the caller composes the
        full command line itself, exactly as a real shell would accept it.
        """
        if not self._started:
            raise SandboxUnavailableError("sandbox not started — call start() first")
        argv = ["docker", "exec", self.container_name, "sh", "-c", command]
        try:
            completed = subprocess.run(  # noqa: S603 — array args, shell=False; `command` itself
                # is the one deliberately-unrestricted string, per this module's own design —
                # it reaches `sh -c` INSIDE the disposable container, never this host's shell.
                argv,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
                shell=False,
            )
        except subprocess.TimeoutExpired:
            return SandboxResult(
                command=command, exit_code=-1, output="(command timed out)", timed_out=True
            )
        except (subprocess.SubprocessError, OSError) as exc:
            return SandboxResult(
                command=command, exit_code=-1, output=f"(sandbox exec failed: {type(exc).__name__})"
            )
        output = (completed.stdout + completed.stderr)[:_MAX_OUTPUT_CHARS]
        return SandboxResult(command=command, exit_code=completed.returncode, output=output)

    def stop(self) -> None:
        """Tear down the container. Safe to call even if `start()` never
        succeeded or was never called — a no-op in that case."""
        if not self._started:
            return
        argv = ["docker", "rm", "-f", self.container_name]
        try:
            subprocess.run(  # noqa: S603 — array args, shell=False
                argv,
                capture_output=True,
                timeout=_STOP_TIMEOUT_S,
                check=False,
                shell=False,
            )
        except (subprocess.SubprocessError, OSError) as exc:
            _log.warning("sandbox teardown for %s failed: %s", self.container_name, exc)
        self._started = False

    def __enter__(self) -> AgentSandbox:
        self.start()
        return self

    def __exit__(self, *_exc: object) -> None:
        self.stop()
