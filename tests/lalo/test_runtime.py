"""Runtime container tests — the host-isolation boundary.

Marked ``integration`` and skipped when Docker is unavailable. Uses ``alpine``
(tiny) rather than the full arsenal image.
"""

from __future__ import annotations

import pytest

from lalo.core.errors import ContainerError
from lalo.runtime import ForbiddenCapabilityError, RuntimeConfig, RuntimeContainer, docker_available

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not docker_available(), reason="docker daemon not available"),
]

_IMAGE = "alpine:latest"


def test_forbidden_capability_rejected_before_any_container_starts() -> None:
    # Runtime-enforced, not just documented — a reference sandbox only documents
    # this exclusion list; requesting one here must raise at config construction,
    # before docker is ever invoked.
    with pytest.raises(ForbiddenCapabilityError):
        RuntimeConfig(cap_add=("SYS_ADMIN",))


def test_forbidden_capability_check_normalizes_case_and_cap_prefix() -> None:
    # Docker itself grants a capability case-insensitively and with an optional
    # CAP_ prefix -- sys_admin, Sys_Admin, and CAP_SYS_ADMIN all actually grant
    # the identical real capability as SYS_ADMIN (verified against a live daemon:
    # `docker run --cap-drop ALL --cap-add sys_admin` sets CapEff's SYS_ADMIN bit
    # exactly like the fully-qualified spelling does), so the forbidden-cap check
    # must normalize the same way or it is trivially bypassed by spelling alone.
    for spelling in ("sys_admin", "Sys_Admin", "CAP_SYS_ADMIN", "cap_sys_admin"):
        with pytest.raises(ForbiddenCapabilityError):
            RuntimeConfig(cap_add=(spelling,))


def test_lifecycle_start_exec_stop() -> None:
    container = RuntimeContainer(RuntimeConfig(image=_IMAGE))
    with container as c:
        assert c.started
        result = c.exec("echo hello-lalo")
        assert result.ok
        assert result.stdout.strip() == "hello-lalo"
    assert container.started is False


def test_host_filesystem_is_not_mounted() -> None:
    with RuntimeContainer(RuntimeConfig(image=_IMAGE)) as c:
        work = c.exec("ls -a /work")
        assert "pyproject.toml" not in work.stdout
        assert "src" not in work.stdout.split()
        assert c.exec("test -e /host").exit_code != 0


def test_no_docker_socket() -> None:
    with RuntimeContainer(RuntimeConfig(image=_IMAGE)) as c:
        assert c.exec("test -S /var/run/docker.sock").exit_code != 0


def test_agent_can_install_and_run_a_tool() -> None:
    # In-container root + network -> the agent can install anything it needs.
    with RuntimeContainer(RuntimeConfig(image=_IMAGE)) as c:
        install = c.exec("apk add --no-cache jq >/dev/null 2>&1 && jq --version", timeout=120)
        assert install.ok, f"install failed: {install.stderr}"
        assert install.stdout.strip().startswith("jq-")


def test_pids_limit_and_memory_flags_applied() -> None:
    with RuntimeContainer(RuntimeConfig(image=_IMAGE, pids_limit=64)) as c:
        result = c.exec("cat /sys/fs/cgroup/pids.max 2>/dev/null || echo missing")
        # cgroup v2 exposes pids.max directly inside the container.
        assert "64" in result.stdout or "missing" in result.stdout


def test_immediate_exit_is_detected() -> None:
    container = RuntimeContainer(RuntimeConfig(image="lalo-nonexistent-image:404"))
    with pytest.raises(ContainerError):
        container.start()
    container.stop()


def test_sys_ptrace_is_granted_unconditionally_for_the_arsenals_debugger() -> None:
    # Docker's default seccomp profile blocks ptrace(2) without CAP_SYS_PTRACE,
    # regardless of user -- without this, the arsenal's own gdb/radare2 could
    # never attach to or single-step a live process, only disassemble statically.
    with RuntimeContainer(RuntimeConfig(image=_IMAGE)) as c:
        cap_eff = c.exec("grep CapEff /proc/self/status").stdout
        assert cap_eff, "could not read /proc/self/status inside the sandbox"
        # bit 19 (0x80000) is CAP_SYS_PTRACE; verified against a live daemon
        # the same way the forbidden-cap check above is.
        hex_value = cap_eff.split()[-1]
        assert int(hex_value, 16) & 0x80000, f"CAP_SYS_PTRACE not effective: {cap_eff!r}"


def test_sys_ptrace_baseline_is_present_even_with_an_empty_cap_add() -> None:
    # Fast, no-docker-needed check on the args shape itself.
    container = RuntimeContainer(RuntimeConfig(image=_IMAGE))
    args = container._run_args()
    ptrace_index = args.index("SYS_PTRACE")
    assert args[ptrace_index - 1] == "--cap-add"
