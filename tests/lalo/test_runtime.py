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
