"""Runtime container tests — the host-isolation boundary.

Marked ``integration`` and skipped when Docker is unavailable. Uses ``alpine``
(tiny, pulled on demand) rather than the full arsenal image.
"""

from __future__ import annotations

import pytest

from lalo.runtime import RuntimeConfig, RuntimeContainer, docker_available

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not docker_available(), reason="docker daemon not available"),
]

_IMAGE = "alpine:latest"


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
        # The repo/host cwd must not be visible anywhere obvious.
        work = c.exec("ls -a /work")
        assert "pyproject.toml" not in work.stdout
        assert "src" not in work.stdout.split()
        # No host home / etc leakage of our own files.
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


def test_immediate_exit_is_detected() -> None:
    # An image whose keepalive can't run should surface as a start failure, not a
    # false "started". Use a bogus image name to force a start error.
    container = RuntimeContainer(RuntimeConfig(image="lalo-nonexistent-image:404"))
    from lalo.core.errors import ContainerError

    with pytest.raises(ContainerError):
        container.start()
    container.stop()
