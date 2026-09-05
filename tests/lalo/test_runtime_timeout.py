"""Hermetic tests for RuntimeContainer's docker-call timeout handling.

No real Docker daemon needed -- subprocess.run itself is mocked, so these run
unconditionally (unlike test_runtime.py's live-Docker integration suite).
"""

from __future__ import annotations

import subprocess
from unittest.mock import patch

import pytest

from lalo.core.errors import ContainerError
from lalo.runtime import RuntimeConfig, RuntimeContainer


def _completed(
    returncode: int = 0, stdout: str = "", stderr: str = ""
) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr=stderr)


def test_start_timeout_raises_container_error_and_attempts_cleanup() -> None:
    calls: list[list[str]] = []

    def fake_run(argv: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append(argv)
        if argv[1] == "run":
            raise subprocess.TimeoutExpired(cmd=argv, timeout=60.0)
        return _completed()  # the best-effort `docker rm -f` cleanup call

    with (
        patch("lalo.runtime.container._docker_bin", return_value="docker"),
        patch("lalo.runtime.container.subprocess.run", side_effect=fake_run),
    ):
        container = RuntimeContainer(RuntimeConfig())
        with pytest.raises(ContainerError, match="timed out"):
            container.start()

    assert any(c[1] == "rm" for c in calls)  # cleanup was actually attempted
    assert container.started is False


def test_liveness_check_timeout_raises_and_cleans_up() -> None:
    calls: list[list[str]] = []

    def fake_run(argv: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append(argv)
        if argv[1] == "run":
            return _completed()
        if argv[1] == "inspect":
            raise subprocess.TimeoutExpired(cmd=argv, timeout=15.0)
        return _completed()  # `docker rm -f` cleanup

    with (
        patch("lalo.runtime.container._docker_bin", return_value="docker"),
        patch("lalo.runtime.container.subprocess.run", side_effect=fake_run),
    ):
        container = RuntimeContainer(RuntimeConfig())
        with pytest.raises(ContainerError, match="timed out"):
            container.start()

    assert any(c[1] == "rm" for c in calls)
    assert container.started is False


def test_stop_timeout_is_logged_not_raised_and_still_marks_stopped() -> None:
    def fake_run(argv: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        if argv[1] == "rm":
            raise subprocess.TimeoutExpired(cmd=argv, timeout=30.0)
        return _completed()

    with (
        patch("lalo.runtime.container._docker_bin", return_value="docker"),
        patch("lalo.runtime.container.subprocess.run", side_effect=fake_run),
    ):
        container = RuntimeContainer(RuntimeConfig())
        container._started = True  # noqa: SLF001 - simulate an already-started container
        container.stop()  # must not raise

    assert container.started is False
