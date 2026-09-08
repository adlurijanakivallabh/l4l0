"""Hermetic tests for RuntimeContainer's opt-in keep-on-failure teardown.

No real Docker daemon needed -- subprocess.run itself is mocked, like
test_runtime_timeout.py's suite.
"""

from __future__ import annotations

import subprocess
from unittest.mock import patch

import lalo.runtime.container as container_module
from lalo.runtime import RuntimeConfig, RuntimeContainer


def _completed(
    returncode: int = 0, stdout: str = "", stderr: str = ""
) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr=stderr)


def test_stop_after_failure_skips_removal_and_logs_a_hint_when_keep_on_failure_is_set() -> None:
    calls: list[list[str]] = []
    warnings: list[str] = []

    def fake_run(argv: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append(argv)
        return _completed()

    def fake_warning(msg: str, *args: object) -> None:
        warnings.append(msg % args)

    with (
        patch("lalo.runtime.container._docker_bin", return_value="docker"),
        patch("lalo.runtime.container.subprocess.run", side_effect=fake_run),
        patch.object(container_module._log, "warning", side_effect=fake_warning),
    ):
        container = RuntimeContainer(RuntimeConfig(keep_on_failure=True))
        container._started = True  # noqa: SLF001 - simulate an already-started container
        container.stop(failed=True)

    assert not any(c[1] == "rm" for c in calls), (
        "docker rm must be skipped when keep_on_failure fires"
    )
    assert container.started is False
    assert any(
        container._name in w and "docker logs" in w and "docker rm" in w
        for w in warnings  # noqa: SLF001
    ), f"expected a docker logs/docker rm hint naming the container, got: {warnings!r}"


def test_stop_after_failure_still_removes_when_keep_on_failure_is_left_at_its_default() -> None:
    calls: list[list[str]] = []

    def fake_run(argv: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append(argv)
        return _completed()

    with (
        patch("lalo.runtime.container._docker_bin", return_value="docker"),
        patch("lalo.runtime.container.subprocess.run", side_effect=fake_run),
    ):
        container = RuntimeContainer(RuntimeConfig())  # keep_on_failure defaults to False
        container._started = True  # noqa: SLF001
        container.stop(failed=True)

    assert any(c[1] == "rm" for c in calls), (
        "a failed run must still be removed when the flag is off"
    )
    assert container.started is False


def test_stop_after_success_always_removes_regardless_of_keep_on_failure() -> None:
    calls: list[list[str]] = []

    def fake_run(argv: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append(argv)
        return _completed()

    with (
        patch("lalo.runtime.container._docker_bin", return_value="docker"),
        patch("lalo.runtime.container.subprocess.run", side_effect=fake_run),
    ):
        container = RuntimeContainer(RuntimeConfig(keep_on_failure=True))
        container._started = True  # noqa: SLF001
        container.stop()  # failed defaults to False -- a normal, successful teardown

    assert any(c[1] == "rm" for c in calls), (
        "a successful run's container removal must be unaffected"
    )
    assert container.started is False
