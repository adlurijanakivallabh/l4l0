"""Hermetic tests for RuntimeContainer.exec_streaming - subprocess.Popen is
mocked, matching test_runtime_timeout.py's own subprocess.run-mocking
convention for this module. No real Docker daemon needed."""

from __future__ import annotations

from unittest.mock import patch

from lalo.runtime import RuntimeConfig, RuntimeContainer


class _FakePopen:
    def __init__(self, argv: list[str], **_kwargs: object) -> None:
        self.argv = argv
        self.stdout = iter(["line one\n", "line two\n"])
        self.stderr = iter(["an error line\n"])
        self.returncode = 0

    def wait(self, timeout: float | None = None) -> int:
        return self.returncode

    def kill(self) -> None:
        self.returncode = -9


def _started_container() -> RuntimeContainer:
    container = RuntimeContainer(RuntimeConfig())
    container._started = True  # bypass a real docker start for this unit test
    return container


def test_exec_streaming_calls_on_chunk_for_each_line_of_each_stream() -> None:
    chunks: list[tuple[str, str]] = []
    with patch("lalo.runtime.container.subprocess.Popen", _FakePopen):
        _started_container().exec_streaming(
            "echo hi", lambda stream, text: chunks.append((stream, text))
        )
    assert ("stdout", "line one\n") in chunks
    assert ("stdout", "line two\n") in chunks
    assert ("stderr", "an error line\n") in chunks


def test_exec_streaming_returns_the_same_exec_result_shape_as_exec() -> None:
    with patch("lalo.runtime.container.subprocess.Popen", _FakePopen):
        result = _started_container().exec_streaming("echo hi", lambda _s, _t: None)
    assert result.exit_code == 0
    assert result.stdout == "line one\nline two\n"
    assert result.stderr == "an error line\n"
    assert result.ok is True


def test_exec_streaming_before_start_raises_container_error() -> None:
    import pytest

    from lalo.core.errors import ContainerError

    container = RuntimeContainer(RuntimeConfig())
    with pytest.raises(ContainerError, match="not started"):
        container.exec_streaming("echo hi", lambda _s, _t: None)
