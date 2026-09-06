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


class _TimeoutPopen:
    """Popen mock that raises TimeoutExpired on wait() to test timeout path."""

    def __init__(self, argv: list[str], **_kwargs: object) -> None:
        self.argv = argv
        self.stdout = iter(["partial output\n"])
        self.stderr = iter([])
        self.returncode = None  # not set until wait succeeds
        self.wait_count = 0

    def wait(self, timeout: float | None = None) -> int:
        import subprocess

        self.wait_count += 1
        if self.wait_count == 1:
            # First call: simulate timeout
            raise subprocess.TimeoutExpired(cmd=self.argv, timeout=timeout or 0.0)
        # Second call (after kill()): return a code
        self.returncode = -9
        return self.returncode

    def kill(self) -> None:
        self.returncode = -9


def test_exec_streaming_timeout_returns_exit_code_124_and_timed_out_true() -> None:
    chunks: list[tuple[str, str]] = []
    with patch("lalo.runtime.container.subprocess.Popen", _TimeoutPopen):
        result = _started_container().exec_streaming(
            "sleep 1000", lambda stream, text: chunks.append((stream, text)), timeout=0.1
        )
    assert result.exit_code == 124
    assert result.timed_out is True
    assert result.ok is False
    # Should have captured partial output before timeout
    assert ("stdout", "partial output\n") in chunks


def test_exec_streaming_tolerates_on_chunk_raising() -> None:
    """If on_chunk raises, the pump thread should catch it and continue draining."""
    chunks: list[tuple[str, str]] = []

    def raising_callback(stream: str, text: str) -> None:
        chunks.append((stream, text))
        if stream == "stdout" and "one" in text:
            raise ValueError("callback error")

    with patch("lalo.runtime.container.subprocess.Popen", _FakePopen):
        # Should not raise, even though callback raises
        result = _started_container().exec_streaming("echo hi", raising_callback)
    # Command should complete normally despite callback raising
    assert result.exit_code == 0
    assert result.ok is True
    # Output should be fully captured
    assert result.stdout == "line one\nline two\n"
    assert result.stderr == "an error line\n"
    # Callback was called and recorded what succeeded before raising
    assert ("stdout", "line one\n") in chunks
