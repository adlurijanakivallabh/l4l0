"""Tests for RuntimeContainer.seed_files - staging pre-existing content (a
spec file, a wordlist, a small script) into a running container's workspace
via ``docker cp`` reading a tar stream from stdin.

The not-started check is hermetic (raises before any docker call, so no
mocking needed and it runs unconditionally); the write-content case needs a
real daemon and follows test_runtime.py's own docker_available() skip
convention.
"""

from __future__ import annotations

import pytest

from lalo.core.errors import ContainerError
from lalo.runtime import RuntimeContainer, docker_available


def test_seed_files_raises_when_container_not_started() -> None:
    container = RuntimeContainer()
    with pytest.raises(ContainerError, match="not started"):
        container.seed_files({"a.txt": b"hello"})


@pytest.mark.skipif(not docker_available(), reason="requires a running docker daemon")
def test_seed_files_writes_content_into_a_running_container() -> None:
    container = RuntimeContainer()
    container.start()
    try:
        container.seed_files({"spec.json": b'{"ok": true}', "sub/dir/note.txt": b"hi"})
        result = container.exec(f"cat {container.config.workdir}/spec.json")
        assert result.exit_code == 0
        assert '{"ok": true}' in result.stdout
        result2 = container.exec(f"cat {container.config.workdir}/sub/dir/note.txt")
        assert result2.exit_code == 0
        assert "hi" in result2.stdout
    finally:
        container.stop()
