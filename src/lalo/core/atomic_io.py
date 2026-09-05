"""Crash-safe atomic file writes with byte-verify-after-write.

Adapted from a reference project's real `exact-output-commit.ts` (336 lines,
read in full), whose own docstring states the principle to keep: "acknowledgement
must follow proof, and a mismatch here rolls back and surfaces as terminal
rather than as a lying success." That file publishes an exact file set as one
git commit with re-read-and-byte-verify before returning success and a
rollback-to-HEAD on any failure. L4L0 has no git-backed deliverables repo to
commit into, so this keeps only the load-bearing idea — write to a unique temp
file, fsync, read it back and byte-compare, THEN atomically replace the real
path — dropping the git-commit machinery entirely as unneeded weight. Verifying
BEFORE the swap (rather than after, like the reference) means a mismatch never
touches the real file at all: no rollback step is even needed, the original is
simply never replaced.
"""

from __future__ import annotations

import os
import uuid
from pathlib import Path

from .errors import LaloError


class AtomicWriteError(LaloError):
    """A write's byte-verify failed before the swap; the original file is untouched."""

    code = "atomic_write_error"


def atomic_write_verified(path: Path, data: bytes) -> None:
    """Write ``data`` to ``path`` atomically, never leaving a truncated file behind.

    A crash at any point before the final ``os.replace`` leaves the original
    file (if any) completely untouched — the temp file is simply orphaned and
    ignored by every reader, which only ever opens ``path`` itself.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.parent / f".{path.name}.tmp-{uuid.uuid4().hex}"
    try:
        with tmp.open("wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        if tmp.read_bytes() != data:
            raise AtomicWriteError(f"byte-verify failed writing {path}; original left untouched")
        os.replace(tmp, path)
    finally:
        tmp.unlink(missing_ok=True)
