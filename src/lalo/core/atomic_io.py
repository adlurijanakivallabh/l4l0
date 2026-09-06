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

Every persisted file written this way is now created owner-only (``0600``) —
informed by a different reference agent's own real ``config/resolver.ts``/
``writer.ts`` (read in full): its CLI config file is always written ``0o600``
and its loader outright *refuses to read* the file if its permissions are
looser than that. This function reuses the idea for a broader reason than
that reference's own single config file: every persisted L4L0 artifact whose
own natural shape is a whole-file replace (the reachability graph, all five
report formats, the lifetime usage log) flows through this one shared
primitive — the durable journal is the one exception, since it's an
append-only log for which a replace-the-whole-file primitive is the wrong
shape (see :mod:`lalo.orchestrator.journal`'s own Phase 2 note for how it
gets the same 0600 property without that mismatch). Every artifact that DOES
route through here can carry confidential engagement/target/finding data even
after
:mod:`lalo.core.redaction` has stripped literal secrets out of it — "what
target was tested and what was found on it" is itself sensitive regardless
of whether a raw credential string survives inside it. Fixed once here,
at the one place every writer already funnels through, rather than as a
per-caller ``os.chmod`` someone has to remember to add at each of many call
sites. The permission is set at file-creation time via ``os.open``'s own
``mode`` argument (not a later ``os.chmod``), so there is no window, however
brief, where the temp file exists more permissively than its final mode —
and since POSIX ``rename`` (what ``os.replace`` performs) preserves the
*source* inode's own permission bits rather than resetting them, the final
path ends up ``0600`` too, with no separate chmod needed after the swap.
"""

from __future__ import annotations

import os
import uuid
from pathlib import Path

from .errors import LaloError

_OWNER_ONLY = 0o600


class AtomicWriteError(LaloError):
    """A write's byte-verify failed before the swap; the original file is untouched."""

    code = "atomic_write_error"


def append_owner_only_line(path: Path, line: str) -> None:
    """Append ``line`` (plus a trailing newline) to ``path``, owner-only (``0600``).

    The append-only counterpart to :func:`atomic_write_verified`: an
    append-only log that grows over a long-running scan is the wrong shape
    for a whole-file replace-and-verify primitive (read-modify-write the
    whole file on every record would be quadratic), so this gets the same
    ``0600`` property a different way — set at file-creation time via
    ``os.open``'s own ``mode`` argument, and re-tightened via
    :func:`os.fchmod` even if the file already existed looser. Originally
    factored out of :class:`~lalo.orchestrator.journal.DurableJournal`
    (its own module docstring has the full citation for why this file's
    permissions matter) once a second append-only-log caller needed the
    exact same behavior.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, _OWNER_ONLY)
    os.fchmod(fd, _OWNER_ONLY)  # tighten even if the file pre-existed looser
    with os.fdopen(fd, "a", encoding="utf-8") as handle:
        handle.write(line if line.endswith("\n") else line + "\n")
        handle.flush()
        os.fsync(handle.fileno())


def atomic_write_verified(path: Path, data: bytes) -> None:
    """Write ``data`` to ``path`` atomically and owner-only (``0600``), never
    leaving a truncated file behind.

    A crash at any point before the final ``os.replace`` leaves the original
    file (if any) completely untouched — the temp file is simply orphaned and
    ignored by every reader, which only ever opens ``path`` itself.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.parent / f".{path.name}.tmp-{uuid.uuid4().hex}"
    try:
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode=_OWNER_ONLY)
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        if tmp.read_bytes() != data:
            raise AtomicWriteError(f"byte-verify failed writing {path}; original left untouched")
        os.replace(tmp, path)
    finally:
        tmp.unlink(missing_ok=True)
