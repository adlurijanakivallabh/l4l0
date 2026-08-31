"""Per-process memory cap for live tool spawns (§9 resilience).

A pre-spawn "is memory low right now" check can't catch a tool that starts
fine and grows afterward — confirmed for real this session: a katana run
against a real remote target grew to 4.48GB resident before the kernel's
OOM-killer intervened, and the surrounding memory pressure froze the host
for minutes before that kill even landed. limit_child_memory() is the
during-the-run backstop.
"""

from __future__ import annotations

import subprocess

from reachagent.recon.tools._net import (
    GO_MEMORY_LIMIT_ENV,
    MAX_TOOL_VIRTUAL_MEMORY_BYTES,
    limit_child_memory,
)

_OVER_LIMIT_ALLOCATION = 5_000_000_000  # comfortably above the cap


def test_child_cannot_exceed_the_virtual_memory_cap() -> None:
    """Real subprocess, real setrlimit — not mocked. This is the exact failure
    mode that froze the host: prove the cap actually stops it."""
    code = (
        "try:\n"
        f"    buf = bytearray({_OVER_LIMIT_ALLOCATION})\n"
        "    buf[0] = 1\n"
        "    print('ALLOCATED')\n"
        "except MemoryError:\n"
        "    print('CAPPED')\n"
    )
    result = subprocess.run(  # noqa: S603
        ["python3", "-c", code],  # noqa: S607 — python3 resolved via PATH deliberately
        capture_output=True,
        text=True,
        timeout=30,
        preexec_fn=limit_child_memory,  # noqa: PLW1509 — trivial setrlimit only
    )
    assert result.stdout.strip() == "CAPPED"


def test_a_normal_small_allocation_is_unaffected() -> None:
    """The cap must not be so tight it breaks a normal, well-behaved tool."""
    code = "buf = bytearray(10_000_000)\nbuf[0] = 1\nprint('OK')\n"
    result = subprocess.run(  # noqa: S603
        ["python3", "-c", code],  # noqa: S607 — python3 resolved via PATH deliberately
        capture_output=True,
        text=True,
        timeout=30,
        preexec_fn=limit_child_memory,  # noqa: PLW1509 — trivial setrlimit only
    )
    assert result.stdout.strip() == "OK"


def test_cap_is_a_sane_multi_gigabyte_ceiling() -> None:
    # Generous enough for a Go binary's own upfront virtual-address-space
    # reservations (much larger than its real working set), but far below
    # what actually froze the host (4.48GB and climbing).
    assert 1_000_000_000 < MAX_TOOL_VIRTUAL_MEMORY_BYTES < 8_000_000_000


def test_go_memory_limit_env_is_set() -> None:
    # Harmless for every non-Go tool; directly targets the confirmed
    # culprit (katana) and the rest of the Go-based recon tier.
    assert GO_MEMORY_LIMIT_ENV.get("GOMEMLIMIT")
