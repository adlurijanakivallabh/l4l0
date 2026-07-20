"""Run the VAmPI Phase 1 gate from the CLI: ``python -m reachagent.eval``.

Points at two running VAmPI instances — one with ``vulnerable=1`` (ON) and one
with ``vulnerable=0`` (OFF) — drives the identical MCP-tool pipeline against both,
prints the measured report, and exits non-zero if the §14/§15 gate fails so CI
can consume it. URLs come from the environment so the same command works against
local containers or a remote lab:

    REACHAGENT_VAMPI_ON=http://127.0.0.1:5000 \\
    REACHAGENT_VAMPI_OFF=http://127.0.0.1:5002 \\
    python -m reachagent.eval
"""

from __future__ import annotations

import os
import sys

from reachagent.eval.harness import evaluate

_ENV_ON = "REACHAGENT_VAMPI_ON"
_ENV_OFF = "REACHAGENT_VAMPI_OFF"
_DEFAULT_ON = "http://127.0.0.1:5000"
_DEFAULT_OFF = "http://127.0.0.1:5002"


def main() -> int:
    on_url = os.environ.get(_ENV_ON, _DEFAULT_ON)
    off_url = os.environ.get(_ENV_OFF, _DEFAULT_OFF)
    result = evaluate(on_base_url=on_url, off_base_url=off_url)
    print(result.report())
    return 0 if result.passed else 1


if __name__ == "__main__":
    sys.exit(main())
