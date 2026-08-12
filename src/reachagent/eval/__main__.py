"""Consolidated Phase 7 gate runner — ``python -m reachagent.eval``.

Runs ALL target gates (VAmPI, crAPI, Juice Shop, PortSwigger, DVGA) and prints
one composite report + verdict + exit code. Each gate is env-gated: a target that
is not provisioned reports SKIPPED and never blocks the composite. Exit codes:
0 = all ran gates passed, 1 = any ran gate failed, 2 = not measurable / nothing
ran.

    REACHAGENT_VAMPI_ON=http://127.0.0.1:5000 \\
    REACHAGENT_VAMPI_OFF=http://127.0.0.1:5002 \\
    REACHAGENT_JUICESHOP_EPHEMERAL=1 \\
    python -m reachagent.eval                 # all gates
    python -m reachagent.eval --target vamp    # just VAmPI
    python -m reachagent.eval --target portswigger dvga

The existing ``harness.evaluate`` VAmPI-only path stays importable for direct use.
"""

from __future__ import annotations

import argparse
import sys

from reachagent.eval.consolidated import run_consolidated


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="reachagent-eval",
        description="Consolidated Phase 7 gate runner (all targets, composite verdict).",
    )
    p.add_argument(
        "--target",
        nargs="*",
        default=None,
        help="Gate(s) to run; default runs all (vamp, crapi, juiceshop, portswigger, dvga)",
    )
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    result = run_consolidated(targets=args.target)
    print(result.report())
    return result.exit_code


if __name__ == "__main__":
    sys.exit(main())
