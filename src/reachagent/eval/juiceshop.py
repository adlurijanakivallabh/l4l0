"""Run Juice Shop Phase 3 gate against persistent or fresh target.

Default mode uses ``REACHAGENT_JUICESHOP_URL``. Fresh mode is explicit:

    REACHAGENT_JUICESHOP_EPHEMERAL=1 uv run python -m reachagent.eval.juiceshop --fresh

Fresh mode starts pinned image, validates clean tracker baseline, runs normal MCP
pipeline, and always removes container. Dirty or invalid targets report
``NOT MEASURABLE`` instead of fake zero coverage.
"""

from __future__ import annotations

import argparse
import os
import sys

from reachagent.eval.juiceshop_ephemeral import (
    EphemeralJuiceshopError,
    run_ephemeral_gate,
)
from reachagent.eval.juiceshop_harness import JuiceshopRun, Phase3GateResult
from reachagent.eval.juiceshop_live import JuiceshopTarget, TrackerSnapshotError, run_juiceshop

_ENV_URL = "REACHAGENT_JUICESHOP_URL"
_DEFAULT_URL = "http://127.0.0.1:3000"


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run Juice Shop Phase 3 gate")
    parser.add_argument(
        "--fresh",
        action="store_true",
        help="start pinned disposable container (requires explicit opt-in)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.fresh:
        try:
            gate = run_ephemeral_gate()
        except EphemeralJuiceshopError as exc:
            print(f"NOT MEASURABLE: {exc}")
            return 2
    else:
        url = os.environ.get(_ENV_URL, _DEFAULT_URL)
        try:
            run = run_juiceshop(JuiceshopTarget(base_url=url))
        except TrackerSnapshotError as exc:
            gate = Phase3GateResult(
                juiceshop=JuiceshopRun.not_measurable(baseline=None, detail=str(exc)),
                setup_failures=1,
                setup_failure_details=[str(exc)],
            )
        else:
            gate = Phase3GateResult(juiceshop=run)
    print(gate.report())
    if not gate.environment_ok:
        return 2
    return 0 if gate.passed else 1


if __name__ == "__main__":
    sys.exit(main())
