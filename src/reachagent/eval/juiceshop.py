"""Run the Juice Shop Phase 3 gate from the CLI: ``python -m reachagent.eval.juiceshop``.

Points at a running Juice Shop instance, drives the four in-scope detection
classes (injection, XSS, file upload, path traversal) through the MCP tool
boundary, scores coverage and false-positive rate against the challenge tracker
(``GET /api/Challenges``), folds in the PortSwigger blind-SQLi invariant when lab
credentials are provisioned, prints the report, and exits non-zero if the
§14/§15 gate fails so CI can consume it:

    REACHAGENT_JUICESHOP_URL=http://127.0.0.1:3000 \\
    python -m reachagent.eval.juiceshop

PortSwigger invariant (3) is SKIPPED unless both
``REACHAGENT_PORTSWIGGER_LAB_URL`` and ``REACHAGENT_PORTSWIGGER_SESSION_TOKEN``
are set; it never blocks invariants 1 and 2 until credentials exist.
"""

from __future__ import annotations

import os
import sys

from reachagent.eval.juiceshop_harness import Phase3GateResult
from reachagent.eval.juiceshop_live import JuiceshopTarget, run_juiceshop

_ENV_URL = "REACHAGENT_JUICESHOP_URL"
_DEFAULT_URL = "http://127.0.0.1:3000"


def main() -> int:
    url = os.environ.get(_ENV_URL, _DEFAULT_URL)
    target = JuiceshopTarget(base_url=url)
    run = run_juiceshop(target)
    gate = Phase3GateResult(juiceshop=run)
    print(gate.report())
    return 0 if gate.passed else 1


if __name__ == "__main__":
    sys.exit(main())
