"""Oracle gateway — injectable seam between detectors and the oracle registry (§7).

Detectors must never import ``reachagent.tools.validator`` directly (CLAUDE.md
non-negotiable: only the Validator role calls ``run_oracle``). In a live gate run
the detector reaches the oracle through the MCP tool boundary. In unit tests and
in-process callers the detector uses :func:`registry_runner`, which dispatches
straight through the oracle registry — same deterministic families, no validator
import, no verdict forgery possible.

The seam is a single callable type alias: ``OracleRunner``. Each prober dataclass
holds one as an optional field (default :func:`registry_runner`). The live gate
swaps in an MCP-backed runner; tests keep the default.
"""

from __future__ import annotations

from typing import Protocol

from reachagent.oracles import OracleMechanism
from reachagent.oracles.base import OracleVerdict
from reachagent.oracles.registry import get_oracle


class OracleOutcome:
    """Thin wrapper so detectors don't import OracleVerdict directly."""

    def __init__(self, verdict: OracleVerdict) -> None:
        self._verdict = verdict

    @property
    def is_violation(self) -> bool:
        return self._verdict.is_violation

    @property
    def confirmed(self) -> bool:
        return self._verdict.confirmed

    @property
    def status(self) -> str:
        return self._verdict.status.value


class OracleRunner(Protocol):
    """Callable contract: (mechanism, evidence) -> OracleOutcome."""

    def __call__(self, mechanism: OracleMechanism, evidence: object) -> OracleOutcome: ...


def registry_runner(mechanism: OracleMechanism, evidence: object) -> OracleOutcome:
    """Default runner: dispatches through the oracle registry (no validator import).

    Used by unit tests and any in-process caller that does not need the MCP
    boundary. Deterministic — same evidence in, same outcome out, every time.
    """
    oracle = get_oracle(mechanism)
    verdict = oracle.run(evidence)
    return OracleOutcome(verdict)
