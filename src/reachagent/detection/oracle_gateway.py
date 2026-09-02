"""Oracle gateway — injectable seam between detectors and the confirmation judgment (§7).

Detectors must never import ``reachagent.tools.validator`` directly (CLAUDE.md
non-negotiable: only the Validator role calls ``run_oracle``). In a live gate run
the detector reaches the judgment through the MCP tool boundary. In unit tests and
in-process callers the detector uses :func:`registry_runner`, which dispatches
straight to :func:`reachagent.oracles.llm_judgment.judge` (v3 decision — CLAUDE.md)
— no validator import, no verdict forgery possible.

The seam is a single callable type alias: ``OracleRunner``. Each prober dataclass
holds one as an optional field (default :func:`registry_runner`). The live gate
swaps in an MCP-backed runner; tests keep the default.
"""

from __future__ import annotations

from typing import Protocol

from reachagent.oracles import OracleMechanism
from reachagent.oracles.base import OracleVerdict
from reachagent.oracles.llm_judgment import judge


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

    @property
    def reason(self) -> str:
        """Stable, deterministic explanation supplied by the oracle."""
        return self._verdict.reason

    @property
    def evidence_metadata(self) -> dict[str, object]:
        """Safe bounded evidence projection; raw bodies remain server-side."""
        return self._verdict.evidence_metadata.as_dict()


class OracleRunner(Protocol):
    """Callable contract: (mechanism, evidence) -> OracleOutcome."""

    def __call__(self, mechanism: OracleMechanism, evidence: object) -> OracleOutcome: ...


def registry_runner(mechanism: OracleMechanism, evidence: object) -> OracleOutcome:
    """Default runner: dispatches to the LLM confirmation judgment (no validator import).

    Used by unit tests and any in-process caller that does not need the MCP
    boundary. Fail-closed: any judgment failure (no provider, parse error) comes
    back inconclusive, never a fabricated violation.
    """
    verdict = judge(mechanism, evidence)
    return OracleOutcome(verdict)
