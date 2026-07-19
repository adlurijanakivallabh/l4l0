"""Oracle base contract (plan §7).

Every oracle mechanism maps to one of the six families in §7 (CLAUDE.md). An
oracle takes evidence and returns a deterministic, non-LLM verdict — exactly one
of the four :class:`~reachagent.graph.nodes.FindingStatus` values. A
``confirmed`` verdict is the only thing that unlocks ``write_finding`` (§13), and
:class:`OracleVerdict` is the *sole* type in the codebase that carries such a
verdict: nothing outside an :class:`Oracle` run constructs one, which is what
makes "only a Validator-run deterministic check produces a Finding" enforceable
in code (§7, §13).
"""

from __future__ import annotations

from dataclasses import dataclass

from reachagent.graph.nodes import FindingStatus
from reachagent.oracles import OracleMechanism

# The deterministic verdicts that count as "confirmed" — anything a scripted
# oracle could positively decide. INCONCLUSIVE is the only non-confirmed status.
_CONFIRMED_STATUSES = frozenset(
    {
        FindingStatus.CONFIRMED_ALLOWED,
        FindingStatus.CONFIRMED_DENIED,
        FindingStatus.CONFIRMED_VIOLATION,
    }
)


@dataclass(frozen=True)
class OracleVerdict:
    """Result of a deterministic oracle run (§7).

    ``status`` is one of the four ``FindingStatus`` values, decided by scripted
    logic — never an LLM judgment. Frozen so a verdict handed back from
    ``run_oracle`` can't be mutated into a different outcome after the fact.
    """

    mechanism: OracleMechanism
    status: FindingStatus
    evidence_ref: str

    @property
    def confirmed(self) -> bool:
        """Whether the oracle reached a deterministic verdict (not inconclusive)."""
        return self.status in _CONFIRMED_STATUSES

    @property
    def is_violation(self) -> bool:
        """Whether the verdict is specifically a confirmed authorization violation.

        This — and only this — is what unlocks ``write_finding`` (§13). A
        ``confirmed_allowed``/``confirmed_denied`` verdict is a confirmed *fact*
        about a ``can_call`` edge (§6), not a finding.
        """
        return self.status is FindingStatus.CONFIRMED_VIOLATION


class Oracle:
    """Base for the six deterministic verification families (§7)."""

    mechanism: OracleMechanism

    def run(self, evidence: object) -> OracleVerdict:
        """Return a deterministic verdict. Implemented per family in §15 phases."""
        raise NotImplementedError
