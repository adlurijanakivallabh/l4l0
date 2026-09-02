"""Oracle base contract (plan §7; v3 architecture decision — CLAUDE.md).

The six evidence families in §7 remain the vocabulary for what real evidence a
verdict is built from. A ``confirmed`` verdict is still the only thing that
unlocks ``write_finding`` (§13), and :class:`OracleVerdict` is still the *sole*
type in the codebase that carries one — but per the operator's explicit,
final v3 decision, the verdict is now reached via LLM judgment over real,
already-fired evidence (``oracles/llm_judgment.py``) rather than a fixed
per-mechanism ``decide()`` function. What's unchanged: nothing outside that
judgment path constructs an ``OracleVerdict``, which is what keeps "only the
Validator's confirmation path produces a Finding" enforceable in code (§13).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from reachagent.graph.nodes import FindingStatus
from reachagent.oracles import OracleMechanism
from reachagent.oracles.evidence import (
    EvidenceMetadata,
    validate_evidence_metadata,
    validate_evidence_ref,
    validate_reason,
)

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
    """Result of a confirmation judgment over real evidence (§7).

    ``status`` is one of the four ``FindingStatus`` values, decided by
    ``oracles/llm_judgment.py`` reasoning over real, already-fired
    request/response evidence (v3 decision — CLAUDE.md). Frozen so a verdict
    handed back from ``run_oracle`` can't be mutated into a different outcome
    after the fact.
    """

    mechanism: OracleMechanism
    status: FindingStatus
    evidence_ref: str
    reason: str = ""
    evidence_metadata: EvidenceMetadata = field(default_factory=EvidenceMetadata)

    def __post_init__(self) -> None:
        """Keep provenance and explanations bounded and secret-free.

        The status is still selected by a concrete oracle before this object is
        created.  These checks only protect the evidence boundary; they never
        change a verdict.
        """
        validate_evidence_ref(self.evidence_ref)
        validate_reason(self.reason)
        validate_evidence_metadata(self.evidence_metadata)

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


def decision_reason(
    mechanism: OracleMechanism,
    status: FindingStatus,
    detail: str = "",
) -> str:
    """Return a stable, secret-free explanation for an oracle status."""
    family = mechanism.value
    if status is FindingStatus.CONFIRMED_VIOLATION:
        outcome = "confirmed_violation"
        default_detail = "security_invariant_broken"
    elif status is FindingStatus.CONFIRMED_ALLOWED:
        outcome = "confirmed_allowed"
        default_detail = "expected_access_observed"
    elif status is FindingStatus.CONFIRMED_DENIED:
        outcome = "confirmed_denied"
        default_detail = "security_invariant_held"
    else:
        outcome = "inconclusive"
        default_detail = "deterministic_signal_absent"
    safe_detail = validate_reason(str(detail)[:200], field="reason_detail")
    return f"{family}:{outcome}:{safe_detail or default_detail}"


class Oracle:
    """Base for the six evidence families (§7).

    Retained as evidence-shape vocabulary (v3 decision — CLAUDE.md); the live
    judgment path is ``oracles/llm_judgment.py``, not a subclass's ``run()``.
    """

    mechanism: OracleMechanism

    def run(self, evidence: object) -> OracleVerdict:
        """Return a verdict. Legacy per-family entry point — see class docstring."""
        raise NotImplementedError
