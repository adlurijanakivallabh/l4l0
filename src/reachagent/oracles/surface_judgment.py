"""Evidence for the broad, surface-shape-only LLM review (v4 R1).

Every other STRUCTURAL/DIFFERENTIAL/etc. evidence dataclass carries a real,
already-fired request/response pair. This one doesn't — it backs the one
place in this codebase that reasons over the discovered surface *shape*
alone (paths/methods/params/sink types/app-domain/tech), the same way a
human pentester eyeballs an endpoint list before testing anything.

This used to be a dead end: v3's ``scan/llm_vuln_review.py`` produced this
exact same judgment but deliberately never let it reach ``run_oracle`` at
all, writing a permanently-unconfirmed ``SuspectedFinding`` instead (v4 R1
removed that tier). Routing through this evidence type instead means the
same "verdict construction confined to known files" AST invariant
(``tests/phase6/test_oracle_hardening.py``) still holds — ``judge()`` is
still the only place an ``OracleVerdict`` gets built, this only supplies
what it reasons over.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from reachagent.oracles.evidence import EvidenceMetadata

_MAX_CONTEXT_CHARS = 4000


@dataclass(frozen=True)
class SurfaceJudgmentEvidence:
    """One proposed lead's context, reasoned over with no fired request.

    ``surface_context`` is the same bounded surface digest the proposing
    call already saw — handing it to the confirming judgment call too, so
    the confirmation isn't reasoning over strictly less information than
    the proposal was.
    """

    vuln_class: str
    endpoint: str = ""
    location: str = ""
    reason: str = ""
    surface_context: str = ""
    evidence_ref: str = ""
    metadata: EvidenceMetadata = field(default_factory=EvidenceMetadata)

    def __post_init__(self) -> None:
        if len(self.surface_context) > _MAX_CONTEXT_CHARS:
            object.__setattr__(self, "surface_context", self.surface_context[:_MAX_CONTEXT_CHARS])
