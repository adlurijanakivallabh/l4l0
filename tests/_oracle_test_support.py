"""Shared fakes for the v3 LLM-judgment oracle model (CLAUDE.md).

The six families' deterministic ``decide()`` functions are gone — confirmation is
now an LLM judgment (``oracles/llm_judgment.py``), which needs a real provider.
Tests need a deterministic stand-in so they can assert a specific
``FindingStatus`` without a live LLM call. Two shapes, matching the two ways a
verdict gets reached in this codebase:

- Most individual detectors (``pathtraversal/detector.py``, ``bola/detector.py``,
  etc.) hold an injectable ``oracle_runner: OracleRunner`` field on their Prober
  dataclass, defaulting to ``detection.oracle_gateway.registry_runner``. Inject
  :func:`fixed_oracle_runner` there to assert on detector WIRING (does it
  correctly relay a given verdict into ``.confirmed``/a written Finding) without
  depending on what a real LLM would decide.
- Anything calling ``tools.validator.run_oracle`` directly can inject
  :class:`FixedJudgmentClient` via its ``client=`` kwarg — the SAME kwarg
  production code would use to plug in a real configured client.

Neither fake tests the LLM's judgment itself (nothing can, deterministically —
that's the whole point of the v3 decision); both let a test fix the ONE
variable it actually wants to hold constant while asserting everything around
it still works.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from reachagent.detection.oracle_gateway import OracleOutcome
from reachagent.graph.nodes import FindingStatus
from reachagent.oracles.base import OracleVerdict

if TYPE_CHECKING:
    from reachagent.oracles import OracleMechanism


def fixed_oracle_runner(status: FindingStatus, *, reason: str = "test-fixed-verdict"):
    """An ``OracleRunner`` that always returns ``status``, whatever evidence it's given.

    Use in place of a Prober's default ``oracle_runner=registry_runner`` when a
    test wants to assert what happens GIVEN a verdict, not to re-derive the
    verdict itself (that's now an LLM's job, not something a hermetic test can
    pin down deterministically).
    """

    def _runner(mechanism: OracleMechanism, evidence: object) -> OracleOutcome:
        ref = str(getattr(evidence, "evidence_ref", "") or "")
        verdict = OracleVerdict(mechanism=mechanism, status=status, evidence_ref=ref, reason=reason)
        return OracleOutcome(verdict)

    return _runner


class FixedJudgmentClient:
    """A fake LLM client (``propose_json``) that always returns a fixed status/reason.

    Inject via ``tools.validator.run_oracle(mechanism, evidence, client=FixedJudgmentClient(...))``
    — the same injection seam production code uses for a real configured client.
    """

    def __init__(self, status: str, *, reason: str = "test-fixed-verdict") -> None:
        self.status = status
        self.reason = reason

    def propose_json(self, prompt: str, *, max_tokens: int = 500) -> dict[str, object]:
        return {"status": self.status, "reason": self.reason}


# Convenience constants — the two outcomes almost every test actually wants.
CONFIRMS = FindingStatus.CONFIRMED_VIOLATION
DENIES = FindingStatus.CONFIRMED_DENIED
ALLOWS = FindingStatus.CONFIRMED_ALLOWED
INCONCLUSIVE = FindingStatus.INCONCLUSIVE
