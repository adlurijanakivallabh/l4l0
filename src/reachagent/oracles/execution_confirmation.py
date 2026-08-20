"""Execution-confirmation oracle — XSS (reflected/stored/DOM) (§7, Phase 3 Task 6).

Confirms code-execution-class findings deterministically via two paths:

  * **DOM XSS**: the taint shim recorded ≥1 source→sink flow (``flows`` non-empty).
    A flow means the shim's sink hook fired with a tainted value — execution
    confirmation without HTTP response parsing.

  * **Reflected/stored XSS**: a unique ``payload_tag`` appears verbatim in
    ``response_body``. The tag is embedded in the injected payload; its presence
    unencoded in the response proves the server reflected the payload without
    output encoding — the defining XSS confirmation.

Both paths are deterministic: no LLM, no fuzzy matching, no heuristics.
Same evidence in, same verdict out, every time.
"""

from __future__ import annotations

from dataclasses import dataclass

from reachagent.browser.shim import TaintFlow
from reachagent.graph.nodes import FindingStatus
from reachagent.oracles import OracleMechanism
from reachagent.oracles.base import Oracle, OracleVerdict


@dataclass(frozen=True)
class ExecutionConfirmationEvidence:
    """Evidence for the execution-confirmation oracle.

    Supply ``flows`` (DOM XSS path) or ``payload_tag`` + ``response_body``
    (reflected/stored XSS path). Both may be supplied; the oracle confirms on
    either signal. Neither yields INCONCLUSIVE.

    ``executed`` (additive, default False) is True when the browser actually
    *executed* injected JS — the taint shim's ``onerror`` marker fired
    (``window.__reachagent_exec = 1``), observable proof beyond a mere sink-
    reached flow. A flow alone is a *candidate* (tainted value reached a sink,
    possibly inert); a flow + marker is *executed*. The marker never replaces
    flows — it strengthens them.

    ``evidence_ref``: short, secret-free provenance handle (§13).
    """

    flows: tuple[TaintFlow, ...] = ()
    executed: bool = False
    payload_tag: str = ""
    response_body: str = ""
    expected_output: str = ""
    template_expression: str = ""
    evidence_ref: str = ""


def decide(evidence: ExecutionConfirmationEvidence) -> FindingStatus:
    """Map execution-confirmation evidence to one verdict — the whole decision (§7).

    Three DOM states, honestly distinguished:

    * **candidate** — ``flows`` non-empty, ``executed`` False: a tainted value
      reached a hooked sink (innerHTML/…), but nothing proves a script ran. Still
      a CONFIRMED_VIOLATION (the existing flows-are-execution contract holds — the
      marker is a strengthening, never a replacement).
    * **executed** — ``flows`` non-empty AND ``executed`` True: the injected
      payload's ``onerror`` marker fired, proving real execution. CONFIRMED_VIOLATION.
    * **no signal** — empty ``flows`` and ``executed`` False: INCONCLUSIVE.

    ``executed`` alone (no flows) also confirms — the marker firing is itself
    observable execution, even if no sink hook happened to record the flow.

    HTTP path: payload_tag non-empty and present verbatim in response_body → CONFIRMED_VIOLATION.
    Neither signal present → INCONCLUSIVE.
    """
    if evidence.flows or evidence.executed:
        return FindingStatus.CONFIRMED_VIOLATION
    if evidence.expected_output and evidence.expected_output in evidence.response_body:
        return FindingStatus.CONFIRMED_VIOLATION
    if evidence.payload_tag and evidence.payload_tag in evidence.response_body:
        return FindingStatus.CONFIRMED_VIOLATION
    return FindingStatus.INCONCLUSIVE


class ExecutionConfirmationOracle(Oracle):
    """Confirms XSS (reflected/stored/DOM) — one of the six §7 families."""

    mechanism = OracleMechanism.EXECUTION_CONFIRMATION

    def run(self, evidence: object) -> OracleVerdict:
        """Return the deterministic verdict for ``evidence``.

        ``evidence`` must be :class:`ExecutionConfirmationEvidence`. Raises
        ``TypeError`` on wrong type — a mis-wired caller is a bug, not an
        inconclusive result (mirrors the differential oracle).
        """
        if not isinstance(evidence, ExecutionConfirmationEvidence):
            raise TypeError(
                f"ExecutionConfirmationOracle needs ExecutionConfirmationEvidence, "
                f"got {type(evidence).__name__}"
            )
        status = decide(evidence)
        return OracleVerdict(
            mechanism=self.mechanism,
            status=status,
            evidence_ref=evidence.evidence_ref,
        )
