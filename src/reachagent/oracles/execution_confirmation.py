"""Execution-confirmation evidence shapes — XSS (reflected/stored/DOM) (§7, Phase 3 Task 6).

v3 architecture decision (CLAUDE.md): the fixed ``decide()`` function that used
to map DOM taint-flow / execution-marker signals and reflected/stored payload-
tag reflection to exactly one deterministic verdict has been REMOVED. Live
confirmation judgment now happens in ``oracles/llm_judgment.py``, which
reasons over the same evidence objects instead of running a scripted decision
table. ``ExecutionConfirmationOracle`` is kept only as a registered-mechanism
marker (``oracles/registry.py`` and ``recon/tools/signal_gated.py`` still look
it up); it no longer computes a verdict itself — see
:class:`~reachagent.oracles.base.Oracle` for the inherited (raising) default
``run()``.

``ExecutionConfirmationEvidence`` remains in use as the evidence-shape
vocabulary for this family: DOM XSS evidence (``flows`` / ``executed``) and
reflected/stored XSS evidence (``payload_tag`` / ``response_body`` /
``expected_output`` / ``template_expression``) — ``llm_judgment.judge`` takes
the same object the old ``decide()`` did.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from reachagent.browser.shim import TaintFlow
from reachagent.oracles import OracleMechanism
from reachagent.oracles.base import Oracle
from reachagent.oracles.evidence import EvidenceMetadata


@dataclass(frozen=True)
class ExecutionConfirmationEvidence:
    """Evidence for the execution-confirmation oracle family.

    Supply ``flows`` (DOM XSS path) or ``payload_tag`` + ``response_body``
    (reflected/stored XSS path). Both may be supplied.

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
    metadata: EvidenceMetadata = field(default_factory=EvidenceMetadata)


class ExecutionConfirmationOracle(Oracle):
    """Registered-mechanism marker for the execution-confirmation family (§7).

    No longer computes a verdict itself (v3 decision — CLAUDE.md): the fixed
    ``decide()`` this class used to wrap is deleted, and live judgment happens
    in ``oracles/llm_judgment.py``. Kept as a class (rather than deleted
    outright) because ``oracles/registry.py`` still instantiates it and
    ``recon/tools/signal_gated.py`` still looks it up via
    ``OracleMechanism.EXECUTION_CONFIRMATION`` to validate a candidate's
    suggested mechanism — neither is part of this file's family and so is out
    of scope here. ``run()`` is inherited unchanged from :class:`Oracle`
    (raises ``NotImplementedError``); nothing in the live scan path calls it.
    """

    mechanism = OracleMechanism.EXECUTION_CONFIRMATION
