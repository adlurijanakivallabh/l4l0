"""LLM-based confirmation judgment (v3 architecture decision — see CLAUDE.md).

Replaces the deterministic oracle-registry lookup that used to live inside
``tools/validator.py::run_oracle`` (the operator's explicit, final decision after
extensive session-long discussion of the tradeoffs). Takes the SAME evidence
objects the six oracle families always used — ``StructuralEvidence``,
``DifferentialEvidence``, ``PairedTrialEvidence``, ``ExecutionConfirmationEvidence``,
``OOBCallbackEvidence``, ``BusinessRuleEvidence`` — real, already-fired
request/response data captured by the audited firer — and asks an LLM to judge
whether it proves a violation, instead of running a fixed ``decide()`` function
per mechanism.

This is now the path that constructs an ``OracleVerdict`` for a live judgment
(mirrors the old "verdict construction confined to the oracle modules"
discipline in ``tests/phase6/test_oracle_hardening.py`` — this file is added to
that allowed set, not exempted from it).

Fail-closed: any LLM/parsing failure returns ``INCONCLUSIVE``, never a
fabricated violation — an uncertain outcome must never masquerade as a
confirmed one just because the model call broke.
"""

from __future__ import annotations

import dataclasses
import json
import logging
from dataclasses import replace

from reachagent.graph.nodes import FindingStatus
from reachagent.llm.client import build_openai_compatible_client
from reachagent.oracles import OracleMechanism
from reachagent.oracles.base import OracleVerdict, decision_reason
from reachagent.oracles.evidence import (
    EvidenceMetadata,
    EvidenceValidationError,
    validate_evidence_metadata,
)

_log = logging.getLogger(__name__)

_MAX_EVIDENCE_CHARS = 4000
_VALID_STATUSES = frozenset(status.value for status in FindingStatus)

_JUDGMENT_PROMPT = (
    "You are the confirmation judge for an authorized security assessment. "
    "You are shown REAL evidence already captured from a live, already-fired "
    "HTTP request/response — never invent a fact not present below. Decide "
    "whether this evidence proves a genuine violation.\n\n"
    "Mechanism family: {mechanism}\n"
    "Evidence (JSON, from a real fired request/response):\n{evidence_json}\n\n"
    'Reply ONLY as JSON: {{"status": "confirmed_violation|confirmed_denied|'
    'confirmed_allowed|inconclusive", "reason": "one short sentence citing '
    'the SPECIFIC evidence field that convinced you"}}. Use inconclusive '
    "whenever the evidence doesn't clearly and specifically prove the "
    "outcome — never guess."
)


def _evidence_to_json(evidence: object) -> str:
    """Bounded, best-effort JSON dump of any oracle evidence dataclass."""
    try:
        raw = (
            dataclasses.asdict(evidence)
            if dataclasses.is_dataclass(evidence)
            else {"repr": repr(evidence)}
        )
    except Exception:  # noqa: BLE001 — degrade to repr rather than crash the judgment
        raw = {"repr": repr(evidence)}
    return json.dumps(raw, default=str, sort_keys=True)[:_MAX_EVIDENCE_CHARS]


def _evidence_ref(evidence: object) -> str:
    return str(getattr(evidence, "evidence_ref", "") or "")


def _enrich_metadata(mechanism: OracleMechanism, evidence: object) -> EvidenceMetadata:
    """Auto-fill evidence_metadata from the evidence's own fields, per mechanism.

    Relocated verbatim from each legacy oracle's ``run()`` (removed alongside
    ``decide()`` — this enrichment was always independent logic, not part of
    the fixed decision itself). Fails open on the metadata SNIPPET only: an
    accidental secret-like match in a real target's response must never block
    a judgment from being reached, only drop the enrichment attempt.
    """
    metadata = validate_evidence_metadata(getattr(evidence, "metadata", None) or EvidenceMetadata())

    if mechanism is OracleMechanism.STRUCTURAL:
        from reachagent.oracles.structural import StructuralEvidence, _body_projection

        if isinstance(evidence, StructuralEvidence):
            if not metadata.headers:
                headers = tuple(
                    (name, value)
                    for name, value in (
                        ("x-frame-options", evidence.x_frame_options),
                        ("content-security-policy", evidence.csp),
                        ("access-control-allow-origin", evidence.acao),
                        ("access-control-allow-credentials", evidence.acac),
                        ("location", evidence.location),
                    )
                    if value
                )
                if headers:
                    try:
                        metadata = replace(metadata, headers=headers).validated()
                    except EvidenceValidationError:
                        pass
            if not metadata.body_projection:
                projection = _body_projection(evidence)
                if projection:
                    try:
                        metadata = replace(metadata, body_projection=projection).validated()
                    except EvidenceValidationError:
                        pass

    elif mechanism is OracleMechanism.TIMING_STATISTICAL:
        from reachagent.oracles.timing_statistical import PairedTrialEvidence

        if isinstance(evidence, PairedTrialEvidence) and not metadata.timing_samples_ms:
            try:
                metadata = replace(
                    metadata,
                    timing_samples_ms=(
                        tuple(evidence.baseline_latencies_ms[:1000])
                        + tuple(evidence.probe_latencies_ms[:1000])
                    ),
                ).validated()
            except EvidenceValidationError:
                pass

    elif mechanism is OracleMechanism.OOB_CALLBACK:
        from reachagent.oracles.oob_callback import OOBCallbackEvidence

        if (
            isinstance(evidence, OOBCallbackEvidence)
            and evidence.observed_channels
            and not metadata.oob_channels
        ):
            try:
                metadata = replace(
                    metadata, oob_channels=tuple(evidence.observed_channels)
                ).validated()
            except EvidenceValidationError:
                pass

    return metadata


def _inconclusive(
    mechanism: OracleMechanism,
    evidence_ref: str,
    detail: str,
    metadata: EvidenceMetadata | None = None,
) -> OracleVerdict:
    return OracleVerdict(
        mechanism=mechanism,
        status=FindingStatus.INCONCLUSIVE,
        evidence_ref=evidence_ref,
        reason=decision_reason(mechanism, FindingStatus.INCONCLUSIVE, detail),
        evidence_metadata=metadata or EvidenceMetadata(),
    )


def judge(
    mechanism: OracleMechanism,
    evidence: object,
    *,
    client: object | None = None,
) -> OracleVerdict:
    """Ask the LLM to judge real, already-captured evidence and return a verdict.

    ``client`` (any object exposing ``propose_json``) is injectable for tests,
    mirroring every other LLM seam in this codebase. Fail-closed throughout: no
    provider configured, a provider error, a malformed reply, or a status the
    model invents outside the four real ``FindingStatus`` values all map to
    ``INCONCLUSIVE`` — never a fabricated violation. Any ``metadata`` already on
    the evidence object (e.g. a captured body projection) carries through to the
    verdict unchanged, the same as the legacy oracles did — a caller-supplied
    projection is still what the report's evidence display renders.
    """
    evidence_ref = _evidence_ref(evidence)
    metadata = _enrich_metadata(mechanism, evidence)
    try:
        reviewer = client if client is not None else build_openai_compatible_client()
        if reviewer is None:
            return _inconclusive(mechanism, evidence_ref, "no_llm_provider_configured", metadata)
        raw = reviewer.propose_json(  # type: ignore[attr-defined]
            _JUDGMENT_PROMPT.format(
                mechanism=mechanism.value,
                evidence_json=_evidence_to_json(evidence),
            ),
            max_tokens=500,
        )
    except Exception as exc:  # noqa: BLE001 — a judgment failure must never crash the scan
        _log.warning("LLM confirmation judgment failed (%s); returning inconclusive", exc)
        return _inconclusive(mechanism, evidence_ref, "judgment_call_failed", metadata)

    status_raw = str(raw.get("status", "")).strip().lower() if isinstance(raw, dict) else ""
    if status_raw not in _VALID_STATUSES:
        return _inconclusive(mechanism, evidence_ref, "malformed_judgment_reply", metadata)
    status = FindingStatus(status_raw)
    detail = str(raw.get("reason", "")).strip()[:200] if isinstance(raw, dict) else ""
    return OracleVerdict(
        mechanism=mechanism,
        status=status,
        evidence_ref=evidence_ref,
        reason=decision_reason(mechanism, status, detail),
        evidence_metadata=metadata,
    )
