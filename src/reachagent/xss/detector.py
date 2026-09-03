"""XSS detection — DOM and stored paths (§7, §9; Phase 3 Task 6).

Two sub-cases, both using EXECUTION_CONFIRMATION oracle (no new family):

  1. **DOM XSS** — Explorer fires ``fire_browser`` with the taint shim; shim
     records source→sink flows; oracle confirms on non-empty flows.
     Read-only-first (§10): no state-changing request before the read-only
     browser probe confirms an injectable sink.

  2. **Stored XSS** — Explorer fires a write (POST/PUT) with a tagged payload,
     then a read-back (GET) to retrieve the stored value; oracle confirms when
     the tag appears verbatim in the read-back response body.
     Read-only-first (§10): the write fires only after a read-only canary probe
     confirms the field is injectable (reflected in a GET response).
     The write is logged as state-changing in the audit log.

Ordering: DOM probe first (no state change); stored path only when a write
endpoint is supplied. Returns at the first confirmation.

The detector contains only ordering logic and oracle dispatch — no I/O.
Tests supply in-memory fakes; the live path supplies firer-backed callbacks.

Optional technique-diversity corroboration (v3 V3): ``fire_second_stored_read``
lets the caller wire in a SECOND, independent read of the same stored
resource — ideally from a DIFFERENT identity/session than the one that wrote
it. A confirmed stored XSS is only trusted once that second read also shows
the tag, ruling out the payload being reflected only in a save-confirmation
view still scoped to the writer's own session/cache rather than genuinely
persisted and visible to another viewer. Optional and additive: when omitted
(the default), behavior is byte-for-byte unchanged from before this was added.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from dataclasses import dataclass

from reachagent.browser.shim import BrowserFireResult, TaintFlow
from reachagent.confirmation.corroboration import corroborate_with_variant
from reachagent.detection.oracle_gateway import OracleRunner, registry_runner
from reachagent.oracles import OracleMechanism
from reachagent.oracles.execution_confirmation import ExecutionConfirmationEvidence


@dataclass(frozen=True)
class DomProbe:
    """Result of a DOM XSS browser probe."""

    result: BrowserFireResult


@dataclass(frozen=True)
class StoredProbe:
    """Result of a stored XSS write→read-back probe pair."""

    payload_tag: str  # unique tag embedded in the written payload
    readback_body: str  # body of the GET read-back response
    write_logged: bool = False  # True iff the write was recorded in the audit log


@dataclass(frozen=True)
class XssResult:
    """Outcome of an XSS detection attempt.

    ``confirmed`` is true only if an oracle returned ``confirmed_violation``.
    ``xss_type`` is "dom", "stored", or None.
    ``flows`` carries the taint flows for DOM XSS (empty for stored).
    ``evidence_ref`` is the provenance handle recorded on the finding.
    """

    confirmed: bool
    xss_type: str | None
    flows: tuple[TaintFlow, ...] = ()
    evidence_ref: str = ""
    corroborated: bool = False


@dataclass
class XssProber:
    """Injectable probe callbacks — keeps detection hermetic and ordering testable.

    Tests supply in-memory fakes; the live detector supplies firer-backed
    implementations. The detector contains only ordering logic, no I/O.

    ``fire_dom``: navigate with the taint shim and return the BrowserFireResult.
    ``fire_stored``: write the tagged payload then read back; return StoredProbe.
      May be None when no write endpoint is available (DOM-only mode).
    ``fire_second_stored_read`` (v3 V3, optional): a second, independent read
    of the same stored resource — see module docstring.
    """

    fire_dom: Callable[[], DomProbe]
    fire_stored: Callable[[], StoredProbe] | None = None
    oracle_runner: OracleRunner = registry_runner
    fire_second_stored_read: Callable[[], str] | None = None


def _dom_confirms(prober: XssProber, evidence_ref: str) -> tuple[bool, tuple[TaintFlow, ...]]:
    """Attempt the DOM XSS path. Return (confirmed, flows)."""
    probe = prober.fire_dom()
    evidence = ExecutionConfirmationEvidence(
        flows=probe.result.flows,
        evidence_ref=evidence_ref,
    )
    verdict = prober.oracle_runner(OracleMechanism.EXECUTION_CONFIRMATION, evidence)
    return verdict.is_violation, probe.result.flows


def _stored_confirms(prober: XssProber, evidence_ref: str) -> tuple[bool, bool]:
    """Attempt the stored XSS path. Return (confirmed, corroborated).

    Caller guarantees ``fire_stored`` is set; guard defensively rather than
    assert (S101) so a mis-wired caller fails loudly, not silently. When
    ``prober.fire_second_stored_read`` is set, a confirmed first read is
    corroborated against a second, independent read (v3 V3) before being
    trusted — a contradicted corroboration fails closed to not-confirmed.
    """
    if prober.fire_stored is None:
        raise ValueError("stored XSS path requires a fire_stored callback")
    probe = prober.fire_stored()
    evidence = ExecutionConfirmationEvidence(
        payload_tag=probe.payload_tag,
        response_body=probe.readback_body,
        evidence_ref=evidence_ref,
    )
    verdict = prober.oracle_runner(OracleMechanism.EXECUTION_CONFIRMATION, evidence)
    if prober.fire_second_stored_read is None:
        return verdict.is_violation, False
    if not verdict.is_violation:
        return False, False

    def _second_attempt() -> object:
        second_body = prober.fire_second_stored_read()  # type: ignore[misc]
        second_evidence = ExecutionConfirmationEvidence(
            payload_tag=probe.payload_tag,
            response_body=second_body,
            evidence_ref=evidence_ref,
        )
        return prober.oracle_runner(OracleMechanism.EXECUTION_CONFIRMATION, second_evidence)

    result = corroborate_with_variant(verdict, _second_attempt)
    return result.corroborated, result.corroborated


def detect_xss(
    prober: XssProber,
    *,
    evidence_ref: str = "",
) -> XssResult:
    """Detect XSS — DOM probe first, stored path second (§7, §9).

    DOM is tried first: it is read-only (no state change) and uses the taint
    shim for direct execution confirmation. Stored is reached only when a
    write callback is supplied and DOM did not confirm.

    Returns at the first confirmation. ``evidence_ref`` is stamped on the
    oracle verdict and downstream finding for audit traceability (§13).
    """
    if not evidence_ref:
        evidence_ref = f"xss/{uuid.uuid4().hex[:8]}"

    # 1. DOM XSS — read-only, taint shim, no state change.
    confirmed, flows = _dom_confirms(prober, evidence_ref)
    if confirmed:
        return XssResult(
            confirmed=True,
            xss_type="dom",
            flows=flows,
            evidence_ref=evidence_ref,
        )

    # 2. Stored XSS — write→read-back, only when a write callback is supplied.
    if prober.fire_stored is not None:
        stored_confirmed, stored_corroborated = _stored_confirms(prober, evidence_ref)
        if stored_confirmed:
            return XssResult(
                confirmed=True,
                xss_type="stored",
                evidence_ref=evidence_ref,
                corroborated=stored_corroborated,
            )

    return XssResult(confirmed=False, xss_type=None, evidence_ref=evidence_ref)
