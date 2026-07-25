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
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from dataclasses import dataclass

from reachagent.browser.shim import BrowserFireResult, TaintFlow
from reachagent.oracles import OracleMechanism
from reachagent.oracles.execution_confirmation import ExecutionConfirmationEvidence
from reachagent.tools.validator import run_oracle


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


@dataclass
class XssProber:
    """Injectable probe callbacks — keeps detection hermetic and ordering testable.

    Tests supply in-memory fakes; the live detector supplies firer-backed
    implementations. The detector contains only ordering logic, no I/O.

    ``fire_dom``: navigate with the taint shim and return the BrowserFireResult.
    ``fire_stored``: write the tagged payload then read back; return StoredProbe.
      May be None when no write endpoint is available (DOM-only mode).
    """

    fire_dom: Callable[[], DomProbe]
    fire_stored: Callable[[], StoredProbe] | None = None


def _dom_confirms(prober: XssProber, evidence_ref: str) -> tuple[bool, tuple[TaintFlow, ...]]:
    """Attempt the DOM XSS path. Return (confirmed, flows)."""
    probe = prober.fire_dom()
    evidence = ExecutionConfirmationEvidence(
        flows=probe.result.flows,
        evidence_ref=evidence_ref,
    )
    verdict = run_oracle(OracleMechanism.EXECUTION_CONFIRMATION, evidence)
    return verdict.is_violation, probe.result.flows


def _stored_confirms(prober: XssProber, evidence_ref: str) -> bool:
    """Attempt the stored XSS path. Return whether it confirmed.

    Caller guarantees ``fire_stored`` is set; guard defensively rather than
    assert (S101) so a mis-wired caller fails loudly, not silently.
    """
    if prober.fire_stored is None:
        raise ValueError("stored XSS path requires a fire_stored callback")
    probe = prober.fire_stored()
    evidence = ExecutionConfirmationEvidence(
        payload_tag=probe.payload_tag,
        response_body=probe.readback_body,
        evidence_ref=evidence_ref,
    )
    verdict = run_oracle(OracleMechanism.EXECUTION_CONFIRMATION, evidence)
    return verdict.is_violation


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
        if _stored_confirms(prober, evidence_ref):
            return XssResult(
                confirmed=True,
                xss_type="stored",
                evidence_ref=evidence_ref,
            )

    return XssResult(confirmed=False, xss_type=None, evidence_ref=evidence_ref)
