"""Attack-path chaining (Build Order v2 W17).

When a confirmed auth-bypass (nosqli/ldap) yields REAL, reusable session material — not
just a 2xx status — this spawns a fresh synthetic Identity + Session and re-hunts under
it once, at the Phase-3→4 boundary, linking any new findings back to the confirming
finding. Bounded to exactly one re-hunt pass per scan (never a chain-of-chains): the
plan's explicit "bounded depth, no infinite re-hunt" line.

Reuses real, already-tested machinery end to end rather than inventing a parallel path:

  * ``identity.login._extract_session_material`` — the SAME response-parsing routine the
    real login flow uses to pull a token/cookies out of an HTTP response, so a captured
    auth-bypass credential is held to the identical "is this genuinely real session
    material" standard, not a heuristic guess. An auth-bypass that merely returned a 2xx
    with no session material grants nothing to chain into.
  * ``IdentityStore.add``/``open_session`` — the same real identity/session machinery
    every normal login uses, never a parallel mechanism.
  * ``RequestFirer.register_identity`` (v2 W17) — the new, additive post-construction
    registration seam that lets the derived identity actually authenticate through the
    SAME firer (rebuilding the firer would lose accumulated read-only clearance and the
    one-shot operator checkpoint state).
  * ``ReachabilityGraph.add_derived_credential``/``add_enables`` — the existing chain
    edges; ``chain_paths()`` already renders them in the report/GUI.

**Charter line (hard, CLAUDE.md §1)**: this reaches every WEB surface a chain unlocks and
proves each web vulnerability through the exact same oracle gate every other finding
uses — it never operates a shell, executes an arbitrary operator command, or performs
lateral/network movement. A benign command-injection PROOF (timing/OOB) still only
confirms a Finding; it is never turned into an interactive session.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass
from typing import Any

_log = logging.getLogger(__name__)

__all__ = [
    "DerivedIdentityLead",
    "capture_bypass_session",
    "spawn_derived_identity",
]


@dataclass(frozen=True)
class DerivedIdentityLead:
    """One confirmed finding whose auth-bypass probe carried real session material.

    Queued by a driver (``run_nosqli``/``run_ldap``) into a plain list the caller
    supplies, rather than acted on inline — the actual spawn + re-hunt happens once, at
    the Phase-3→4 boundary, from a single well-understood place (mirrors how ``events``
    is already threaded through every driver the same way).
    """

    finding_id: str
    vuln_class: str
    role_hint: str
    captured: object  # an identity.login.CapturedSession


def capture_bypass_session(result: object, body_text: str) -> object | None:
    """Extract real, reusable session material from a confirmed auth-bypass's raw HTTP
    response/body — the SAME parser ``identity.login``'s real login flow uses. Returns
    ``None`` (never raises) when nothing genuinely reusable was captured.
    """
    from reachagent.identity.login import _extract_session_material

    try:
        captured = _extract_session_material(result, body_text)
    except Exception as exc:  # noqa: BLE001 — a parse miss must not break the driver
        _log.debug("capture_bypass_session: extraction failed (%s)", exc)
        return None
    if not captured.token and not captured.cookies:
        return None
    return captured


def spawn_derived_identity(
    identities: Any,
    firer: Any,
    graph: Any,
    *,
    role_hint: str,
    captured: Any,
) -> tuple[str, str] | None:
    """Register a new synthetic Identity+Session from ``captured`` material on the
    IdentityStore, the live firer, AND the graph. Returns ``(identity_name,
    session_node_id)``, or ``None`` on any failure — a chaining failure must never abort
    the scan, so every error here is swallowed and logged, matching the same
    fail-open discipline every other advisory/steering mechanism in this codebase uses.
    """
    from reachagent.graph.nodes import AuthState, Provenance
    from reachagent.identity.store import Credential, IdentityStore

    if not isinstance(identities, IdentityStore):
        return None
    name = f"derived-{role_hint}-{uuid.uuid4().hex[:8]}"
    try:
        identity_obj = identities.add(
            Credential(
                identity=name,
                username=name,
                password="",
                role=role_hint,
                auth_state=AuthState.SYNTHETIC,
            ),
            provenance=Provenance.DERIVED,
        )
        graph.add_identity(name, identity_obj)
        material = captured.material()
        session = identities.open_session(
            name,
            material.token or "",
            kind=material.kind,
            cookies=dict(material.cookies),
            expires_at=material.expires_at,
            refresh_token=material.refresh_token,
            refresh_url=material.refresh_url,
            token_type=material.token_type,
        )
        session_node = graph.add_session(session)
        firer.register_identity(name, identities.token_store(name))
    except Exception as exc:  # noqa: BLE001 — a spawn failure must not abort the scan
        _log.warning("spawn_derived_identity failed for role_hint=%r: %s", role_hint, exc)
        return None
    return name, session_node
