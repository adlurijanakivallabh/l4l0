"""crAPI recon runner (plan §3, §6, §10, §14; Phase 2 Task 6).

Drives the Task 2–extended :class:`~reachagent.recon.mapper.SurfaceMapper` against
a live crAPI instance to build the structural + ownership layer of the graph for
the two documented multi-step BOLA flows (vehicle-location, mechanic-contact).

The split mirrors the Phase 1 eval harness (Task 9), and it is load-bearing for
the §10 safety story:

  * **Onboarding is authorized setup, done directly over HTTP** — logging each
    seeded identity in and storing the resulting bearer token in that identity's
    isolated :class:`TokenStore`. crAPI creates the vehicle↔user association
    during onboarding, so this is the "after which workflow step" the ownership
    recipe waits on. Setup is target manipulation, never part of recon detection.
  * **Recon runs entirely through the mapper** — structure materialization,
    empirical ``can_call`` probes, and ownership discovery, all fired through
    Task 1's :class:`RequestFirer` under scope + read-only-first. Recon never
    fires a state-changing crAPI endpoint, so the run logs zero destructive side
    effects (§10) — the precondition for the Task 7 gate's second clause.

Credentials are never hardcoded (§10): identities load from the environment or a
local secrets file, exactly as in Phase 1.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

import httpx

from reachagent.execution.audit import AuditEntry, AuditLog
from reachagent.execution.firer import RequestFirer
from reachagent.execution.scope import ScopeGuard
from reachagent.graph.store import ReachabilityGraph
from reachagent.identity.store import IdentityStore
from reachagent.recon.mapper import MapSummary, SurfaceMapper, SurfaceSpec

_ENV_BASE_URL = "REACHAGENT_CRAPI_BASE_URL"
_DEFAULT_BASE_URL = "http://127.0.0.1:8888"
_ENV_IDENTITIES_FILE = "REACHAGENT_CRAPI_IDENTITIES_FILE"

_LOGIN_PATH = "/identity/api/auth/login"
_HTTP_TIMEOUT = 10.0

# Default surface inventory shipped with the package (the two BOLA flows, §14).
_DEFAULT_SURFACE = Path(__file__).resolve().parents[3] / "config" / "crapi-surface.yaml"


@dataclass(frozen=True)
class ReconResult:
    """Outcome of a crAPI recon run — the mapper summary plus safety evidence."""

    summary: MapSummary
    onboarded: tuple[str, ...]
    # Every audit entry, so a caller (and the Task 6 test) can assert that no
    # state-changing request was ever fired by recon (§10).
    audit: tuple[AuditEntry, ...]

    @property
    def destructive_actions(self) -> tuple[AuditEntry, ...]:
        """Audit entries that fired a state-changing request — must be empty (§10).

        A recon run is read-only-first: the only ``fired:`` entries should be the
        read-only probes and reveals. Any fired non-read-only method is a
        destructive side effect the gate forbids.
        """
        return tuple(
            e
            for e in self.audit
            if e.outcome.startswith("fired:") and e.method not in ("GET", "HEAD", "OPTIONS")
        )


def _load_identities() -> IdentityStore:
    """Seed identities from a local secrets file or the environment (§10)."""
    path = os.environ.get(_ENV_IDENTITIES_FILE)
    if path:
        return IdentityStore.from_secrets_file(path)
    return IdentityStore.from_env()


def _onboard(
    identities: IdentityStore, base_url: str, *, client: httpx.Client | None = None
) -> tuple[str, ...]:
    """Log each seeded identity into crAPI and store its bearer token (setup).

    Direct HTTP, out of band from recon — this is the onboarding step the
    ownership recipe's ``requires_session`` waits on. Every configured identity
    must authenticate; a partial identity set would silently turn ownership
    checks into anonymous data, so failures stop the run loudly.
    """
    owns_client = client is None
    http = client or httpx.Client(timeout=_HTTP_TIMEOUT)
    onboarded: list[str] = []
    try:
        for name in identities.names():
            cred = identities.credential(name)
            resp = http.post(
                f"{base_url.rstrip('/')}{_LOGIN_PATH}",
                json={"email": cred.username, "password": cred.password},
            )
            from reachagent.identity.login import LoginError

            if resp.status_code == 429:
                raise LoginError(f"identity {name!r} rate-limited (HTTP 429)", code="rate_limited")
            if not 200 <= resp.status_code < 300:
                raise LoginError(
                    f"identity {name!r} rejected by login (HTTP {resp.status_code})",
                    code="rejected",
                )
            try:
                token = resp.json().get("token")
            except (TypeError, ValueError):
                token = None
            if not isinstance(token, str) or not token:
                raise LoginError(
                    f"identity {name!r} login returned no session material",
                    code="no_session_material",
                )
            identities.open_session(name, token)
            onboarded.append(name)
    finally:
        if owns_client:
            http.close()
    return tuple(onboarded)


def run_recon(
    *,
    base_url: str | None = None,
    surface_path: str | Path | None = None,
    graph: ReachabilityGraph | None = None,
    identities: IdentityStore | None = None,
    firer_client: httpx.Client | None = None,
    onboard_client: httpx.Client | None = None,
) -> ReconResult:
    """Run full crAPI recon: onboard, then map structure + ``can_call`` + ``owns``.

    The mapper fires through a scope-guarded, read-only-first firer, so recon
    cannot emit a state-changing request even though the surface *materializes*
    crAPI's state-changing endpoints (login/signup/contact-mechanic) as nodes.
    The returned :class:`ReconResult` carries the audit log so the caller can
    assert zero destructive side effects (§10) — verified by the Task 6 test and
    required by the Task 7 gate.
    """
    resolved_base = base_url or os.environ.get(_ENV_BASE_URL, _DEFAULT_BASE_URL)
    surface = SurfaceSpec.from_file(surface_path or _DEFAULT_SURFACE)
    graph = graph or ReachabilityGraph()
    identities = identities or _load_identities()

    # Onboarding (authorized setup): establish each identity's session directly.
    onboarded = _onboard(identities, resolved_base, client=onboard_client)

    # Recon: one audited, scope-guarded firer for every mapper request.
    host = httpx.URL(resolved_base).host or ""
    audit = AuditLog()
    client = firer_client or httpx.Client(timeout=_HTTP_TIMEOUT)
    firer = RequestFirer(client, ScopeGuard.from_hosts([host]), audit)
    mapper = SurfaceMapper(graph, firer, identities, resolved_base)

    summary = mapper.run(surface)

    return ReconResult(
        summary=summary,
        onboarded=onboarded,
        audit=tuple(audit.entries),
    )
