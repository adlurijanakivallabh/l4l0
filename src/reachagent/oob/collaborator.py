"""Out-of-band collaborator client (plan §7, §13; Phase 3 Task 1).

A thin client over a **self-hosted interact.sh instance** (§13) — never Burp
Collaborator or any external service (CLAUDE.md: no external scanners). It does
two things:

  * mints a unique per-probe callback subdomain (``<nonce>.<base-domain>``) so a
    payload's out-of-band trigger can be attributed to exactly one probe, even
    when concurrent probes run on different parameters;
  * reports which nonces the collaborator has actually observed, so the
    :class:`~reachagent.oracles.oob_callback.OOBCallbackOracle` can confirm.

The collaborator base domain and auth token are loaded from the environment /
secret store, never hardcoded — a literal collaborator hostname in this module
would both leak infrastructure and pin every deployment to one host. The
:class:`OOBCollaborator` protocol lets a test inject an in-memory fake without
any network, and lets the real interact.sh HTTP poller drop in unchanged.
"""

from __future__ import annotations

import os
from typing import Protocol, runtime_checkable

# Env keys — the self-hosted interact.sh base domain and its polling auth token.
# No default host: an unset base domain must fail loudly, never silently fall
# back to a hardcoded or public collaborator.
_ENV_BASE_DOMAIN = "REACHAGENT_OOB_BASE_DOMAIN"
_ENV_TOKEN = "REACHAGENT_OOB_TOKEN"  # noqa: S105 — env *key* name, not a secret


class OOBConfigError(RuntimeError):
    """Raised when the collaborator base domain is not configured.

    Refusing to run without a configured self-hosted domain is deliberate: a
    missing domain must surface as an error, never a silent fallback to a public
    or hardcoded collaborator (CLAUDE.md, §10 scope discipline).
    """


@runtime_checkable
class OOBCollaborator(Protocol):
    """The collaborator surface a blind-injection probe needs.

    Implemented by the real self-hosted interact.sh poller and by an in-memory
    fake in tests — the detector depends on this protocol, not a concrete host.
    """

    def callback_domain(self, nonce: str) -> str:
        """Return the callback subdomain a probe with ``nonce`` should exfil to."""
        ...

    def observed_nonces(self) -> frozenset[str]:
        """Return the set of nonces the collaborator has received so far."""
        ...


class InteractshCollaborator:
    """Real collaborator over a self-hosted interact.sh instance (§13).

    The base domain and token come from the environment. This class builds
    per-nonce subdomains and would poll the instance's registration endpoint for
    received interactions; the poll transport is injected so the class carries no
    network specifics itself (and stays testable).
    """

    def __init__(
        self,
        base_domain: str | None = None,
        token: str | None = None,
        *,
        environ: dict[str, str] | None = None,
    ) -> None:
        env = os.environ if environ is None else environ
        resolved = base_domain or env.get(_ENV_BASE_DOMAIN)
        if not resolved:
            raise OOBConfigError(
                f"no OOB collaborator base domain configured; set {_ENV_BASE_DOMAIN} "
                "to a self-hosted interact.sh domain (no default — external/public "
                "collaborators are refused)"
            )
        self._base_domain = resolved.lstrip(".")
        self._token = token if token is not None else env.get(_ENV_TOKEN)
        self._observed: set[str] = set()

    def callback_domain(self, nonce: str) -> str:
        """Return ``<nonce>.<base-domain>`` — the per-probe callback subdomain."""
        if not nonce:
            raise ValueError("nonce must be non-empty to attribute a callback")
        return f"{nonce}.{self._base_domain}"

    def record_interaction(self, nonce: str) -> None:
        """Register that the collaborator observed a callback for ``nonce``.

        The real poller calls this as it drains interactions from the interact.sh
        instance; a test calls it to simulate a received callback.
        """
        self._observed.add(nonce)

    def observed_nonces(self) -> frozenset[str]:
        """Snapshot the nonces observed so far (immutable copy)."""
        return frozenset(self._observed)
