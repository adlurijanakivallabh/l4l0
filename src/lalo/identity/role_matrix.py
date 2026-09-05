"""Role matrix: identity x endpoint as a systematic access-control test plan.

Confirmed original for this phase: none of the five references builds an
explicit access-control test plan as a data structure — access-control
testing lives entirely in prose methodology (a reference skill's own
two-tenant/privileged-token guidance, read in full for this phase) or an
LLM's own todo list. Materializing the cartesian product as data lets a
coverage check ask "which (identity, endpoint) pairs were never tried" as a
plain set difference, rather than trusting an agent's self-reported todo list.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class RoleMatrixEntry:
    identity_id: str
    endpoint_id: str
    expected_status: str | None = None


def build_role_matrix(identity_ids: list[str], endpoint_ids: list[str]) -> list[RoleMatrixEntry]:
    """Every (identity, endpoint) pair, identity-major then endpoint-minor.

    Identity-major ordering means a caller working through the plan
    sequentially covers one identity across every endpoint before moving on
    to the next, rather than interleaving identities per endpoint.
    """
    return [
        RoleMatrixEntry(identity_id=identity_id, endpoint_id=endpoint_id)
        for identity_id in identity_ids
        for endpoint_id in endpoint_ids
    ]
