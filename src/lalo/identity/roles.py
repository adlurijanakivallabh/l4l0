"""Role matrix — the systematic core of access-control testing.

Every discovered endpoint x every configured identity is a cell to test: fire the
same endpoint under each identity and compare, surfacing BOLA/IDOR/function-level
auth gaps.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass


@dataclass(frozen=True)
class MatrixCell:
    endpoint: str
    identity: str


def build_role_matrix(
    endpoints: Sequence[str], identities: Sequence[str]
) -> list[MatrixCell]:
    """Return every (endpoint, identity) cell to exercise for access control."""
    return [MatrixCell(endpoint=e, identity=i) for e in endpoints for i in identities]
