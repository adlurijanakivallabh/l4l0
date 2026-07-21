"""Recon and surface mapping (plan §3, §15 Phase 1).

Discovers endpoints, parameters, and objects and writes the structural layer of
the reachability graph (§6). Feeds the ``C → D → E → F → G → C`` loop (§3).
Phase 1 target: VAmPI (§14).
"""

from __future__ import annotations

from reachagent.recon.mapper import (
    EndpointSpec,
    MapSummary,
    ObjectSpec,
    OwnershipDiscovery,
    ParameterSpec,
    SurfaceMapper,
    SurfaceSpec,
    classify_can_call,
)

__all__ = [
    "EndpointSpec",
    "MapSummary",
    "ObjectSpec",
    "OwnershipDiscovery",
    "ParameterSpec",
    "SurfaceMapper",
    "SurfaceSpec",
    "classify_can_call",
]
