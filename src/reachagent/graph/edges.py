"""Graph edge types (plan §6).

Two edge layers:
  * structural edges (surface mapping)
  * finding-relationship edges (the chain mechanism, §8)

Structure only — Phase 1 scaffolding (§15).
"""

from __future__ import annotations

from enum import StrEnum


class StructuralEdge(StrEnum):
    """Surface-mapping edges (§6)."""

    CAN_CALL = "can_call"  # Identity → Endpoint, empirically confirmed authorization
    RETURNS = "returns"  # Endpoint → Object
    OWNS = "owns"  # Identity → Object, intended ownership
    ACCEPTS = "accepts"  # Endpoint → Parameter
    REACHES = "reaches"  # Endpoint → InternalResource, SSRF outbound reachability
    AUTHENTICATES_AS = "authenticates_as"  # Session → Identity


class FindingEdge(StrEnum):
    """Chain-mechanism edges (§6, §8)."""

    ENABLES = "enables"  # Finding → Finding, the chain edge
    DERIVED_CREDENTIAL = "derived_credential"  # Finding → Session | Identity
