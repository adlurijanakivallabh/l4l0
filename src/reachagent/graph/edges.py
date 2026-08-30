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
    # Transport-tier (§9, v1.8) — recon facts, never a can_call/Finding, no status.
    RUNS_SERVICE = "runs_service"  # Host → Service, a host exposes a port/service
    RESOLVES_TO = "resolves_to"  # Host → Endpoint, a host serves an HTTP path
    DATA_DEPENDENCY = "data_dependency"  # Endpoint → Endpoint, producer data feeds a consumer


class FindingEdge(StrEnum):
    """Chain-mechanism edges (§6, §8)."""

    ENABLES = "enables"  # Finding → Finding, the chain edge
    DERIVED_CREDENTIAL = "derived_credential"  # Finding → Session | Identity
