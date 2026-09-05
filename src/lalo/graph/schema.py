"""Node and edge type vocabulary for the reachability graph.

New node/edge types need explicit justification — the design goal is to absorb new
capabilities into this schema, not grow it per-feature.
"""

from __future__ import annotations

from enum import StrEnum


class NodeType(StrEnum):
    ENDPOINT = "endpoint"
    PARAMETER = "parameter"
    IDENTITY = "identity"
    SESSION = "session"
    SERVICE = "service"  # non-web network service
    CLOUD_ASSET = "cloud_asset"
    HOST = "host"
    FINDING = "finding"
    EVIDENCE = "evidence"
    FINGERPRINT = "fingerprint"


class EdgeType(StrEnum):
    # structural discovery
    HAS_PARAMETER = "has_parameter"
    AUTHENTICATED_AS = "authenticated_as"  # session -> identity
    RUNS_ON = "runs_on"  # endpoint/service -> host
    EVIDENCED_BY = "evidenced_by"  # finding -> evidence
    AFFECTS = "affects"  # finding -> endpoint/service/asset
    # attack chaining: a primitive/finding enables reaching another node
    ENABLES = "enables"
