"""Graph node types (plan §6).

Node dataclasses for the two-layer reachability graph. Structure only — no
persistence or validation logic yet (Phase 1 scaffolding, §15).

The design goal (CLAUDE.md working conventions) is absorbing new vulnerability
classes into this existing schema, not growing it per-class. Adding a node type
here needs explicit justification.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum


class AuthState(StrEnum):
    """Authentication state of an Identity (§6)."""

    UNAUTH = "unauth"
    USER = "user"
    ADMIN = "admin"
    SYNTHETIC = "synthetic"


class Provenance(StrEnum):
    """How an Identity/Session came to exist (§6).

    ``DERIVED`` nodes are the ones the Coordinator weights heaviest via
    ``is_newly_spawned_identity`` in the §4 scoring rule.
    """

    SEEDED = "seeded"
    DERIVED = "derived"


class Protocol(StrEnum):
    """Endpoint protocol (§6)."""

    REST = "rest"
    GRAPHQL = "graphql"


class SinkType(StrEnum):
    """Inferred sink type set on a Parameter by ``fingerprint_parameter`` (§9)."""

    SQL = "sql"
    NOSQL = "nosql"
    SHELL = "shell"
    LDAP = "ldap"
    TEMPLATE = "template"
    FILE_PATH = "file_path"
    DESERIALIZE_TARGET = "deserialize_target"
    HTML_REFLECTION = "html_reflection"
    URL = "url"


class FindingStatus(StrEnum):
    """Status carried by ``can_call`` and ``Finding`` edges/nodes (§6)."""

    CONFIRMED_ALLOWED = "confirmed_allowed"
    CONFIRMED_DENIED = "confirmed_denied"
    CONFIRMED_VIOLATION = "confirmed_violation"
    INCONCLUSIVE = "inconclusive"


@dataclass
class Identity:
    """A test principal in the target's role hierarchy (§6)."""

    role: str
    auth_state: AuthState
    provenance: Provenance


@dataclass
class Session:
    """A live/expired session bound to an Identity (§6)."""

    token_ref: str
    identity_ref: str
    live: bool = True


@dataclass
class Endpoint:
    """A callable surface on the target (§6)."""

    method: str
    path: str
    content_type: str | None = None
    protocol: Protocol = Protocol.REST
    graphql_operation_type: str | None = None


@dataclass
class Parameter:
    """An input on an Endpoint; ``inferred_sink_type`` set by fingerprinting (§6, §9)."""

    name: str
    location: str
    inferred_sink_type: SinkType | None = None


@dataclass
class Object:
    """A data object the app exposes, with ownership and sensitivity (§6)."""

    type: str
    owner_identity_ref: str | None = None
    sensitivity_tier: int = 0


@dataclass
class InternalResource:
    """SSRF-relevant target — internal ranges, metadata endpoints, OOB domain (§6)."""

    descriptor: str


@dataclass
class ExecutionContext:
    """Confirms code execution occurred for injection/RCE-class findings (§6).

    Deliberately not wired to any interactive/post-exploitation tooling (§1).
    """

    detail: str


@dataclass
class Finding:
    """A confirmed vulnerability — only ever written by the Validator (§4, §13).

    Never constructed from anything but a ``confirmed`` ``run_oracle`` result.
    """

    vuln_class: str
    severity: str
    oracle_used: str
    evidence_ref: str
    status: FindingStatus = FindingStatus.INCONCLUSIVE
    metadata: dict[str, str] = field(default_factory=dict)
