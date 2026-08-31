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
    # Non-secret session metadata.  The token/cookie value remains exclusively
    # in the owning IdentityStore; these fields are safe for graph persistence
    # and UI snapshots.
    auth_kind: str = "bearer"
    expires_at: str | None = None


@dataclass
class Endpoint:
    """A callable surface on the target (§6)."""

    method: str
    path: str
    content_type: str | None = None
    protocol: Protocol = Protocol.REST
    graphql_operation_type: str | None = None
    # Transport-tier attributes (§9, v1.8): a stack fingerprinted per-endpoint by a
    # recon tool (whatweb). Attributes, not a Technology node (§6 — absorb, don't
    # sprawl). Facts only; they never carry a finding status.
    technology: str | None = None
    detected_version: str | None = None
    # ACL-surface fact from content discovery (§9, phase2a): when a discovered
    # path responded 401/403, the path EXISTS but is access-restricted — a real
    # third state (exists-served / exists-restricted / missing). Carries the
    # status string ("401"/"403"), None when unclassified. Never a finding, never
    # a bypass — recon-tier fact only.
    access_restricted: str | None = None
    state_changing: bool = False
    # Mapping provenance and replay material. These are facts copied from the
    # discovery source; they never carry a verdict or authorize a request.
    source: str | None = None
    confidence: float | None = None
    evidence_ref: str | None = None
    request_headers: tuple[tuple[str, str], ...] = ()
    request_body: str | None = None
    response_content_type: str | None = None
    response_shape: str | None = None


@dataclass
class Parameter:
    """An input on an Endpoint; ``inferred_sink_type`` set by fingerprinting (§6, §9)."""

    name: str
    location: str
    inferred_sink_type: SinkType | None = None
    # ``location`` is explicit (query/path/json/form/header/cookie/multipart/
    # graphql). ``serialization`` records how a value is encoded so a later
    # firing step cannot silently put a form field into a JSON request.
    serialization: str | None = None
    required: bool = False
    example: str | None = None
    source: str | None = None
    confidence: float | None = None
    evidence_ref: str | None = None


@dataclass
class Object:
    """A data object the app exposes, with ownership and sensitivity (§6).

    ``instance_key`` distinguishes two instances of the same ``type`` (e.g. two
    vehicles) — cross-user BOLA is posed between object *instances* (§5, §8), so
    a type alone is not enough to anchor "identity B reaches identity A's
    object". ``None`` means a type-level object (the structural default); a set
    key is the app's own stable identifier for the instance (e.g. a UUID),
    discovered from a response, never fabricated (Task 7).
    """

    type: str
    owner_identity_ref: str | None = None
    sensitivity_tier: int = 0
    instance_key: str | None = None


@dataclass
class InternalResource:
    """SSRF-relevant target — internal ranges, metadata endpoints, OOB domain (§6)."""

    descriptor: str


@dataclass
class Host:
    """A transport-tier host asserted by a recon tool (§6, §9; v1.8).

    A discovered subdomain is a ``Host`` (a subdomain is just a hostname) — there
    is deliberately no ``Subdomain`` node. Detected CMS/framework/version is an
    *attribute* here (``technology``/``detected_version``), never a ``Technology``
    node — absorbing recon facts into the existing schema, not growing it per-class
    (CLAUDE.md).

    Facts only: a ``Host`` never carries a finding status, is never a ``can_call``
    or ``Finding``, and is never confirmed by an oracle. ``source`` records which
    recon tool asserted the host, so a transport fact is auditable to its emitter.
    """

    address: str
    hostname: str | None = None
    source: str | None = None
    technology: str | None = None
    detected_version: str | None = None
    cname: str | None = None  # a DNS CNAME target — a takeover surface when it's dangling


@dataclass
class Service:
    """A transport-tier port/service asserted by a recon tool (§6, §9; v1.8).

    A port/service pair (e.g. ``443/tcp https``) is a ``Service`` node attached to
    its ``Host`` by a ``runs_service`` edge. Facts only — never a finding status,
    never confirmed by an oracle. ``source`` records the asserting recon tool.
    """

    port: int
    protocol: str = "tcp"
    service_name: str | None = None
    banner: str | None = None
    detected_version: str | None = None
    source: str | None = None


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
