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
    # Application-domain inference (v2 W18): an LLM's best guess at WHAT the app is
    # ("hospital records", "ecommerce", "banking", ...) from the observed surface. An
    # advisory fact, order-only steering for testing priority — never a finding, never a gate.
    app_domain: str | None = None


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
class SourceFile:
    """A static-analysis (SAST) hit in the operator-supplied repo (§6, Build Order 7).

    Facts only — same spirit as ``Host``/``Service``: never a finding status,
    never confirmed by an oracle, never written by anything but a white-box
    static tool (``whitebox/tools/semgrep.py``). A SAST hit STEERS live-testing
    priority (folded into the same bounded ``signals`` dict the tech-aware
    picker already uses); it never gates or substitutes for oracle confirmation.
    """

    path: str
    rule_id: str
    line: int
    message: str
    severity: str = "info"
    source: str | None = None


@dataclass
class PackageDependency:
    """One manifest-declared software dependency (§6, Build Order 7).

    Named ``PackageDependency``, not ``Dependency`` — ``add_dependency``
    already exists in the store as an edge writer (producer/consumer
    parameter data-flow, §8), an unrelated concept this would otherwise
    collide with. Facts only, populated by manifest parsing
    (``whitebox/sca.py``), never a finding status.
    """

    ecosystem: str  # "pypi" | "npm" | ... — the manifest format's package registry
    name: str
    version: str
    manifest: str  # the manifest file path this was declared in
    source: str | None = None


@dataclass
class Secret:
    """A detected hardcoded-secret location in the operator-supplied repo (§6,
    Build Order 7).

    The secret VALUE never enters the graph — only its detector type and
    location, the same "value stays out of the graph" discipline
    :class:`Session` already applies to live tokens (§6, §10). ``verified``
    reflects the scanning tool's own live-validity check (e.g. TruffleHog
    confirming a credential still authenticates), never an oracle
    confirmation — this is a fact-only node like ``Host``/``Service``, not a
    ``Finding``.
    """

    path: str
    line: int
    detector: str
    verified: bool = False
    source: str | None = None


@dataclass
class StaticAdvisory:
    """A known-CVE match against a manifest-declared dependency version (§6,
    Build Order 7) — the plan's one narrow, explicit exception to "no Finding
    without a confirmed run_oracle result."

    Deliberately its OWN node type, never a :class:`Finding`: evidence here is
    a manifest line + a public advisory reference, not a behavioral
    confirmation, because the vulnerable code path may not be reachable from
    the live surface at all — no oracle can fire against a fact this shape.
    Never routed through ``write_finding``/``add_finding``, never merged into
    a confirmed-findings report section — the report template keeps this in
    a visibly separate "static / unconfirmed-reachability" section, always.
    """

    ecosystem: str
    package: str
    version: str
    cve_id: str
    manifest: str
    cvss_score: float | None = None
    epss_score: float | None = None
    summary: str = ""


@dataclass
class SuspectedFinding:
    """A tried-but-unconfirmed lead — the "Suspected / Unconfirmed" tier (Build Order v2 W2).

    Deliberately its OWN node type, never a :class:`Finding`, exactly like
    :class:`StaticAdvisory`: it records something the agent probed and thinks may be real but
    that a deterministic oracle did NOT confirm — an oracle that ran and returned
    non-violation, a signal-gated scanner claim (nuclei/sqlmap/dalfox) the oracle couldn't
    re-prove, or a candidate dropped before it could be tested. Never routed through
    ``write_finding``/``add_finding``, never merged into the confirmed-findings section, never
    counted in confirmed severity stats — the report keeps it in a visibly separate
    "Suspected / Unconfirmed (not oracle-verified)" section, always. It exists so the agent
    surfaces leads for manual review (matching what the reference tools report) instead of
    silently dropping them, WITHOUT weakening the "no Finding without run_oracle" guarantee.

    ``source`` names what proposed it (an oracle mechanism, a tool name, or "llm").
    ``reason`` says why it stayed unconfirmed (e.g. "oracle_inconclusive", "no_oob_channel",
    "scanner_claim_unverified"). ``confidence`` is an optional advisory LLM/heuristic label,
    never a gate.
    """

    vuln_class: str
    endpoint: str = ""
    location: str = ""
    source: str = ""
    reason: str = ""
    evidence: str = ""
    severity: str = "info"
    confidence: str = ""


@dataclass
class Finding:
    """A confirmed vulnerability — only ever written by the Validator (§4, §13).

    Never constructed from anything but a ``confirmed`` ``run_oracle`` result.

    ``llm_confidence``/``llm_confidence_rationale`` (Build Order 5) are kept
    as dedicated fields, deliberately separate from ``metadata``: metadata's
    documented contract (validator.write_finding) is deterministic
    provenance the caller derives from the fired evidence, never LLM
    judgment. Confidence is an LLM's own advisory annotation, added strictly
    after the finding is already oracle-confirmed — it can never influence
    whether the finding exists, only add a second opinion alongside it, and
    keeping it out of ``metadata`` means a report/audit consumer can trust
    every ``metadata`` key came from deterministic evidence without having
    to parse key-name conventions to tell the two apart.
    """

    vuln_class: str
    severity: str
    oracle_used: str
    evidence_ref: str
    status: FindingStatus = FindingStatus.INCONCLUSIVE
    metadata: dict[str, str] = field(default_factory=dict)
    llm_confidence: str = ""
    llm_confidence_rationale: str = ""
