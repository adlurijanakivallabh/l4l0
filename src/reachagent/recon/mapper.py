"""Surface mapper (plan §3, §6; docs/phase1-tasks.md Task 3).

Turns a target + scope + test identities into the *structural* layer of the
reachability graph (§6):

  * ``Endpoint``/``Parameter``/``Object`` nodes, with ``accepts``/``returns``
    edges, materialized from a declarative surface inventory (grey-box recon,
    §16 — an OpenAPI ingest or crawl produces the same inventory);
  * ``can_call`` edges written **per identity**, whose status is set
    *empirically* from a real response fired through Task 1's
    :class:`~reachagent.execution.firer.RequestFirer` — never assumed
    (Task 3 DoD, §6).

Two safety properties are load-bearing here, not incidental:

  * **Read-only-first (§10).** Recon only *probes* authorization on read-only
    endpoints. A state-changing endpoint (``state_changing: true``, e.g. a
    ``GET /createdb`` that wipes the database) is materialized structurally but
    never fired during recon, so its ``can_call`` stays unprobed rather than
    guessed.
  * **can_call is empirical.** The status comes from the observed HTTP status of
    an actual request; an unprobed edge is simply absent, not defaulted to
    allowed. The mapper has no code path that writes a ``can_call`` status
    without a :class:`~reachagent.execution.firer.FireResult` in hand.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from enum import Enum, auto
from pathlib import Path
from typing import Any

import yaml

from reachagent.execution.firer import ReadOnlyFirstError, RequestFirer
from reachagent.execution.scope import OutOfScopeError
from reachagent.graph.nodes import Endpoint, FindingStatus, Object, Parameter, Protocol
from reachagent.graph.store import ReachabilityGraph, identity_id
from reachagent.identity.store import IdentityStore


class _OwnDiscovery(Enum):
    """Outcome of one ownership-reveal attempt for a single identity (Task 2).

    Drives the ``discover_ownership`` counters. Only ``WROTE`` writes an ``owns``
    edge; the other two are empirical-or-absent skips, recorded so a run summary
    can distinguish "not onboarded yet" from "reveal gave no association".
    """

    WROTE = auto()  # the app's response associated the object with this identity
    NO_SESSION = auto()  # requires_session and this identity has no session yet
    UNRESOLVED = auto()  # reveal didn't fire, wasn't served, or named no known owner


@dataclass(frozen=True)
class _OwnResult:
    """One identity's ownership-reveal outcome plus how many ``owns`` edges it wrote.

    ``edges_written`` is > 1 only for a per-instance reveal where the caller owns
    several instances at once (Task 7); it is 0 for every non-``WROTE`` outcome.
    """

    outcome: _OwnDiscovery
    edges_written: int = 0


# HTTP methods recon may fire during surface mapping. Everything else is
# state-changing and gated by read-only-first (§10) — mirrors the firer's own
# read-only set, kept here so recon refuses *before* even handing it to the firer.
_READ_ONLY_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})

# Keep the wire location explicit. ``body`` remains a compatibility alias for
# older surface files; new discovery emits ``json`` for JSON request bodies.
PARAMETER_LOCATIONS = frozenset(
    {"query", "path", "json", "body", "form", "header", "cookie", "multipart", "graphql"}
)

# {placeholder} segments in a templated path (e.g. /users/v1/{username}).
_PATH_PLACEHOLDER = re.compile(r"\{([^}]+)\}")


@dataclass(frozen=True)
class OwnershipDiscovery:
    """A *recipe* for discovering an object's owner empirically (§6, Task 2).

    On a stateful target, ownership is created at runtime — an object is
    associated with a user during signup/onboarding, so there is no owner to
    write into a static YAML field the way a fixed inventory could. Instead an
    ``ObjectSpec`` carries this recipe declaring *how to discover* ownership:

      * ``reveal_path`` — a **read-only** endpoint whose authenticated response
        associates the object with its owner (e.g. a "my resources" listing that
        returns only the caller's own objects);
      * ``requires_session`` — whether that reveal only yields the association
        after the identity has an authenticated session (the "after which
        workflow step" clause): before onboarding establishes the session, the
        mapper writes no edge, keeping ownership empirical-or-absent;
      * ``owner_field`` — if the reveal response *names* the owner in a JSON
        field, the value is matched to a seeded identity's username; if ``None``
        the reveal is **caller-scoped** (the authenticated caller owns whatever
        the endpoint returns to them — the common "my resources" model).
      * ``instance_key_field`` — if set, each resource in the reveal is a distinct
        object *instance* keyed by that field's value (e.g. a resource ``uuid``),
        so two identities owning two different instances of the same type get two
        distinct object nodes (Task 7). If ``None``, the object is type-level: one
        ``owns`` edge to the type node, the pre–Task 7 behaviour.
      * ``items_field`` — if the reveal wraps its resource list under a JSON key
        (e.g. ``{"items": [...]}``) rather than returning a bare array, this names
        that key so the mapper unwraps the collection before keying instances. If
        ``None``, the body is taken as-is (bare list or single object). The key
        name is a fact about the target's response shape, so it lives in the
        surface config, never hardcoded in the mapper.

    The recipe never asserts *who* owns the object, nor fabricates an instance
    key — only how the mapper reads both off the app's own response (Task 2/7).
    """

    reveal_path: str
    reveal_method: str = "GET"
    owner_field: str | None = None
    requires_session: bool = True
    instance_key_field: str | None = None
    items_field: str | None = None

    def __post_init__(self) -> None:
        # The reveal is a probe, so it must be read-only — a state-changing
        # "reveal" would violate read-only-first the moment discovery ran (§10).
        if self.reveal_method.upper() not in _READ_ONLY_METHODS:
            raise ValueError(
                f"ownership reveal_method {self.reveal_method!r} must be read-only "
                f"(one of {sorted(_READ_ONLY_METHODS)}) — discovery only ever probes"
            )


@dataclass(frozen=True)
class ObjectSpec:
    """A declared object an endpoint returns (recon input).

    ``ownership`` is an optional discovery recipe (§6, Task 2); absent means the
    object has no declared owner and the mapper writes no ``owns`` edge for it.
    """

    type: str
    sensitivity_tier: int = 0
    ownership: OwnershipDiscovery | None = None


@dataclass(frozen=True)
class ParameterSpec:
    """A declared parameter of an endpoint (recon input)."""

    name: str
    location: str
    serialization: str | None = None
    required: bool = False
    example: str | None = None
    source: str | None = None
    confidence: float | None = None
    evidence_ref: str | None = None

    def __post_init__(self) -> None:
        if not self.name.strip():
            raise ValueError("parameter name must not be empty")
        if self.location not in PARAMETER_LOCATIONS:
            raise ValueError(
                f"unsupported parameter location {self.location!r}; "
                f"expected one of {sorted(PARAMETER_LOCATIONS)}"
            )
        if self.serialization is not None:
            serialization = self.serialization.lower()
            expected = {
                "query": ("application/x-www-form-urlencoded", "query"),
                "path": ("path",),
                "header": ("header",),
                "cookie": ("cookie",),
                "json": ("application/json", "json"),
                "body": ("application/json", "json", "body"),
                "form": ("application/x-www-form-urlencoded", "form"),
                "multipart": ("multipart/form-data", "multipart"),
                "graphql": ("application/json", "graphql"),
            }[self.location]
            if not any(token in serialization for token in expected):
                raise ValueError(
                    f"serialization {self.serialization!r} is incompatible with "
                    f"parameter location {self.location!r}"
                )


@dataclass(frozen=True)
class EndpointSpec:
    """One declared endpoint: its verb, path, inputs, and outputs (recon input)."""

    method: str
    path: str
    content_type: str | None = None
    state_changing: bool = False
    parameters: tuple[ParameterSpec, ...] = ()
    returns: tuple[ObjectSpec, ...] = ()
    sample_path_values: Mapping[str, str] = field(default_factory=dict)
    protocol: Protocol = Protocol.REST
    graphql_operation_type: str | None = None
    source: str | None = None
    confidence: float | None = None
    evidence_ref: str | None = None
    request_headers: tuple[tuple[str, str], ...] = ()
    request_body: str | None = None
    response_content_type: str | None = None
    response_shape: str | None = None

    @property
    def is_read_only(self) -> bool:
        """A recon-fireable endpoint: read-only verb and not flagged mutating (§10)."""
        return self.method.upper() in _READ_ONLY_METHODS and not self.state_changing


@dataclass(frozen=True)
class SurfaceSpec:
    """The full declared surface — the mapper's input inventory."""

    endpoints: tuple[EndpointSpec, ...]

    @classmethod
    def from_file(cls, path: str | Path) -> SurfaceSpec:
        """Load a surface inventory from a YAML file (see the per-target surface configs)."""
        raw = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
        if not isinstance(raw, Mapping) or "endpoints" not in raw:
            raise ValueError("surface file must have a top-level 'endpoints' list")
        return cls.from_mapping(raw)

    @classmethod
    def from_mapping(cls, raw: Mapping[str, object]) -> SurfaceSpec:
        """Build a spec from an already-parsed mapping."""
        raw_endpoints = raw.get("endpoints")
        if not isinstance(raw_endpoints, list):
            raise ValueError("surface 'endpoints' must be a list")
        endpoints: list[EndpointSpec] = []
        for entry in raw_endpoints:
            if not isinstance(entry, Mapping):
                raise ValueError("each endpoint entry must be a mapping")
            params = tuple(
                ParameterSpec(
                    name=str(p["name"]),
                    location=str(p["location"]),
                    serialization=(
                        str(p["serialization"]) if p.get("serialization") is not None else None
                    ),
                    required=bool(p.get("required", False)),
                    example=(str(p["example"]) if p.get("example") is not None else None),
                    source=(str(p["source"]) if p.get("source") is not None else None),
                    confidence=(
                        float(p["confidence"]) if p.get("confidence") is not None else None
                    ),
                    evidence_ref=(
                        str(p["evidence_ref"]) if p.get("evidence_ref") is not None else None
                    ),
                )
                for p in entry.get("parameters", [])
                if isinstance(p, Mapping)
            )
            returns = tuple(cls._object_spec(o) for o in entry.get("returns", []))
            raw_headers = entry.get("request_headers", {})
            request_headers = (
                tuple(sorted((str(k), str(v)) for k, v in raw_headers.items()))
                if isinstance(raw_headers, Mapping)
                else ()
            )
            raw_body = entry.get("request_body")
            request_body = (
                raw_body
                if isinstance(raw_body, str)
                else json.dumps(raw_body, sort_keys=True)
                if raw_body is not None
                else None
            )
            endpoints.append(
                EndpointSpec(
                    method=str(entry["method"]),
                    path=str(entry["path"]),
                    content_type=entry.get("content_type"),
                    state_changing=bool(entry.get("state_changing", False)),
                    parameters=params,
                    returns=returns,
                    sample_path_values={
                        str(k): str(v)
                        for k, v in (
                            entry.get("sample_path_values", {})
                            if isinstance(entry.get("sample_path_values", {}), Mapping)
                            else {}
                        ).items()
                    },
                    protocol=Protocol(str(entry.get("protocol", Protocol.REST.value))),
                    graphql_operation_type=(
                        str(entry["graphql_operation_type"])
                        if entry.get("graphql_operation_type") is not None
                        else None
                    ),
                    source=(str(entry["source"]) if entry.get("source") is not None else None),
                    confidence=(
                        float(entry["confidence"]) if entry.get("confidence") is not None else None
                    ),
                    evidence_ref=(
                        str(entry["evidence_ref"])
                        if entry.get("evidence_ref") is not None
                        else None
                    ),
                    request_headers=request_headers,
                    request_body=request_body,
                    response_content_type=(
                        str(entry["response_content_type"])
                        if entry.get("response_content_type") is not None
                        else None
                    ),
                    response_shape=(
                        str(entry["response_shape"])
                        if entry.get("response_shape") is not None
                        else None
                    ),
                )
            )
        return cls(endpoints=tuple(endpoints))

    @staticmethod
    def _object_spec(raw: Mapping[str, object]) -> ObjectSpec:
        """Build one ``ObjectSpec``, parsing an optional ``ownership`` recipe.

        ``ownership`` is a discovery recipe (§6, Task 2), never a static owner:
        absent → no owner is declared and the mapper writes no ``owns`` edge.
        """
        raw_ownership = raw.get("ownership")
        ownership: OwnershipDiscovery | None = None
        if raw_ownership is not None:
            if not isinstance(raw_ownership, Mapping):
                raise ValueError("object 'ownership' must be a mapping (a discovery recipe)")
            if "reveal_path" not in raw_ownership:
                raise ValueError("ownership recipe needs a 'reveal_path' (the read-only reveal)")
            ownership = OwnershipDiscovery(
                reveal_path=str(raw_ownership["reveal_path"]),
                reveal_method=str(raw_ownership.get("reveal_method", "GET")),
                owner_field=(
                    str(raw_ownership["owner_field"])
                    if raw_ownership.get("owner_field") is not None
                    else None
                ),
                requires_session=bool(raw_ownership.get("requires_session", True)),
                instance_key_field=(
                    str(raw_ownership["instance_key_field"])
                    if raw_ownership.get("instance_key_field") is not None
                    else None
                ),
                items_field=(
                    str(raw_ownership["items_field"])
                    if raw_ownership.get("items_field") is not None
                    else None
                ),
            )
        return ObjectSpec(
            type=str(raw["type"]),
            # Coerce through str first: raw.get is typed `object`, and int() has no
            # overload for object — a YAML scalar (int/str/float) round-trips cleanly.
            sensitivity_tier=int(str(raw.get("sensitivity_tier", 0))),
            ownership=ownership,
        )


@dataclass(frozen=True)
class MapSummary:
    """Coverage counts from a mapping run — cheap reporting/test surface."""

    endpoints: int
    parameters: int
    objects: int
    can_call_probed: int
    can_call_skipped_state_changing: int
    can_call_skipped_untemplated: int
    owns_discovered: int = 0
    owns_skipped_no_session: int = 0
    owns_skipped_unresolved: int = 0


def classify_can_call(status_code: int) -> FindingStatus:
    """Map an observed HTTP status to an empirical ``can_call`` verdict (§6).

    Deterministic and response-driven — this is the only place a status is
    derived, and it takes a real status code, never a guess:

      * 2xx                → ``CONFIRMED_ALLOWED`` (the identity reached it)
      * 401 / 403          → ``CONFIRMED_DENIED``  (authorization refused)
      * anything else      → ``INCONCLUSIVE``      (404/5xx/redirect — no
                             authorization signal to stand on)
    """
    if 200 <= status_code < 300:
        return FindingStatus.CONFIRMED_ALLOWED
    if status_code in (401, 403):
        return FindingStatus.CONFIRMED_DENIED
    return FindingStatus.INCONCLUSIVE


class SurfaceMapper:
    """Populates the structural layer of the reachability graph from recon (§6).

    The mapper is generic: no per-endpoint logic lives here. It reads a declared
    surface, materializes nodes/edges, and confirms ``can_call`` empirically by
    firing read-only probes for each seeded identity through the execution layer.
    """

    def __init__(
        self,
        graph: ReachabilityGraph,
        firer: RequestFirer,
        identities: IdentityStore,
        base_url: str,
        *,
        default_path_values: Mapping[str, str] | None = None,
    ) -> None:
        self._graph = graph
        self._firer = firer
        self._identities = identities
        self._base_url = base_url.rstrip("/")
        # Fallback values for path placeholders not carried on an endpoint itself.
        self._default_path_values = dict(default_path_values or {})

    # -- structural materialization (§6) ----------------------------------

    def map_structure(self, spec: SurfaceSpec) -> None:
        """Materialize every endpoint, parameter, and object as graph nodes/edges.

        Idempotent: the store keys nodes deterministically, so re-running recon
        refreshes rather than duplicates the surface.
        """
        for ep in spec.endpoints:
            endpoint_node = self._graph.add_endpoint(
                Endpoint(
                    method=ep.method.upper(),
                    path=ep.path,
                    content_type=ep.content_type,
                    state_changing=ep.state_changing,
                    protocol=ep.protocol,
                    graphql_operation_type=ep.graphql_operation_type,
                    source=ep.source,
                    confidence=ep.confidence,
                    evidence_ref=ep.evidence_ref,
                    request_headers=ep.request_headers,
                    request_body=ep.request_body,
                    response_content_type=ep.response_content_type,
                    response_shape=ep.response_shape,
                )
            )
            for param in ep.parameters:
                self._graph.add_parameter(
                    endpoint_node,
                    Parameter(
                        name=param.name,
                        location=param.location,
                        serialization=param.serialization,
                        required=param.required,
                        example=param.example,
                        source=param.source,
                        confidence=param.confidence,
                        evidence_ref=param.evidence_ref,
                    ),
                )
            for obj in ep.returns:
                object_node = self._graph.add_object(
                    Object(type=obj.type, sensitivity_tier=obj.sensitivity_tier)
                )
                self._graph.add_returns(endpoint_node, object_node)

    # -- empirical authorization (§6, §10) --------------------------------

    def probe_can_call(self, spec: SurfaceSpec) -> MapSummary:
        """Fire read-only probes per identity and write empirical ``can_call`` edges.

        For each read-only endpoint and each seeded identity, fires one request
        (carrying that identity's own token, if any) and records the resulting
        ``can_call`` status from the *observed* response. State-changing and
        un-fillable templated endpoints are materialized but left unprobed —
        their authorization is confirmed later, under the read-only-first
        controls, never assumed now.
        """
        probed = 0
        skipped_state_changing = 0
        skipped_untemplated = 0

        for ep in spec.endpoints:
            if not ep.is_read_only:
                skipped_state_changing += 1
                continue
            concrete = self._resolve_path(ep)
            if concrete is None:
                # A templated path we have no sample value for — can't fire a
                # real request, so we refuse to invent a can_call status.
                skipped_untemplated += 1
                continue

            endpoint_node = self._graph.add_endpoint(
                Endpoint(
                    method=ep.method.upper(),
                    path=ep.path,
                    content_type=ep.content_type,
                    state_changing=ep.state_changing,
                    protocol=ep.protocol,
                    graphql_operation_type=ep.graphql_operation_type,
                    source=ep.source,
                    confidence=ep.confidence,
                    evidence_ref=ep.evidence_ref,
                    request_headers=ep.request_headers,
                    request_body=ep.request_body,
                    response_content_type=ep.response_content_type,
                    response_shape=ep.response_shape,
                )
            )
            url = f"{self._base_url}{concrete}"
            for name in self._identities.names():
                identity_node = self._graph.add_identity(name, self._identities.identity(name))
                status = self._probe_one(
                    name,
                    identity_node,
                    ep.method,
                    endpoint_node,
                    url,
                    **self._probe_kwargs(ep),
                )
                if status is not None:
                    probed += 1

        return MapSummary(
            endpoints=len(spec.endpoints),
            parameters=sum(len(ep.parameters) for ep in spec.endpoints),
            objects=sum(len(ep.returns) for ep in spec.endpoints),
            can_call_probed=probed,
            can_call_skipped_state_changing=skipped_state_changing,
            can_call_skipped_untemplated=skipped_untemplated,
        )

    def discover_ownership(self, spec: SurfaceSpec, base: MapSummary) -> MapSummary:
        """Discover object ownership empirically and write ``owns`` edges (§6, Task 2).

        Ownership on a stateful target is created at runtime, so the mapper never
        asserts an owner — it runs each object's :class:`OwnershipDiscovery` recipe:
        fire the recipe's **read-only** reveal endpoint as an identity that has an
        authenticated session (the onboarding step, Task 6), then write the ``owns``
        edge from what the response *actually* associates:

          * ``requires_session`` + no session for an identity → that identity is
            skipped (counted ``owns_skipped_no_session``): before onboarding
            establishes the session there is no association to read, so no edge is
            written — the empirical-or-absent rule (mirrors ``can_call``).
          * ``owner_field is None`` (caller-scoped) → a 2xx reveal means the
            authenticated caller owns the object the endpoint returned to them, so
            an ``owns(identity → object)`` edge is written from that observed 2xx.
          * ``owner_field`` set → the named owner in the JSON body is matched to a
            seeded identity; an unmatched/absent value writes no edge (counted
            ``owns_skipped_unresolved``), never a guessed owner.
          * ``instance_key_field`` set → each resource in the reveal is a distinct
            object *instance* (keyed by that field, e.g. a resource ``uuid``), so a
            caller can own several instances at once and two owners of two
            instances get two distinct nodes (Task 7). ``owns_discovered`` counts
            edges written, so a caller owning N instances contributes N.

        Generic by construction: the loop reads only the recipe + the response, so
        the same code path serves any target — no per-object or per-target branch.
        """
        discovered = 0
        skipped_no_session = 0
        skipped_unresolved = 0

        for ep in spec.endpoints:
            for obj in ep.returns:
                recipe = obj.ownership
                if recipe is None:
                    continue  # No recipe: empirical-or-absent — write nothing.
                for name in self._identities.names():
                    result = self._discover_one_owner(name, obj, recipe)
                    if result.outcome is _OwnDiscovery.WROTE:
                        discovered += result.edges_written
                    elif result.outcome is _OwnDiscovery.NO_SESSION:
                        skipped_no_session += 1
                    else:  # UNRESOLVED
                        skipped_unresolved += 1

        return replace(
            base,
            owns_discovered=discovered,
            owns_skipped_no_session=skipped_no_session,
            owns_skipped_unresolved=skipped_unresolved,
        )

    def run(self, spec: SurfaceSpec) -> MapSummary:
        """Full recon pass: structure, then empirical ``can_call``, then ``owns``."""
        self.map_structure(spec)
        summary = self.probe_can_call(spec)
        return self.discover_ownership(spec, summary)

    # -- internals --------------------------------------------------------

    def _probe_one(
        self,
        identity: str,
        identity_node: str,
        method: str,
        endpoint_node: str,
        url: str,
        **kwargs: Any,
    ) -> FindingStatus | None:
        """Fire one read-only probe and write the empirical ``can_call`` edge.

        ``identity_node``/``endpoint_node`` are the ids the caller already
        materialized — passed in rather than reconstructed, so this method has a
        single source of truth for node identity.

        Returns the recorded status, or ``None`` if the request never produced a
        response we can classify (out-of-scope, read-only-first refusal, or a
        transport error) — in which case no ``can_call`` edge is written, so an
        unfired probe never masquerades as a confirmed verdict.
        """
        headers = self._auth_headers(identity)
        try:
            if kwargs.get("headers"):
                merged_headers = dict(kwargs["headers"])
                merged_headers.update(headers)
                kwargs["headers"] = merged_headers
            else:
                kwargs["headers"] = headers
            result = self._firer.fire(identity, method, url, **kwargs)
        except (OutOfScopeError, ReadOnlyFirstError):
            # Safety gate refused it — audited by the firer; nothing to record.
            return None
        except Exception:  # noqa: BLE001 — a transport error is not an auth signal
            return None

        status = classify_can_call(result.status_code)
        self._graph.set_can_call(
            identity_node,
            endpoint_node,
            status,
            evidence=f"HTTP {result.status_code}",
        )
        return status

    def _discover_one_owner(
        self, identity: str, obj: ObjectSpec, recipe: OwnershipDiscovery
    ) -> _OwnResult:
        """Fire one ownership reveal for ``identity`` and write the ``owns`` edge(s).

        The empirical partner of :meth:`_probe_one`, held to the same discipline:
        an edge is written only from an observed 2xx reveal, and any path that
        can't read a real association (no session, refused, transport error, an
        unmatched owner field, an empty reveal) writes nothing. Returns an
        :class:`_OwnResult` so the caller can tally the run summary.

        With ``recipe.instance_key_field`` set, each resource in the reveal is a
        distinct object *instance* keyed by that field, so the caller can own
        several instances at once (Task 7); without it, the object is type-level
        and the caller owns at most the one type node (pre–Task 7 behaviour).
        """
        # "After which workflow step": a session-gated reveal is skipped until
        # onboarding has established this identity's session (empirical-or-absent).
        if recipe.requires_session and self._identities.session(identity) is None:
            return _OwnResult(_OwnDiscovery.NO_SESSION)

        headers = self._auth_headers(identity)
        url = f"{self._base_url}{recipe.reveal_path}"
        try:
            result = self._firer.fire(identity, recipe.reveal_method, url, headers=headers)
        except (OutOfScopeError, ReadOnlyFirstError):
            return _OwnResult(_OwnDiscovery.UNRESOLVED)
        except Exception:  # noqa: BLE001 — a transport error is not an ownership signal
            return _OwnResult(_OwnDiscovery.UNRESOLVED)

        # Only a served reveal carries an association to read; anything else
        # (403/404/5xx) means this identity did not demonstrate ownership here.
        if not 200 <= result.status_code < 300:
            return _OwnResult(_OwnDiscovery.UNRESOLVED)

        if recipe.instance_key_field is None:
            return self._write_type_level_owner(identity, obj, recipe, result.body)
        return self._write_instance_owners(identity, obj, recipe, result.body)

    def _write_type_level_owner(
        self, identity: str, obj: ObjectSpec, recipe: OwnershipDiscovery, body: bytes
    ) -> _OwnResult:
        """Type-level ownership (no ``instance_key_field``): one owns edge, unchanged."""
        owner = self._resolve_owner(identity, recipe, body)
        if owner is None:
            # No association: an empty caller-scoped reveal, or a named owner that
            # matched no seeded identity — never guess an owner.
            return _OwnResult(_OwnDiscovery.UNRESOLVED)
        node = self._graph.add_object(Object(type=obj.type, sensitivity_tier=obj.sensitivity_tier))
        self._graph.set_owns(identity_id(owner), node)
        return _OwnResult(_OwnDiscovery.WROTE, edges_written=1)

    def _write_instance_owners(
        self, identity: str, obj: ObjectSpec, recipe: OwnershipDiscovery, body: bytes
    ) -> _OwnResult:
        """Per-instance ownership: one distinct object node per resource in the reveal.

        Each resource is keyed by ``recipe.instance_key_field`` read from the
        response (the app's own identifier, e.g. a resource ``uuid``), never a
        positional index — so two identities owning two different instances get
        two distinct nodes (Task 7). A resource with no owner or no instance key
        is skipped rather than guessed; a reveal that yields no ownable instance
        is ``UNRESOLVED``.
        """
        written = 0
        key_field = recipe.instance_key_field
        if key_field is None:  # unreachable via _discover_one_owner; guards the type
            return _OwnResult(_OwnDiscovery.UNRESOLVED)
        for item in self._reveal_items(body, recipe.items_field):
            owner = self._item_owner(identity, recipe, item)
            if owner is None:
                continue
            key = item.get(key_field)
            if key is None:
                continue  # No stable identifier for this instance — don't fabricate one.
            node = self._graph.add_object(
                Object(
                    type=obj.type,
                    sensitivity_tier=obj.sensitivity_tier,
                    instance_key=str(key),
                )
            )
            self._graph.set_owns(identity_id(owner), node)
            written += 1
        if written == 0:
            return _OwnResult(_OwnDiscovery.UNRESOLVED)
        return _OwnResult(_OwnDiscovery.WROTE, edges_written=written)

    def _item_owner(
        self, caller: str, recipe: OwnershipDiscovery, item: Mapping[str, object]
    ) -> str | None:
        """Resolve the owner of one reveal resource, or ``None`` if unresolvable.

        Caller-scoped (``owner_field is None``): the resource is in the caller's
        own "my resources" reveal, so the owner is the caller. Named-owner: the
        resource's ``owner_field`` value is matched to a seeded identity's
        username; an absent field or an unrecognized value resolves to ``None``.
        """
        if recipe.owner_field is None:
            return caller
        named = item.get(recipe.owner_field)
        if named is None:
            return None
        for name in self._identities.names():
            if self._identities.credential(name).username == str(named):
                return name
        return None

    @staticmethod
    def _reveal_items(body: bytes, items_field: str | None = None) -> list[Mapping[str, object]]:
        """The reveal's resources as a list of JSON objects (empty if none/unparseable).

        When ``items_field`` is set the collection is unwrapped from that key first
        (e.g. ``{"items": [...]}``), so the resources — not the wrapper — are keyed.
        Otherwise a list body yields its object elements and a single object body
        yields itself; anything else yields no items.
        """
        try:
            payload = json.loads(body)
        except (json.JSONDecodeError, ValueError):
            return []
        if items_field is not None and isinstance(payload, Mapping):
            payload = payload.get(items_field, [])
        if isinstance(payload, list):
            return [it for it in payload if isinstance(it, Mapping)]
        if isinstance(payload, Mapping):
            return [payload]
        return []

    def _resolve_owner(self, caller: str, recipe: OwnershipDiscovery, body: bytes) -> str | None:
        """Resolve the owning identity from a 2xx reveal, or ``None`` if unresolved.

        Two modes, both reading the app's own response, never asserting an owner:

          * caller-scoped (``owner_field is None``): the authenticated ``caller``
            owns whatever the reveal returned to them — the natural "my resources"
            model. But a 2xx alone is not ownership: a caller with *no* resource
            gets an empty reveal (``[]``/``{}``/``null``), which is no association,
            so the owner resolves to ``None`` (no edge). Only a non-empty reveal
            body attributes the object to the caller.
          * named-owner (``owner_field`` set): the field's value in the JSON body
            is matched to a seeded identity's username; an absent field or a value
            matching no seeded identity resolves to ``None`` (no edge).
        """
        if recipe.owner_field is None:
            return caller if self._reveal_has_resource(body) else None
        try:
            payload = json.loads(body)
        except (json.JSONDecodeError, ValueError):
            return None
        named = self._read_field(payload, recipe.owner_field)
        if named is None:
            return None
        # Match the app-reported owner name to a seeded identity by username; the
        # graph keys identities by seed name, so translate through the credential.
        for name in self._identities.names():
            if self._identities.credential(name).username == named:
                return name
        return None

    @staticmethod
    def _reveal_has_resource(body: bytes) -> bool:
        """True iff a caller-scoped reveal body actually returned a resource.

        An empty reveal — an empty list/object, ``null``, or a non-JSON/empty
        body — is *no association*, so it must not attribute ownership to the
        caller (empirical-or-absent). A non-empty JSON list or object does.
        """
        try:
            payload = json.loads(body)
        except (json.JSONDecodeError, ValueError):
            return False
        if isinstance(payload, list | Mapping):
            return len(payload) > 0
        # A bare scalar (unusual for a "my resources" reveal) is not a resource.
        return False

    @staticmethod
    def _read_field(payload: object, field_name: str) -> str | None:
        """Read ``field_name`` from a JSON object (or the first item of a list)."""
        if isinstance(payload, list):
            payload = payload[0] if payload else None
        if isinstance(payload, Mapping):
            value = payload.get(field_name)
            return str(value) if value is not None else None
        return None

    def _auth_headers(self, identity: str) -> dict[str, str]:
        """Bearer header from the identity's isolated token store, if it has one.

        Reads only the owning identity's store (§10 isolation) — an identity with
        no seeded session probes unauthenticated, which is itself a valid
        ``can_call`` signal (unauth → typically ``confirmed_denied``).
        """
        token = self._identities.token_store(identity).get_token()
        return {"Authorization": f"Bearer {token}"} if token else {}

    def _resolve_path(self, ep: EndpointSpec) -> str | None:
        """Fill ``{placeholders}`` from sample/default values; ``None`` if any remain."""
        placeholders = _PATH_PLACEHOLDER.findall(ep.path)
        if not placeholders:
            return ep.path
        resolved = ep.path
        for name in placeholders:
            value = ep.sample_path_values.get(name) or self._default_path_values.get(name)
            if value is None:
                return None
            resolved = resolved.replace(f"{{{name}}}", value)
        return resolved

    def _probe_kwargs(self, ep: EndpointSpec) -> dict[str, object]:
        """Build a benign, serialization-correct request shape for a read-only probe."""
        if ep.method.upper() not in {"GET", "HEAD", "OPTIONS"}:
            return {}
        query: dict[str, str] = {}
        headers = dict(ep.request_headers)
        cookies: dict[str, str] = {}
        form: dict[str, str] = {}
        body: dict[str, object] = {}
        if ep.request_body:
            try:
                seed_body = json.loads(ep.request_body)
            except (json.JSONDecodeError, TypeError):
                seed_body = None
            if isinstance(seed_body, Mapping):
                body.update(seed_body)
        for param in ep.parameters:
            raw_value = param.example if param.example is not None else _benign_value(param.name)
            decoded_value = _json_value(raw_value)
            value = (
                str(decoded_value)
                if isinstance(decoded_value, (str, int, float, bool))
                else json.dumps(decoded_value, sort_keys=True)
            )
            if param.location == "query":
                query[param.name] = value
            elif param.location == "header":
                headers[param.name] = value
            elif param.location == "cookie":
                cookies[param.name] = value
            elif param.location == "form":
                form[param.name] = value
            elif param.location in {"json", "body"}:
                body[param.name] = decoded_value
        kwargs: dict[str, object] = {}
        if query:
            kwargs["params"] = query
        if headers:
            kwargs["headers"] = headers
        if cookies:
            kwargs["cookies"] = cookies
        if form:
            form.update({str(k): str(v) for k, v in body.items()})
            kwargs["data"] = form
        elif body:
            kwargs["json"] = body
        return kwargs


def _benign_value(name: str) -> str:
    """Return a stable non-invasive example when a schema gave none."""
    lowered = name.lower()
    if lowered.endswith(("id", "count", "page", "limit")):
        return "1"
    if "email" in lowered:
        return "probe@example.invalid"
    return "reachagent-probe"


def _json_value(value: str) -> object:
    try:
        return json.loads(value)
    except (json.JSONDecodeError, TypeError):
        return value
