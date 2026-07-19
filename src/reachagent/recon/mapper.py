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
    endpoints. A state-changing endpoint (``state_changing: true``, e.g. VAmPI's
    ``GET /createdb`` which wipes the DB) is materialized structurally but never
    fired during recon, so its ``can_call`` stays unprobed rather than guessed.
  * **can_call is empirical.** The status comes from the observed HTTP status of
    an actual request; an unprobed edge is simply absent, not defaulted to
    allowed. The mapper has no code path that writes a ``can_call`` status
    without a :class:`~reachagent.execution.firer.FireResult` in hand.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from reachagent.execution.firer import ReadOnlyFirstError, RequestFirer
from reachagent.execution.scope import OutOfScopeError
from reachagent.graph.nodes import Endpoint, FindingStatus, Object, Parameter, Protocol
from reachagent.graph.store import ReachabilityGraph
from reachagent.identity.store import IdentityStore

# HTTP methods recon may fire during surface mapping. Everything else is
# state-changing and gated by read-only-first (§10) — mirrors the firer's own
# read-only set, kept here so recon refuses *before* even handing it to the firer.
_READ_ONLY_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})

# {placeholder} segments in a templated path (e.g. /users/v1/{username}).
_PATH_PLACEHOLDER = re.compile(r"\{([^}]+)\}")


@dataclass(frozen=True)
class ObjectSpec:
    """A declared object an endpoint returns (recon input)."""

    type: str
    sensitivity_tier: int = 0


@dataclass(frozen=True)
class ParameterSpec:
    """A declared parameter of an endpoint (recon input)."""

    name: str
    location: str


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
        """Load a surface inventory from a YAML file (see config/vampi-surface.yaml)."""
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
                ParameterSpec(name=p["name"], location=p["location"])
                for p in entry.get("parameters", [])
            )
            returns = tuple(
                ObjectSpec(type=o["type"], sensitivity_tier=int(o.get("sensitivity_tier", 0)))
                for o in entry.get("returns", [])
            )
            endpoints.append(
                EndpointSpec(
                    method=entry["method"],
                    path=entry["path"],
                    content_type=entry.get("content_type"),
                    state_changing=bool(entry.get("state_changing", False)),
                    parameters=params,
                    returns=returns,
                    sample_path_values=dict(entry.get("sample_path_values", {})),
                )
            )
        return cls(endpoints=tuple(endpoints))


@dataclass(frozen=True)
class MapSummary:
    """Coverage counts from a mapping run — cheap reporting/test surface."""

    endpoints: int
    parameters: int
    objects: int
    can_call_probed: int
    can_call_skipped_state_changing: int
    can_call_skipped_untemplated: int


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
                    protocol=Protocol.REST,
                )
            )
            for param in ep.parameters:
                self._graph.add_parameter(
                    endpoint_node, Parameter(name=param.name, location=param.location)
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
                    protocol=Protocol.REST,
                )
            )
            url = f"{self._base_url}{concrete}"
            for name in self._identities.names():
                identity_node = self._graph.add_identity(name, self._identities.identity(name))
                status = self._probe_one(name, identity_node, ep.method, endpoint_node, url)
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

    def run(self, spec: SurfaceSpec) -> MapSummary:
        """Full recon pass: materialize structure, then confirm ``can_call``."""
        self.map_structure(spec)
        return self.probe_can_call(spec)

    # -- internals --------------------------------------------------------

    def _probe_one(
        self,
        identity: str,
        identity_node: str,
        method: str,
        endpoint_node: str,
        url: str,
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
            result = self._firer.fire(identity, method, url, headers=headers)
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
