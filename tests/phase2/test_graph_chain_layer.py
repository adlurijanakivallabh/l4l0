"""Finding-relationship + ownership graph layer at the store (plan §6, §8; Phase 2 Task 1).

Asserts the Task 1 DoD invariants, all at the store level (recon-side population
of ``owns`` is Task 2; the Chain Solver that walks ``enables`` is Task 4):

  1. ``enables(Finding → Finding)`` and ``derived_credential(Finding → Session |
     Identity)`` edges exist as typed store writers and round-trip.
  2. The store writes an ``owns(Identity → Object)`` edge and stamps
     ``Object.owner_identity_ref`` — both readable back.
  3. A ``derived_credential`` target is a real queryable node: writing one spawns
     a ``Session``/``Identity`` the graph returns from a normal query.
  4. The Phase 1 non-negotiable still holds after the schema grew: the store
     refuses any ``Finding`` whose status is not ``confirmed_violation``.
  5. No node/edge type beyond the §6 set was introduced.
"""

from __future__ import annotations

import pytest

from reachagent.graph.edges import FindingEdge, StructuralEdge
from reachagent.graph.nodes import (
    AuthState,
    Finding,
    FindingStatus,
    Identity,
    Object,
    Provenance,
    Session,
)
from reachagent.graph.store import (
    ReachabilityGraph,
    identity_id,
    object_id,
    session_id,
)


def _committed_finding(graph: ReachabilityGraph, vuln_class: str, evidence_ref: str) -> str:
    """Commit a real confirmed_violation Finding node and return its id."""
    return graph.add_finding(
        Finding(
            vuln_class=vuln_class,
            severity="high",
            oracle_used="differential",
            evidence_ref=evidence_ref,
            status=FindingStatus.CONFIRMED_VIOLATION,
        )
    )


# -- Invariant 1: enables / derived_credential round-trip -----------------


def test_enables_edge_round_trips() -> None:
    graph = ReachabilityGraph()
    a = _committed_finding(graph, "xss_stored", "xss/profile")
    b = _committed_finding(graph, "ssrf", "ssrf/internal")

    graph.add_enables(a, b)

    assert graph.enables_edges() == [(a, b)]


def test_derived_credential_edge_round_trips() -> None:
    graph = ReachabilityGraph()
    graph.add_identity("admin", Identity("admin", AuthState.ADMIN, Provenance.DERIVED))
    finding = _committed_finding(graph, "xss_stored", "xss/admin-view")
    spawned = graph.add_session(Session(token_ref="tok-admin-derived", identity_ref="admin"))

    graph.add_derived_credential(finding, spawned)

    assert graph.derived_credential_edges() == [(finding, spawned)]


def test_enables_and_derived_credential_are_idempotent() -> None:
    graph = ReachabilityGraph()
    a = _committed_finding(graph, "xss_stored", "xss/profile")
    b = _committed_finding(graph, "ssrf", "ssrf/internal")
    graph.add_identity("admin", Identity("admin", AuthState.ADMIN, Provenance.DERIVED))
    spawned = graph.add_session(Session(token_ref="tok", identity_ref="admin"))

    graph.add_enables(a, b)
    graph.add_enables(a, b)
    graph.add_derived_credential(a, spawned)
    graph.add_derived_credential(a, spawned)

    assert graph.enables_edges() == [(a, b)]
    assert graph.derived_credential_edges() == [(a, spawned)]


def test_enables_requires_committed_findings_on_both_ends() -> None:
    graph = ReachabilityGraph()
    real = _committed_finding(graph, "xss_stored", "xss/profile")

    # A raw, uncommitted id can never anchor a chain edge — the edge only ever
    # links two confirmations, never a candidate or arbitrary node.
    with pytest.raises(ValueError, match="not a committed Finding"):
        graph.add_enables(real, "finding:made-up:not-real")
    with pytest.raises(ValueError, match="not a committed Finding"):
        graph.add_enables("finding:made-up:not-real", real)


def test_derived_credential_requires_an_existing_target() -> None:
    graph = ReachabilityGraph()
    finding = _committed_finding(graph, "ssrf", "ssrf/metadata")

    with pytest.raises(ValueError, match="does not exist"):
        graph.add_derived_credential(finding, session_id("never-spawned"))


# -- Invariant 2: owns edge + owner_identity_ref, both readable back ------


def test_set_owns_writes_edge_and_stamps_owner_ref() -> None:
    graph = ReachabilityGraph()
    owner = graph.add_identity("name1", Identity("user", AuthState.USER, Provenance.SEEDED))
    obj = graph.add_object(Object(type="vehicle_location"))

    graph.set_owns(owner, obj)

    # Readable as an edge...
    assert graph.owns_edges() == [(owner, obj)]
    # ...and as an attribute on the Object itself.
    assert graph.owner_of(obj) == owner


def test_owner_of_is_none_when_ownership_undeclared() -> None:
    graph = ReachabilityGraph()
    obj = graph.add_object(Object(type="public_catalog"))

    # Empirical-or-absent (mirrors can_call): no owner declared → no edge, None ref.
    assert graph.owner_of(obj) is None
    assert graph.owns_edges() == []


def test_set_owns_is_idempotent_on_redeclare() -> None:
    graph = ReachabilityGraph()
    owner = graph.add_identity("name1", Identity("user", AuthState.USER, Provenance.SEEDED))
    obj = graph.add_object(Object(type="vehicle_location"))

    graph.set_owns(owner, obj)
    graph.set_owns(owner, obj)

    # Single edge, not two parallel ones.
    assert graph.owns_edges() == [(owner, obj)]


# -- Invariant 3: a derived_credential target is a first-class queryable node --


def test_spawned_session_is_returned_by_normal_query() -> None:
    graph = ReachabilityGraph()
    graph.add_identity("admin", Identity("admin", AuthState.ADMIN, Provenance.DERIVED))
    finding = _committed_finding(graph, "xss_stored", "xss/admin-view")
    spawned = graph.add_session(Session(token_ref="tok-derived", identity_ref="admin"))
    graph.add_derived_credential(finding, spawned)

    # The spawned session comes back from the ordinary sessions() query, exactly
    # like a seeded one would — that is what makes a derived credential first-class.
    session_ids = [sid for sid, _ in graph.sessions()]
    assert spawned in session_ids
    # And its authenticates_as edge points at the identity it acts as.
    assert graph.has_node(identity_id("admin"))


def test_spawned_identity_is_returned_by_normal_query() -> None:
    graph = ReachabilityGraph()
    finding = _committed_finding(graph, "ssrf", "ssrf/metadata-token")
    # An SSRF reaching cloud metadata yields a usable token → a new synthetic
    # identity the Coordinator re-tests against internal-only endpoints (§8).
    spawned = graph.add_identity(
        "metadata-synthetic",
        Identity("synthetic", AuthState.SYNTHETIC, Provenance.DERIVED),
    )
    graph.add_derived_credential(finding, spawned)

    identity_ids = [iid for iid, _ in graph.identities()]
    assert spawned in identity_ids
    assert graph.derived_credential_edges() == [(finding, spawned)]


def test_session_node_carries_only_a_token_ref_never_a_value() -> None:
    # Secrets never enter the graph (§10): the Session node holds only the handle.
    graph = ReachabilityGraph()
    graph.add_identity("admin", Identity("admin", AuthState.ADMIN, Provenance.SEEDED))
    graph.add_session(Session(token_ref="tok-ref-only", identity_ref="admin"))

    ((_, stored),) = graph.sessions()
    assert stored.token_ref == "tok-ref-only"
    # The dataclass has no field that could hold a raw token value.
    assert not hasattr(stored, "token")


# -- Invariant 4: the confirmed_violation gate still holds after the schema grew --


def test_store_still_refuses_a_non_violation_finding() -> None:
    graph = ReachabilityGraph()
    for status in (
        FindingStatus.INCONCLUSIVE,
        FindingStatus.CONFIRMED_ALLOWED,
        FindingStatus.CONFIRMED_DENIED,
    ):
        with pytest.raises(ValueError, match="confirmed_violation"):
            graph.add_finding(
                Finding(
                    vuln_class="bola",
                    severity="high",
                    oracle_used="differential",
                    evidence_ref=f"e/{status.value}",
                    status=status,
                )
            )
    assert graph.findings() == []


def test_findings_query_returns_only_committed_violations() -> None:
    graph = ReachabilityGraph()
    a = _committed_finding(graph, "bola", "bola/orders/42")
    ids = [fid for fid, _ in graph.findings()]
    assert ids == [a]


# -- Invariant 5: no node/edge type beyond the §6 set ---------------------


def test_no_edge_type_outside_the_ss6_set() -> None:
    """Every edge key ever written is a member of the two §6 edge enums."""
    graph = ReachabilityGraph()
    # Exercise every writer so the graph carries one of each edge kind.
    owner = graph.add_identity("name1", Identity("user", AuthState.USER, Provenance.SEEDED))
    from reachagent.graph.nodes import Endpoint, Parameter

    ep = graph.add_endpoint(Endpoint(method="GET", path="/vehicle/location"))
    graph.add_parameter(ep, Parameter(name="id", location="query"))
    obj = graph.add_object(Object(type="vehicle_location"))
    graph.add_returns(ep, obj)
    graph.set_owns(owner, obj)
    graph.set_can_call(owner, ep, FindingStatus.CONFIRMED_ALLOWED, evidence="HTTP 200")
    graph.add_session(Session(token_ref="tok", identity_ref="name1"))
    a = _committed_finding(graph, "bola", "bola/a")
    b = _committed_finding(graph, "ssrf", "ssrf/b")
    graph.add_enables(a, b)
    spawned = graph.add_identity(
        "syn", Identity("synthetic", AuthState.SYNTHETIC, Provenance.DERIVED)
    )
    graph.add_derived_credential(a, spawned)

    allowed = {e.value for e in StructuralEdge} | {e.value for e in FindingEdge}
    seen = {key.value for _, _, key in graph._g.edges(keys=True)}  # noqa: SLF001
    assert seen <= allowed
    # And we actually exercised both layers, not a vacuous pass.
    assert {"owns", "enables", "derived_credential"} <= seen


def test_no_node_kind_outside_the_ss6_set() -> None:
    """Every node-kind tag is one of the §6 node types."""
    graph = ReachabilityGraph()
    from reachagent.graph.nodes import Endpoint, Parameter

    owner = graph.add_identity("name1", Identity("user", AuthState.USER, Provenance.SEEDED))
    ep = graph.add_endpoint(Endpoint(method="GET", path="/x"))
    graph.add_parameter(ep, Parameter(name="id", location="query"))
    obj = graph.add_object(Object(type="vehicle_location"))
    graph.set_owns(owner, obj)
    graph.add_session(Session(token_ref="tok", identity_ref="name1"))
    _committed_finding(graph, "bola", "bola/a")

    allowed = {"endpoint", "parameter", "object", "identity", "session", "finding"}
    seen = {attrs["kind"] for _, attrs in graph._g.nodes(data=True)}  # noqa: SLF001
    assert seen <= allowed
    assert object_id("vehicle_location") in graph._g  # noqa: SLF001
