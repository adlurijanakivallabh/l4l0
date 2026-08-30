"""Chain Solver — spawn-and-requery over the finding layer (plan §8; Phase 2 Task 4).

The uniform mechanism §8 describes: any confirmed finding that yields a new
credential or elevates an identity's effective privilege triggers exactly one
action — spawn the Session/Identity node (if needed) and re-run reachability
queries from that identity. The same entry point handles both cases:

* **Credential-yielding finding** (e.g. XSS → derived admin session, SSRF →
  cloud-metadata token): caller passes a ``Session`` or ``Identity`` to spawn;
  the solver adds the node, writes the ``derived_credential`` edge, and returns
  the unexplored ``(identity, endpoint)`` pairs for the new identity.
* **Self-escalation** (e.g. mass-assignment privilege escalation — no new node,
  the acting identity's own effective privilege changed): caller passes
  ``spawn=None``; the solver returns the unexplored pairs for the acting identity.

No per-class-pair branch exists in either path — the only branch is on whether
a spawned credential was provided, which is a structural fact about the finding,
not a vuln-class label.

Termination is enforced by skipping any ``(identity, endpoint)`` pair that
already has a ``can_call`` verdict in the graph (written by the execution layer
or a prior solver pass), so nothing is retested. The §11 per-path budget cap
is tracked per ``path_id``; ``advance`` returns ``[]`` once the budget is
exhausted, preventing unbounded re-querying.
"""

from __future__ import annotations

from reachagent.graph.nodes import FindingStatus, Identity, Session
from reachagent.graph.store import ReachabilityGraph, identity_id

_DEFAULT_PATH = "default"


class ChainSolver:
    """Spawn-and-requery engine over the finding-relationship layer (§8).

    Operates on the graph store directly; the actual firing and oracle calls
    remain in the Explorer/Validator tool layer. The solver's job is:

    1. Spawn a ``Session``/``Identity`` node from a credential-yielding finding
       and write the ``derived_credential`` edge (or skip spawning for a
       self-escalation).
    2. Return the unexplored ``(identity_node, endpoint_node)`` pairs for the
       relevant identity — the Coordinator's next test candidates.
    3. Enforce termination (skip already-explored pairs) and the §11 budget cap.
    """

    def __init__(self, graph: ReachabilityGraph, *, path_budget: int = 40) -> None:
        if path_budget < 1:
            raise ValueError("path_budget must be positive")
        self._graph = graph
        self._path_budget = path_budget
        self._budgets: dict[str, int] = {}
        self._spawned_by_path: dict[str, set[str]] = {}
        # Persisted advances are remembered separately from this process's
        # mutable ledger.  A live coordinator may deliberately explore two
        # derived identities from one finding; after a restart the persisted
        # advance is a completed decision and must not be replayed.
        self._advanced_findings: dict[str, set[str]] = {}
        self._restored_advanced_findings: dict[str, set[str]] = {}

    # -- public API -------------------------------------------------------

    def advance(
        self,
        finding_node: str,
        *,
        acting_identity: str,
        spawn: Session | Identity | None = None,
        spawn_name: str | None = None,
        path_id: str = _DEFAULT_PATH,
    ) -> list[tuple[str, str]]:
        """Uniform spawn-and-requery entry point (§8).

        Parameters
        ----------
        finding_node:
            The committed ``Finding`` node id that triggered this advance.
        acting_identity:
            The identity node id that produced the finding (used for
            self-escalation and as the ``identity_ref`` anchor).
        spawn:
            A ``Session`` or ``Identity`` dataclass to spawn from the finding
            (credential-yielding case), or ``None`` for a self-escalation where
            the acting identity's own edges are re-queried.
        spawn_name:
            Required when ``spawn`` is an ``Identity`` — the name key used by
            :func:`~reachagent.graph.store.identity_id`.
        path_id:
            Budget scope; defaults to ``"default"``.

        Returns
        -------
        list[tuple[str, str]]
            ``(identity_node, endpoint_node)`` pairs with no existing
            ``can_call`` verdict — the Coordinator's next test candidates.
            Returns ``[]`` when the budget is exhausted.
        """
        finding = next(
            (data for node, data in self._graph.findings() if node == finding_node),
            None,
        )
        if finding is None or finding.status is not FindingStatus.CONFIRMED_VIOLATION:
            raise ValueError("advance requires a committed confirmed_violation Finding")
        if self.budget_remaining(path_id) <= 0:
            return []
        if finding_node in self._restored_advanced_findings.get(path_id, ()):
            return []

        if spawn is None:
            # Self-escalation: re-query the acting identity's own edges.
            target_identity = acting_identity
        elif isinstance(spawn, Session):
            spawned = self._graph.add_session(spawn)
            self._graph.add_derived_credential(finding_node, spawned)
            target_identity = identity_id(spawn.identity_ref)
        else:
            # Identity spawn (e.g. synthetic principal from SSRF cloud-metadata token).
            if spawn_name is None:
                raise ValueError("spawn_name is required when spawning an Identity")
            spawned = self._graph.add_identity(spawn_name, spawn)
            self._graph.add_derived_credential(finding_node, spawned)
            target_identity = spawned

        if spawn is not None:
            self._spawned_by_path.setdefault(path_id, set()).add(target_identity)
        candidates = self._unexplored(target_identity)
        self._advanced_findings.setdefault(path_id, set()).add(finding_node)
        self._consume(path_id, 1)
        return candidates

    def link(self, from_finding: str, to_finding: str) -> None:
        """Persist an ``enables`` edge between two confirmed findings (§8).

        Records that ``from_finding``'s output made ``to_finding`` possible —
        the chain edge that turns two disconnected findings into one connected
        attack path. Asserted by querying ``graph.enables_edges()`` /
        ``graph.chain_paths()``, not by report text.
        """
        self._graph.add_enables(from_finding, to_finding)

    def budget_remaining(self, path_id: str = _DEFAULT_PATH) -> int:
        """Remaining budget for ``path_id`` (initialised to ``path_budget`` on first call)."""
        if path_id not in self._budgets:
            self._budgets[path_id] = self._path_budget
        return self._budgets[path_id]

    def spawned_identity_nodes(self, path_id: str = _DEFAULT_PATH) -> frozenset[str]:
        """Identity nodes spawned by this solver on ``path_id`` in this run.

        The ledger is deliberately solver-local: durable ``Provenance.DERIVED``
        marks historical graph state, while this set identifies fresh chain hops
        for the Coordinator's current run.
        """
        return frozenset(self._spawned_by_path.get(path_id, ()))

    def consume_budget(self, path_id: str = _DEFAULT_PATH, units: int = 1) -> bool:
        """Reserve ordinary Coordinator work against this solver-owned budget.

        ``advance`` consumes its own chain-solver operation. The Coordinator uses
        this same ledger for each selected Explorer/Validator dispatch, so no
        second counter exists and a path cannot run past its cap.
        """
        if units < 1 or self.budget_remaining(path_id) < units:
            return False
        self._consume(path_id, units)
        return True

    # -- internals --------------------------------------------------------

    # -- run persistence (D6 durable resume) ---------------------------------

    def snapshot(self) -> dict[str, object]:
        """The solver's durable ledgers — budgets, spawned nodes, and advances.

        The ONLY solver state that crosses a restart boundary. Everything else is
        re-derived from the graph on load (the graph carries the findings, edges,
        and attributes). ``spawned_by_path`` values are sorted for determinism so
        a dump → load → dump round-trips byte-identically.
        """
        return {
            "budgets": dict(self._budgets),
            "spawned_by_path": {k: sorted(v) for k, v in self._spawned_by_path.items()},
            "advanced_findings": {k: sorted(v) for k, v in self._advanced_findings.items()},
        }

    def restore(self, state: object) -> None:
        """Restore the persisted ledgers onto a fresh solver (resume, D6).

        ``budgets`` are restored verbatim so a path continues from its remaining
        count; ``spawned_by_path`` is restored so §4 scoring keeps weighting the
        chain hops already spawned in the prior run.
        """
        if not isinstance(state, dict):
            return
        budgets = state.get("budgets", {})
        spawned = state.get("spawned_by_path", {})
        if isinstance(budgets, dict):
            self._budgets = {str(k): int(v) for k, v in budgets.items()}
        if isinstance(spawned, dict):
            self._spawned_by_path = {str(k): set(str(x) for x in v) for k, v in spawned.items()}
        advanced = state.get("advanced_findings", {})
        if isinstance(advanced, dict):
            self._advanced_findings = {
                str(k): set(str(x) for x in v) for k, v in advanced.items() if isinstance(v, list)
            }
            self._restored_advanced_findings = {
                key: set(values) for key, values in self._advanced_findings.items()
            }

    def recover_derived(
        self,
        target_identity: str,
        *,
        path_id: str = _DEFAULT_PATH,
    ) -> list[tuple[str, str]]:
        """RECOVER pass: re-surface unexplored pairs for a persisted derived identity.

        Continue-not-replay (D3): a derived credential whose spawn/edge writes
        are already persisted in the loaded graph gets its unexplored ``(identity,
        endpoint)`` pairs re-queried and is marked spawned for §4 scoring — but the
        persisted Session/Identity node and ``derived_credential`` edge are NOT
        re-written, and an already-marked identity is skipped. ``advance`` is the
        fresh-run path; this is the resume path (advance-lite by design). Returns
        ``[]`` when the identity was already advanced or the budget is exhausted.
        """
        if self.budget_remaining(path_id) <= 0:
            return []
        if target_identity in self._spawned_by_path.get(path_id, ()):
            return []  # already advanced in this (resumed) run — no replay
        self._spawned_by_path.setdefault(path_id, set()).add(target_identity)
        candidates = self._unexplored(target_identity)
        self._consume(path_id, 1)
        return candidates

    def _unexplored(self, identity_node: str) -> list[tuple[str, str]]:
        """All (identity_node, endpoint_node) pairs with no can_call verdict yet."""
        explored = {ep for id_, ep, _ in self._graph.can_call_edges() if id_ == identity_node}
        return [
            (identity_node, ep) for ep, _ in sorted(self._graph.endpoints()) if ep not in explored
        ]

    def _consume(self, path_id: str, n: int = 1) -> None:
        self._budgets[path_id] = max(0, self.budget_remaining(path_id) - n)
