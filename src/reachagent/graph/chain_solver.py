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

from reachagent.graph.nodes import Identity, Session
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
        self._graph = graph
        self._path_budget = path_budget
        self._budgets: dict[str, int] = {}

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
        if self.budget_remaining(path_id) <= 0:
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

        candidates = self._unexplored(target_identity)
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

    # -- internals --------------------------------------------------------

    def _unexplored(self, identity_node: str) -> list[tuple[str, str]]:
        """All (identity_node, endpoint_node) pairs with no can_call verdict yet."""
        explored = {ep for id_, ep, _ in self._graph.can_call_edges() if id_ == identity_node}
        return [
            (identity_node, ep) for ep, _ in sorted(self._graph.endpoints()) if ep not in explored
        ]

    def _consume(self, path_id: str, n: int = 1) -> None:
        self._budgets[path_id] = max(0, self.budget_remaining(path_id) - n)
