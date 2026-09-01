"""Child-graph -> parent-graph merge (Build Order 2c).

Concurrent specialist children each run against their own deep-copied graph
snapshot (the plan's chosen default: per-child graph + merge at defined sync
points, not a lock around every NetworkX mutation — simpler, and avoids
retrofitting locking through every ``ReachabilityGraph`` call site for a
library, `networkx.MultiDiGraph`, that has none). This module is the "merge"
half of that contract.

Scoped deliberately to what a Phase-3 driver actually produces: a
``Finding`` (via ``seam.write`` -> ``write_finding`` -> ``add_finding``) plus
its chain edges (``enables``/``derived_credential``). Every driver read this
session writes findings only — none creates a new ``Host``/``Endpoint``/
``Session``/``Identity`` node (those are Phase 1/2 recon facts, already
present in the child's snapshot from before it was spawned). If a future
driver starts writing graph facts beyond findings, this module needs
extending — a disclosed scope limit, not a silent gap: ``merge_new_findings``
returns exactly the finding ids it merged, so a caller can tell precisely
what did (and didn't) make it across.

Both ``add_finding`` and ``add_enables``/``add_derived_credential`` are
already documented as idempotent by id/keyed-edge, so replaying the same
fact twice (across repeated merges of the same child) is always safe —
never a duplicate node or a duplicate parallel edge.
"""

from __future__ import annotations

import dataclasses
import logging

from reachagent.graph.store import ReachabilityGraph

_log = logging.getLogger(__name__)


def merge_new_findings(source: ReachabilityGraph, target: ReachabilityGraph) -> list[str]:
    """Replay findings ``source`` has that ``target`` doesn't, plus their
    chain edges, via ``target``'s own public ``add_finding``/``add_enables``/
    ``add_derived_credential`` — so every write-time invariant (the
    ``CONFIRMED_VIOLATION`` gate, first) re-applies exactly as it would on a
    live scan. Returns the finding ids newly written to ``target`` (never
    ones ``target`` already had, whether from a prior merge or its own work).
    """
    existing = {fid for fid, _ in target.findings()}
    new_ids: list[str] = []
    for fid, finding in source.findings():
        if fid in existing:
            continue
        # A shallow dataclass copy (with its own metadata dict) so the two
        # graphs never share a mutable Finding instance — findings are
        # write-once in practice, but this costs nothing and closes the door
        # on a future accidental cross-graph mutation.
        target.add_finding(dataclasses.replace(finding, metadata=dict(finding.metadata)))
        new_ids.append(fid)

    if not new_ids:
        return new_ids
    new_set = set(new_ids)
    for from_id, to_id in source.enables_edges():
        if from_id in new_set or to_id in new_set:
            target.add_enables(from_id, to_id)
    for from_id, spawned_node in source.derived_credential_edges():
        if from_id not in new_set and spawned_node not in new_set:
            continue
        if not target.has_node(spawned_node):
            # Disclosed scope limit: the spawned Session/Identity itself was
            # never replicated (a driver created a NEW one mid-Phase-3,
            # beyond this module's findings-only scope) -- skip this one
            # edge rather than crash the whole merge over it.
            _log.warning(
                "merge_new_findings: derived_credential target %r not present in "
                "the parent graph — skipping this edge (spawned mid-specialist, "
                "outside findings-only merge scope)",
                spawned_node,
            )
            continue
        target.add_derived_credential(from_id, spawned_node)
    return new_ids
