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

**Finding deduplication (v4 R3b) — investigated, not added.** Dynamic
re-hunt agents (one per derived-identity lead) can rediscover the same
underlying issue, which raised the question of whether exact-id matching
(below) is enough. Verified directly against every driver's own
``evidence_ref=f"orchestrator/..."`` construction: none embeds an
identity/session component, so two agents reconfirming the identical
issue always produce the identical ``evidence_ref`` and thus the identical
deterministic finding id — already caught by the exact-id check below. A
coarser fingerprint (vuln_class + first path segment) was prototyped and
adversarially reviewed; it was rejected because it collapses genuinely
DIFFERENT findings that share only a path (e.g. a PUT-IDOR and a
DELETE-IDOR on the same endpoint, or two different injectable parameters
on the same endpoint) — a false-positive drop is worse than the
theoretical duplicate it would have caught, especially since that
duplicate scenario turned out not to occur in practice.
"""

from __future__ import annotations

import dataclasses
import logging
import re

from reachagent.graph.store import ReachabilityGraph

_log = logging.getLogger(__name__)

_PATH_IN_EVIDENCE_REF = re.compile(r"(/[^\s?#]+)")


def extract_endpoint_path(evidence_ref: str, vuln_class: str) -> str:
    """Best-effort endpoint path recovered from an ``evidence_ref`` string,
    for ``report/renderer.py``'s evidence_ref -> audit-trail join (v4 R1b).

    Searches for a path AFTER the known ``vuln_class`` token, not the first
    "/..."-shaped substring in ``evidence_ref`` overall — most drivers'
    convention embeds the class name itself right after a source prefix
    (e.g. ``"orchestrator/sqli /api/users/1"``), and a naive first-match
    search would just re-match "/sqli" (the class name), never the actual
    endpoint path that follows it. Returns "" (not the raw evidence_ref) when
    no path is recoverable — callers that want a fallback key decide that
    for themselves, since "no path" and "the whole opaque ref" mean
    different things to the two callers here.
    """
    remainder = evidence_ref
    class_at = remainder.find(vuln_class)
    if class_at != -1:
        remainder = remainder[class_at + len(vuln_class) :]
    match = _PATH_IN_EVIDENCE_REF.search(remainder)
    return match.group(1) if match else ""


def merge_new_findings(source: ReachabilityGraph, target: ReachabilityGraph) -> list[str]:
    """Replay findings ``source`` has that ``target`` doesn't, plus their
    chain edges, via ``target``'s own public ``add_finding``/``add_enables``/
    ``add_derived_credential`` — so every write-time invariant (the
    ``CONFIRMED_VIOLATION`` gate, first) re-applies exactly as it would on a
    live scan. Returns the finding ids newly written to ``target`` (never
    ones ``target`` already had, whether from a prior merge or its own work).

    Disclosed precondition (adversarial review, Build Order 2c): if two
    SEPARATE calls each supply a finding that resolves to the same
    deterministic finding id but with different content (metadata/severity/
    confidence), the second call's content is silently dropped — whichever
    call happens to run first wins, permanently. This is not reachable
    through the current sole call site (``_run_phase3_concurrent`` scopes
    each vuln_class to exactly one concurrent specialist via
    ``_SPECIALIST_OF_CLASS``, so two children can never produce the same
    finding id today), but this function itself enforces no such guarantee —
    a future caller that violates that external invariant hits silent data
    loss. Logged (not raised) when detected, matching the
    ``derived_credential``-target-missing case below.
    """
    existing = dict(target.findings())
    new_ids: list[str] = []
    for fid, finding in source.findings():
        if fid in existing:
            if finding != existing[fid]:
                _log.warning(
                    "merge_new_findings: finding %r already present in the parent graph "
                    "with different content — keeping the existing version; the second, "
                    "differing confirmation was silently dropped",
                    fid,
                )
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
