"""Coordinator tool subset (plan §13, §4).

Owns the graph; decides what to test next, prioritizing chain-completing tests
over fresh exploration via the §4 scoring rule. Sonnet-tier (§4). Never calls
``fire_request`` or ``run_oracle`` — only these three tools (§13, CLAUDE.md
non-negotiable). Phase 1 scaffolding — signatures only, no logic (§15).

The Coordinator itself arrives in Phase 5 (§15); its tools are stubbed here so
the manifest is complete and a human can drive the same contracts by hand (§13).
"""

from __future__ import annotations


def query_graph(filter: object) -> None:
    """Pull untested edges, recent findings, spawned identities (§13)."""
    raise NotImplementedError


def score_and_select(candidates: object) -> None:
    """Apply the §4 scoring rule, return the next test (§13).

    score = object_sensitivity_tier×3 + is_newly_spawned_identity×5
            + sink_severity_weight − prior_attempts_in_neighborhood  (§4)
    """
    raise NotImplementedError


def check_budget(path_id: str) -> None:
    """Enforce the per-path budget cap (~40 tool calls / fixed $ ceiling) (§11, §13)."""
    raise NotImplementedError
