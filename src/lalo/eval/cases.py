"""Benchmark cases: ground-truth vulnerability classes, scored against a real graph.

Reference reads for this phase (all five, real source). A reference
toolkit's own ``benchmarks/eval.py`` (951 lines, read in full) is a
multiple-choice cybersecurity-knowledge quiz harness (SecEval, CyberMetric,
CTI-Bench) grading an LLM's static answers against a fixed "Solution"
field — a fundamentally different task from scoring whether a live scan
actually found real vulnerabilities planted in a running target, so its
per-benchmark answer-parsing functions are not adopted; only the generic
shape ("correct / total as a percentage," F1 for a classification-style
sub-benchmark) is a reasonable, non-reference-specific idea. A reference
agent's own ``benchmarks/README.md`` documents a CTF-style benchmark (104
challenges, binary solved/unsolved, 96% success rate) with no
precision/false-positive measurement at all, since a flag-capture format has
no "nothing here" case to score — confirming CLAUDE.md's own more rigorous
design choice (recall AND precision, not just a binary win rate) is a
deliberate improvement, not an oversight. A reference platform's own
``pipeline-testing`` prompt fixtures (read directly) are hermetic,
deterministic prompt scripts used to exercise pipeline mechanics without a
live LLM's non-determinism — independently confirming the pattern this
project's own test suite already uses throughout (a scripted/fake provider
standing in for a real model call), which the harness's own tests below
follow again rather than adopting anything new.

Findings are already graph nodes (Phase 7/12) with a computed confidence
score (Phase 12b), so scoring a case is a read over already-existing data —
:func:`run_case` reuses :func:`~lalo.report.collect.collect_findings`
rather than re-deriving anything from the graph directly.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..graph.model import ReachabilityGraph
from ..report.collect import collect_findings


@dataclass(frozen=True)
class BenchmarkCase:
    name: str
    description: str
    ground_truth_classes: frozenset[str]


@dataclass(frozen=True)
class CaseResult:
    case: BenchmarkCase
    found_classes: frozenset[str]
    confidence_by_class: dict[str, int]


def run_case(case: BenchmarkCase, graph: ReachabilityGraph) -> CaseResult:
    """Score ``case`` against whatever findings actually landed on ``graph``.

    Vuln classes are compared case-insensitively (matching
    :mod:`lalo.report.coverage`'s own simple exact-match convention, not a
    fuzzy phrasing table). A class reported more than once keeps its
    highest confidence score.
    """
    confidence_by_class: dict[str, int] = {}
    for record in collect_findings(graph):
        vuln_class = record.vuln_class.strip().lower()
        if not vuln_class:
            continue
        best = confidence_by_class.get(vuln_class, -1)
        confidence_by_class[vuln_class] = max(best, record.confidence.score)
    return CaseResult(
        case=case,
        found_classes=frozenset(confidence_by_class),
        confidence_by_class=confidence_by_class,
    )
