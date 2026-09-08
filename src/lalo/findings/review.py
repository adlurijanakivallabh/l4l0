"""The LLM adversarial review — CLAUDE.md's second, independent non-blocking layer.

A reference SAST platform's real review/confirm/critic prompt trio
(``review.prompt.hbs``, ``confirm.prompt.hbs``, ``critic.prompt.hbs``, all
read in full in Phase 12a) converge on one instruction worth adopting
near-verbatim: "Assume every finding is a false positive by default...
Evaluate the claim based ONLY on the code and the raw claim itself.
Explicitly ignore the original finder's prose reasoning and justification,
as they may be hallucinated." L4L0's version of "the code" is the finding's
real captured evidence; its version of "the raw claim" is the bare
vuln_class/target/param identity — never the finder's own ``description`` or
``counterevidence`` text, which is deliberately withheld from this prompt
for exactly the reason that reference states.

Diverges from that reference in scope and structure: its 13-rule
static-analysis checklist (SIMD padding, file-path coherence, resource-
exhaustion DoS) is written for a source-code-under-audit model L4L0 doesn't
have (a running web/API/network/cloud target, not a repository) and isn't
ported. The three-outcome vocabulary (confirmed/ruled_out/open_proof_gap)
comes from CLAUDE.md itself, which already names it — matching a different
reference's own real ``counterevidence.md`` three-state model
(confirmed/ruled_out/open_proof_gap, adopted directly back in Phase 11's
``closure-discipline`` skill), so this review step is the code-side
implementation of a vocabulary the skill library already teaches the agent
to use on itself.

A verdict only ever adjusts :mod:`~lalo.findings.confidence`'s score by a
fixed, transparent delta — it never sets the score directly (an LLM-picked
arbitrary number would undermine the "transparent" part) and never removes
the finding, matching CLAUDE.md's "neither layer ever removes a finding."
A total provider failure (every provider in the review role's chain down)
degrades to ``open_proof_gap`` rather than crashing the reporting pipeline
or silently claiming a verdict that was never actually reached.

:func:`run_adversarial_review` persists its :class:`ReviewResult` onto the
finding's own graph node (via the existing, already-merging
:meth:`~lalo.graph.model.ReachabilityGraph.add_node`, reused rather than
adding a new graph-mutation method for this) before returning it — a real
gap this closes, not an original design choice: nothing else in the
codebase ever wrote a review verdict back onto a node, so
:mod:`lalo.report.collect`'s ``review_verdict``/``review_proof_level``
fields existed on every :class:`~lalo.report.collect.FindingRecord` but
could never actually be populated by a real review, only ever default to
``None``. This is the one and only place a verdict is written, so
:mod:`lalo.report.collect` reading it back is a plain field read, not a
second source of truth to keep in sync.

A fresh re-check against a studied reference agent, of this same confirmation-oracle territory,
confirmed its own gate-shaped export mechanism is NOT adoptable (a hard
drop for three whole status classes before its primary machine-consumable
artifact — exactly what this module's own non-blocking design exists to
avoid), but its differently-framed multi-persona pattern transplants
cleanly as a purely additive extra signal: ``run_adversarial_review``'s
opt-in ``second_opinion`` runs a SECOND, differently-lensed review
(``review_second_opinion.txt``) and applies a small, fixed, always-positive
bonus only on agreement — genuine independent corroboration, never a
second gate, never a way to score a finding lower than the primary review
alone would have.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, replace
from enum import StrEnum
from pathlib import Path

from ..core.errors import AllProvidersFailedError
from ..core.json_response import extract_json_object
from ..core.model_router import CompletionRequest, ModelRouter
from ..graph.model import NodeKind, ReachabilityGraph
from ..prompts import render_prompt
from .confidence import ConfidenceScore

_VALID_PROOF_LEVELS = frozenset({"L1", "L2", "L3", "L4"})
# review.txt defines L2-L4 purely in terms of a CONFIRMED finding ("confirmed
# but low-value" / "real impact" / "durable/systemic") - pairing one of these
# with a ruled_out/open_proof_gap verdict contradicts the reviewer's own
# stated scale, not a legitimate independent reading of "how far the
# evidence goes." See _compute_review's use below.
_CONFIRMED_ONLY_PROOF_LEVELS = frozenset({"L2", "L3", "L4"})
# One real retry after a single malformed/unparseable turn from an otherwise-
# healthy provider - never applied to AllProvidersFailedError (the router has
# already exhausted its own failover chain by the time that reaches here, so
# retrying would just repeat the same failure).
_MAX_ATTEMPTS = 2
# Opt-in second opinion (run_adversarial_review's own second_opinion=): a
# fixed, always-positive bonus when a second, differently-framed reviewer
# (review_second_opinion.txt's production-viability-skeptic lens, distinct
# from the primary evidence-authenticity lens) independently reaches the
# SAME verdict - genuine cross-lens corroboration. Never a penalty for
# disagreement: this is an additional non-blocking signal, never a second
# gate, so the worst case is simply "no bonus," never a lower score than the
# primary review alone would have produced.
_SECOND_OPINION_AGREEMENT_BONUS = 5


class ReviewVerdict(StrEnum):
    CONFIRMED = "confirmed"
    RULED_OUT = "ruled_out"
    OPEN_PROOF_GAP = "open_proof_gap"


_VERDICT_ADJUSTMENT = {
    ReviewVerdict.CONFIRMED: 10,
    ReviewVerdict.OPEN_PROOF_GAP: -20,
    ReviewVerdict.RULED_OUT: -50,
}


@dataclass(frozen=True)
class ReviewResult:
    verdict: ReviewVerdict
    proof_level: str
    reasoning: str
    adjusted_score: int


def _build_user_prompt(node: dict[str, object]) -> str:
    payload = {
        "vuln_class": node.get("vuln_class"),
        "target": node.get("target"),
        "param": node.get("param"),
        "evidence": node.get("evidence", []),
        "evidence_excerpt": node.get("evidence_excerpt"),
        "evidence_grounded": node.get("evidence_grounded"),
        "cvss_severity": node.get("cvss_severity"),
    }
    return "FINDING TO REVIEW:\n" + json.dumps(payload, indent=2, default=str)


def _fallback(reasoning: str, score: int) -> ReviewResult:
    return ReviewResult(
        verdict=ReviewVerdict.OPEN_PROOF_GAP,
        proof_level="L1",
        reasoning=reasoning,
        adjusted_score=score,
    )


def run_adversarial_review(
    graph: ReachabilityGraph,
    finding_id: str,
    confidence: ConfidenceScore,
    router: ModelRouter,
    *,
    role: str = "review",
    prompt_overrides_dir: Path | None = None,
    second_opinion: bool = False,
) -> ReviewResult:
    """Run the independent review for one finding, persist it, and return the verdict.

    ``role`` selects the :class:`~lalo.core.model_router.ModelRouter` chain
    (which provider serves this call) — a different axis from the *prompt*
    template, which is always the ``review`` role in
    :mod:`lalo.prompts` regardless of which provider chain answers it.
    ``prompt_overrides_dir``, if given, lets an operator supply their own
    ``review.txt`` (falls back to the built-in on any validation failure).

    ``second_opinion`` (opt-in, off by default — doubles this call's review-
    role LLM cost per finding) runs a SECOND, differently-framed review
    (``review_second_opinion.txt``'s production-viability-skeptic lens,
    distinct from the primary evidence-authenticity lens) and applies
    :data:`_SECOND_OPINION_AGREEMENT_BONUS` only when it independently
    reaches the same verdict — disagreement never lowers the score below
    what the primary review alone produced, matching CLAUDE.md's
    non-blocking-layers design (an additional corroboration signal, never a
    second gate).

    Never raises: a total provider failure or an unparseable response
    degrades to ``open_proof_gap`` at the finding's unadjusted score rather
    than crashing the confirmation pipeline or fabricating a verdict. Either
    way, the result is written onto ``finding_id``'s own graph node before
    returning, so a report generated from ``graph`` afterward can render it.
    """
    result = _compute_review(graph, finding_id, confidence, router, role, prompt_overrides_dir)
    attrs: dict[str, object] = {
        "review_verdict": result.verdict.value,
        "review_proof_level": result.proof_level,
        "review_reasoning": result.reasoning,
    }
    if second_opinion:
        second = _compute_review(
            graph,
            finding_id,
            confidence,
            router,
            role,
            prompt_overrides_dir,
            prompt_role="review_second_opinion",
        )
        attrs["second_opinion_verdict"] = second.verdict.value
        attrs["second_opinion_reasoning"] = second.reasoning
        if second.verdict == result.verdict:
            boosted = min(100, result.adjusted_score + _SECOND_OPINION_AGREEMENT_BONUS)
            result = replace(result, adjusted_score=boosted)
    graph.add_node(finding_id, NodeKind.FINDING, **attrs)
    return result


def _parse_review_response(text: str) -> tuple[dict[str, object] | None, str]:
    """Parse and validate one response's verdict field.

    Returns ``(parsed, "")`` for a response with a recognized verdict, or
    ``(None, reason)`` otherwise - ``reason`` becomes the eventual fallback's
    reasoning if every attempt fails.
    """
    parsed = extract_json_object(text)
    if parsed is None:
        return None, "review response was not valid JSON"
    raw_verdict = str(parsed.get("verdict", ""))
    if raw_verdict not in {v.value for v in ReviewVerdict}:
        return None, f"review returned an unrecognized verdict: {raw_verdict!r}"
    return parsed, ""


def _compute_review(
    graph: ReachabilityGraph,
    finding_id: str,
    confidence: ConfidenceScore,
    router: ModelRouter,
    role: str,
    prompt_overrides_dir: Path | None,
    *,
    prompt_role: str = "review",
) -> ReviewResult:
    node = graph.node(finding_id)
    system_prompt = render_prompt(prompt_role, overrides_dir=prompt_overrides_dir)
    user_prompt = _build_user_prompt(node)

    parsed: dict[str, object] | None = None
    reason = ""
    for _attempt in range(_MAX_ATTEMPTS):
        try:
            response = router.complete(
                role, CompletionRequest(system=system_prompt, prompt=user_prompt)
            )
        except AllProvidersFailedError:
            return _fallback("review unavailable: every provider failed", confidence.score)
        parsed, reason = _parse_review_response(response.text)
        if parsed is not None:
            break

    if parsed is None:
        return _fallback(reason, confidence.score)

    verdict = ReviewVerdict(str(parsed["verdict"]))

    proof_level = str(parsed.get("proof_level", ""))
    if proof_level not in _VALID_PROOF_LEVELS:
        proof_level = "L1"
    elif verdict != ReviewVerdict.CONFIRMED and proof_level in _CONFIRMED_ONLY_PROOF_LEVELS:
        proof_level = "L1"

    adjusted_score = max(0, min(100, confidence.score + _VERDICT_ADJUSTMENT[verdict]))
    return ReviewResult(
        verdict=verdict,
        proof_level=proof_level,
        reasoning=str(parsed.get("reasoning", "")),
        adjusted_score=adjusted_score,
    )
