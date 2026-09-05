"""The LLM adversarial review — CLAUDE.md's second, independent non-blocking layer.

A reference SAST platform's real capella review/confirm/critic prompts
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
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from enum import StrEnum

from ..core.errors import AllProvidersFailedError
from ..core.model_router import CompletionRequest, ModelRouter
from ..graph.model import ReachabilityGraph
from .confidence import ConfidenceScore

_VALID_PROOF_LEVELS = frozenset({"L1", "L2", "L3", "L4"})

_SYSTEM_PROMPT = """You are an independent adversarial reviewer of a security finding.

Assume the finding is a false positive by default. Your job is to disprove it.
Evaluate the claim based ONLY on the vuln_class/target/param identity and the raw
captured evidence shown below. You are NOT shown the finder's own description or
counterevidence text - it may be hallucinated, so do not ask for it and do not
assume anything it might have said.

Reply with a single JSON object and nothing else:
{"verdict": "confirmed" | "ruled_out" | "open_proof_gap",
 "proof_level": "L1" | "L2" | "L3" | "L4",
 "reasoning": "one or two sentences, grounded only in the evidence shown"}

- "confirmed": the evidence shown directly demonstrates the claimed vulnerability.
- "ruled_out": the evidence shown does not support the claim, or actively
  contradicts it (e.g. the excerpt is not present in the evidence, or the
  evidence shows a control working correctly).
- "open_proof_gap": the evidence is suggestive but insufficient to confirm or
  rule out - name the specific gap in your reasoning.
- proof_level is your assessment of how far the evidence goes, independent of
  verdict (L1 = anomaly only, L2 = confirmed but low-value, L3 = real impact,
  L4 = durable/systemic)."""


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


def _extract_json_object(text: str) -> dict[str, object] | None:
    stripped = text.strip()
    start = stripped.find("{")
    end = stripped.rfind("}")
    if start == -1 or end == -1 or end <= start:
        return None
    try:
        parsed = json.loads(stripped[start : end + 1])
    except json.JSONDecodeError:
        return None
    return parsed if isinstance(parsed, dict) else None


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
) -> ReviewResult:
    """Run the independent review for one finding and return its verdict.

    Never raises: a total provider failure or an unparseable response
    degrades to ``open_proof_gap`` at the finding's unadjusted score rather
    than crashing the confirmation pipeline or fabricating a verdict.
    """
    node = graph.node(finding_id)
    try:
        response = router.complete(
            role,
            CompletionRequest(system=_SYSTEM_PROMPT, prompt=_build_user_prompt(node)),
        )
    except AllProvidersFailedError:
        return _fallback("review unavailable: every provider failed", confidence.score)

    parsed = _extract_json_object(response.text)
    if parsed is None:
        return _fallback("review response was not valid JSON", confidence.score)

    raw_verdict = str(parsed.get("verdict", ""))
    if raw_verdict not in {v.value for v in ReviewVerdict}:
        return _fallback(
            f"review returned an unrecognized verdict: {raw_verdict!r}", confidence.score
        )
    verdict = ReviewVerdict(raw_verdict)

    proof_level = str(parsed.get("proof_level", ""))
    if proof_level not in _VALID_PROOF_LEVELS:
        proof_level = "L1"

    adjusted_score = max(0, min(100, confidence.score + _VERDICT_ADJUSTMENT[verdict]))
    return ReviewResult(
        verdict=verdict,
        proof_level=proof_level,
        reasoning=str(parsed.get("reasoning", "")),
        adjusted_score=adjusted_score,
    )
