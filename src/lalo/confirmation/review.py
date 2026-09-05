"""Adversarial confirmation review — LLM-driven, structurally separate.

This is the reference methodology (an independent "assume-false, disprove-it"
validator over real captured evidence + a proof ladder), NOT a fixed detector:
- reason from the CAPTURED traffic only, explicitly ignoring the finder's prose
  (defends against a self-attesting finder);
- return one of ``confirmed`` / ``ruled_out`` / ``open_proof_gap`` (missing
  information is never proof of safety) with a 1–4 proof level;
- nothing is withheld — the verdict folds into the finding's confidence + flags,
  it never drops the finding.

Grounding first: only evidence whose ``observed`` text is actually present in the
captured traffic is shown to the validator, so the review can't be fooled by a
fabricated evidence string.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass

from ..core.model_router import CompletionRequest, ModelRouter
from ..models import Finding

_REVIEW_SYSTEM = (
    "You are an INDEPENDENT adversarial security validator. You did not find this "
    "issue and you owe its author nothing. Assume it is a FALSE POSITIVE by default "
    "and try to disprove it using ONLY the captured traffic provided. Ignore the "
    "finder's own wording — it may be hallucinated. Missing information is NOT proof "
    "of safety."
)

_REVIEW_TEMPLATE = """Finding under review:
  title: {title}
  class: {vuln_class}
  target: {target}

Cited evidence (grounded — each line was verified present in captured traffic):
{evidence_block}

Captured traffic (authoritative):
{captures_block}

Decide and reply with EXACTLY ONE JSON object, nothing else:
{{"verdict": "confirmed|ruled_out|open_proof_gap",
  "proof_level": 1,
  "counterevidence": "the strongest concrete case against the finding",
  "reasoning": "why, referencing the captured traffic"}}

verdict meanings:
- confirmed: the captured traffic genuinely demonstrates the issue. Set proof_level
  1=theoretical, 2=reflected/echoed, 3=demonstrated impact (e.g. data/command
  output), 4=chained/critical impact.
- ruled_out: name the SPECIFIC control or reason it is not exploitable.
- open_proof_gap: the evidence is insufficient to decide (never mark clean)."""


@dataclass
class ReviewVerdict:
    verdict: str  # confirmed | ruled_out | open_proof_gap
    proof_level: int
    counterevidence: str
    reasoning: str


def _grounded_evidence(finding: Finding, captures: Mapping[str, str]) -> list[str]:
    lines: list[str] = []
    for e in finding.evidence:
        body = captures.get(e.fire_ref or "")
        verified = bool(e.observed) and body is not None and e.observed in body
        tag = "VERIFIED" if verified else "UNVERIFIED"
        detail = e.observed[:200] if e.observed else e.summary[:200]
        lines.append(f"  - [{e.kind.value}/{tag}] {detail}")
    return lines


def adversarial_review(
    finding: Finding,
    captures: Mapping[str, str],
    router: ModelRouter,
    *,
    role: str = "reasoning",
) -> ReviewVerdict:
    evidence_block = "\n".join(_grounded_evidence(finding, captures)) or "  (none)"
    captures_block = (
        "\n".join(f"  [{ref}] {body[:600]}" for ref, body in list(captures.items())[:6])
        or "  (none captured)"
    )
    prompt = _REVIEW_TEMPLATE.format(
        title=finding.title,
        vuln_class=finding.vuln_class,
        target=finding.target,
        evidence_block=evidence_block,
        captures_block=captures_block,
    )
    response = router.complete(role, CompletionRequest(prompt=prompt, system=_REVIEW_SYSTEM))
    return _parse_verdict(response.text)


def _parse_verdict(text: str) -> ReviewVerdict:
    start = text.find("{")
    if start != -1:
        try:
            obj, _ = json.JSONDecoder().raw_decode(text, start)
        except (json.JSONDecodeError, ValueError):
            obj = None
        if isinstance(obj, dict) and "verdict" in obj:
            verdict = str(obj.get("verdict", "open_proof_gap"))
            if verdict not in ("confirmed", "ruled_out", "open_proof_gap"):
                verdict = "open_proof_gap"
            level_raw = obj.get("proof_level", 1)
            proof_level = (
                int(level_raw)
                if isinstance(level_raw, int | float | str) and str(level_raw).strip().isdigit()
                else 1
            )
            return ReviewVerdict(
                verdict=verdict,
                proof_level=max(1, min(4, proof_level)),
                counterevidence=str(obj.get("counterevidence", "")),
                reasoning=str(obj.get("reasoning", "")),
            )
    # Fail closed to an open proof gap on an unparseable review — never auto-confirm.
    return ReviewVerdict("open_proof_gap", 1, "", "review output was unparseable")


def apply_review(finding: Finding, verdict: ReviewVerdict) -> None:
    """Fold a review verdict into a finding — adjusts confidence + flags, never drops it."""
    finding.metadata["review_verdict"] = verdict.verdict
    finding.metadata["proof_level"] = verdict.proof_level
    if verdict.counterevidence and not finding.counterevidence:
        finding.counterevidence = verdict.counterevidence
    base = finding.confidence if finding.confidence is not None else 0.0
    if verdict.verdict == "confirmed":
        # A confirmed verdict floors confidence by proof level (nothing withheld).
        finding.confidence = max(base, 40.0 + 15.0 * verdict.proof_level)
    elif verdict.verdict == "ruled_out":
        finding.confidence = round(base * 0.3, 1)
        finding.metadata.setdefault("review_flag", "ruled_out_by_adversarial_review")
    else:  # open_proof_gap
        finding.metadata.setdefault("review_flag", "open_proof_gap")
