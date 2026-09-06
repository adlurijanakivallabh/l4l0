"""Coverage: what was never assessed, from machine-observed facts only.

CLAUDE.md's own working convention states this directly: "Honest coverage.
A surface that wasn't tested reads 'not assessed,' never 'clean.' Coverage
is machine-observed, not asserted." A reference agent's own dual-track
coverage design (``report/coverage.py``, read in full) keeps this exact
distinction between ``agent_reported`` (a self-attestation ledger) and
``machine_observed`` (runtime facts that "contradict rather than confirm" —
an agent equipped with a skill that never shows up in any recorded outcome
is a gap, not evidence of a clean result). L4L0 has no self-attestation
ledger tool at all (no ``record_coverage`` equivalent was built in any
earlier phase, and CLAUDE.md's own principle argues against leaning on one)
— so this module keeps only the machine-observed half, deliberately
narrower than that reference's two-track design: which vulnerability-class
skills the library holds (Phase 11) versus which vuln_class values actually
appear among filed findings (Phase 12). A skill never matched by any
finding is "not assessed" — which honestly does not distinguish "tested and
found clean" from "never looked at," since nothing yet records the former.
That honesty gap is the correct default until a real, code-enforced signal
for "this class was actively tested" exists; asserting a false "clean" would
be strictly worse.

Matching is deliberately simple: an exact, case-insensitive comparison
between a finding's ``vuln_class`` and a skill's name, rather than the
reference's 29-entry word-phrasing table (``_SKILL_PHRASINGS``, 76 phrase
strings total across all entries — counted directly from the real source,
not estimated) built to bridge a skill's filename against a pentester's own
wording. L4L0's skills use short, hyphenated class names (``sql-injection``,
``xss``), so the exact match covers the common path IF the agent's own
``vuln_class`` choice actually matches one.

**Correction, found via a real live-agent eval run against VAmPI (not a
hypothetical):** this docstring previously claimed ``record_finding``'s own
tool description "uses the same short, hyphenated class names" already —
false. The description only ever said ``"vuln_class": str``, no convention
stated at all, and a real autonomous run confirmed the consequence: the
agent filed two genuinely correct findings (a real SQL injection, a real
broken-access-control issue) as ``"SQL Injection"`` and ``"OWASP
API1:2023 Broken Object Level Authorization"`` — neither matches any skill
name or any eval ground-truth class by exact string, so both coverage and
eval scoring silently read them as unmatched despite being right. Fixed at
the source (``findings/tool.py``'s own tool description now names the
hyphenated-slug convention explicitly, with examples), not by loosening the
match here — a real free-text mismatch is still a real, acknowledged
ceiling of this simpler approach for a class the agent invents outside the
skill library entirely, just no longer for the common, in-library case a
one-line prompt fix already closes.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..skills.loader import Skill, SkillCategory
from .collect import FindingRecord


@dataclass(frozen=True)
class CoverageSummary:
    assessed: list[str]
    not_assessed: list[str]

    @property
    def total_known_classes(self) -> int:
        return len(self.assessed) + len(self.not_assessed)


def build_coverage_summary(skills: list[Skill], records: list[FindingRecord]) -> CoverageSummary:
    """Compare the skill library's vulnerability classes against filed findings."""
    known = sorted(
        {skill.name.lower() for skill in skills if skill.category == SkillCategory.VULNERABILITY}
    )
    seen = {record.vuln_class.strip().lower() for record in records}
    assessed = [name for name in known if name in seen]
    not_assessed = [name for name in known if name not in seen]
    return CoverageSummary(assessed=assessed, not_assessed=not_assessed)
