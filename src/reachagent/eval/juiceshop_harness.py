"""Juice Shop evaluation harness — the Phase 3 numeric gate (plan §14, §15; Task 9).

Two invariants are scored here (invariant 3, PortSwigger blind-SQLi, is a
separate scoring section — see ``PortswiggerResult`` — added once lab
credentials exist, with no change to the Juice Shop logic below):

  * **Invariant 1 — coverage ≥ 75%:** ``solved_in_scope / total_in_scope >= 0.75``.
    A challenge counts as solved only when the Juice Shop challenge tracker
    confirms it (``GET /api/Challenges``), never by report text.
  * **Invariant 2 — false-positive rate ≤ 10%:**
    ``false_positives / (true_positives + false_positives) <= 0.10``, where a
    false positive is a ReachAgent-confirmed finding on a challenge the tracker
    has *not* confirmed solved.

Scope (docs/phase3-tasks.md Task 9): injection, XSS, file upload, and path
traversal challenge classes only — not business-logic or auth challenges
(Phase 2/4 scope). The in-scope set is derived generically from the tracker's
own category field, so no Juice Shop challenge *name* appears in this module.

MCP boundary: like the Phase 1 VAmPI harness, every detection call in the live
run crosses ``mcp.call_tool`` — never a direct Python call into a tool function.
The harness itself only does target *setup* and tracker *scoring* over HTTP.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# In-scope challenge classes (Phase 3 gate §14). Mapped from the Juice Shop
# tracker's category strings generically — no per-challenge logic.
IN_SCOPE_CLASSES: tuple[str, ...] = ("injection", "xss", "file_upload", "path_traversal")

# Gate thresholds (§14/§15).
COVERAGE_FLOOR = 0.75
FP_RATE_CEILING = 0.10


# ---------------------------------------------------------------------------
# Tracker types — map Juice Shop category strings to in-scope classes.
# ---------------------------------------------------------------------------

# Maps Juice Shop tracker category strings (lowercased) to in-scope class keys.
# Generic: no challenge names, no endpoint paths.
_CATEGORY_MAP: dict[str, str] = {
    "injection": "injection",
    "xss": "xss",
    "improper input validation": "file_upload",  # upload type/size challenges
    "vulnerable components": "path_traversal",  # local file read / arbitrary write
}


def in_scope_class(category: str) -> str | None:
    """Return the in-scope class key for a tracker category, or None if out of scope."""
    return _CATEGORY_MAP.get(category.lower())


# ---------------------------------------------------------------------------
# Metrics — pure and unit-testable without a live Juice Shop.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ChallengeResult:
    """One in-scope challenge: whether ReachAgent confirmed it and whether it's solved."""

    vuln_class: str
    challenge_key: str  # opaque tracker key — never a challenge name in logic
    confirmed: bool  # ReachAgent confirmed a finding for this challenge
    tracker_solved: bool  # Juice Shop tracker confirmed this challenge solved


@dataclass
class JuiceshopRun:
    """All in-scope challenge results from one Juice Shop run."""

    results: list[ChallengeResult] = field(default_factory=list)
    # Class-level false positives: a class whose oracle confirmed a finding while
    # NO in-scope challenge of that class flipped unsolved→solved this run (we
    # claimed the class exploitable; Juice Shop's tracker disagreed). Kept off the
    # coverage denominator — it is a false-positive signal only (invariant 2).
    class_false_positives: int = 0

    @property
    def total_in_scope(self) -> int:
        return len(self.results)

    @property
    def tracker_solved_count(self) -> int:
        return sum(1 for r in self.results if r.tracker_solved)

    @property
    def true_positives(self) -> int:
        """Confirmed by ReachAgent AND solved in tracker."""
        return sum(1 for r in self.results if r.confirmed and r.tracker_solved)

    @property
    def false_positives(self) -> int:
        """Confirmed by ReachAgent but NOT solved in tracker.

        Per-challenge FPs (a challenge credited but not tracker-solved) plus
        class-level FPs (a class whose oracle confirmed but which produced no
        tracker flip this run). Under tracker-delta attribution the per-challenge
        term is 0 by construction, so ``class_false_positives`` is what makes the
        rate meaningful instead of structurally zero.
        """
        per_challenge = sum(1 for r in self.results if r.confirmed and not r.tracker_solved)
        return per_challenge + self.class_false_positives

    @property
    def coverage(self) -> float:
        """Fraction of in-scope challenges confirmed (invariant 1)."""
        if self.total_in_scope == 0:
            return 0.0
        return self.true_positives / self.total_in_scope

    @property
    def fp_rate(self) -> float:
        """False-positive rate over all confirmed findings (invariant 2)."""
        total_confirmed = self.true_positives + self.false_positives
        if total_confirmed == 0:
            return 0.0
        return self.false_positives / total_confirmed

    @property
    def coverage_passes(self) -> bool:
        return self.coverage >= COVERAGE_FLOOR

    @property
    def fp_rate_passes(self) -> bool:
        return self.fp_rate <= FP_RATE_CEILING


@dataclass(frozen=True)
class PortswiggerResult:
    """Invariant 3 placeholder — populated once PortSwigger lab credentials exist.

    Invariant 3 (§14): a confirmed ``sqli_blind`` finding exists in the graph for
    the vulnerable lab, and zero ``sqli_blind`` findings exist for the non-vulnerable
    variant. Both are asserted by querying the graph, not by report text.

    Set ``available = True`` and populate the fields when lab credentials are
    provisioned (``REACHAGENT_PORTSWIGGER_LAB_URL`` +
    ``REACHAGENT_PORTSWIGGER_SESSION_TOKEN`` env vars). Until then the gate
    reports this section as SKIPPED without blocking invariants 1 and 2.
    """

    available: bool = False
    vuln_lab_confirmed: bool = False  # sqli_blind confirmed on vulnerable lab
    clean_lab_fp_count: int = 0  # sqli_blind findings on non-vulnerable variant

    @property
    def passes(self) -> bool:
        if not self.available:
            return True  # not blocking until credentials exist
        return self.vuln_lab_confirmed and self.clean_lab_fp_count == 0


@dataclass
class Phase3GateResult:
    """Composite Phase 3 gate verdict — invariants 1, 2, and 3."""

    juiceshop: JuiceshopRun
    portswigger: PortswiggerResult = field(default_factory=PortswiggerResult)

    @property
    def passed(self) -> bool:
        return (
            self.juiceshop.coverage_passes
            and self.juiceshop.fp_rate_passes
            and self.portswigger.passes
        )

    def report(self) -> str:
        j = self.juiceshop
        ps = self.portswigger
        lines = [
            "=== Phase 3 Gate Report ===",
            f"In-scope challenges : {j.total_in_scope}",
            f"Tracker solved      : {j.tracker_solved_count}",
            f"True positives      : {j.true_positives}",
            f"False positives     : {j.false_positives}",
            f"Coverage            : {j.coverage:.1%}  (floor {COVERAGE_FLOOR:.0%}) "
            + ("✅" if j.coverage_passes else "❌"),
            f"FP rate             : {j.fp_rate:.1%}  (ceiling {FP_RATE_CEILING:.0%}) "
            + ("✅" if j.fp_rate_passes else "❌"),
            "",
            "--- Invariant 3 (PortSwigger blind-SQLi) ---",
        ]
        if not ps.available:
            lines.append("SKIPPED — lab credentials not provisioned")
        else:
            lines += [
                f"Vuln lab confirmed  : {ps.vuln_lab_confirmed} "
                + ("✅" if ps.vuln_lab_confirmed else "❌"),
                f"Clean lab FP count  : {ps.clean_lab_fp_count} "
                + ("✅" if ps.clean_lab_fp_count == 0 else "❌"),
            ]
        lines += [
            "",
            f"=== {'PASSED' if self.passed else 'FAILED'} ===",
        ]
        return "\n".join(lines)
