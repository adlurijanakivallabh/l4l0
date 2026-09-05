"""Coverage ledger — machine-observed vs applicable, so gaps read 'not assessed'.

Records which vuln classes were *applicable* to a target/param and which were
actually *assessed* (a detector ran). The report exposes the gap explicitly rather
than letting an untested surface look clean.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class CoverageLedger:
    applicable: set[tuple[str, str]] = field(default_factory=set)
    assessed: set[tuple[str, str]] = field(default_factory=set)

    def mark_applicable(self, target: str, vuln_class: str) -> None:
        self.applicable.add((target, vuln_class))

    def mark_assessed(self, target: str, vuln_class: str) -> None:
        self.assessed.add((target, vuln_class))
        self.applicable.add((target, vuln_class))

    def not_assessed(self) -> list[tuple[str, str]]:
        return sorted(self.applicable - self.assessed)

    def report(self) -> dict[str, object]:
        gaps = self.not_assessed()
        return {
            "applicable": len(self.applicable),
            "assessed": len(self.assessed),
            "not_assessed": gaps,
            "coverage_ratio": (
                round(len(self.assessed) / len(self.applicable), 3) if self.applicable else 1.0
            ),
        }
