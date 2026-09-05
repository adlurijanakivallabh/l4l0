"""CVE / EPSS enrichment — a fact source feeding prioritization.

A known-CVE match is a static fact for prioritization; it is never suppressed for
lack of a dynamic PoC, and never on its own written as a confirmed finding. The
lookup source is injectable (offline data set, or a live client added later).
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

# (product, version) -> CVE facts
CVESource = Callable[[str, str], "list[CVEFact]"]


@dataclass(frozen=True)
class CVEFact:
    cve_id: str
    product: str
    version: str
    cvss: float | None = None
    epss: float | None = None


def enrich_cves(product: str, version: str, source: CVESource) -> list[CVEFact]:
    """Return known CVEs for a fingerprinted product/version, ranked by EPSS then CVSS."""
    facts = source(product, version)
    return sorted(facts, key=lambda f: (f.epss or 0.0, f.cvss or 0.0), reverse=True)
