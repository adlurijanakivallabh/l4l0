"""Live NVD/EPSS CVE intelligence (§7 Build Order 4) — see nvd_client, detector."""

from reachagent.cve_intel.detector import (
    KnownVulnerableVersionResult,
    VersionProbe,
    VersionProber,
    detect_known_vulnerable_version,
)
from reachagent.cve_intel.nvd_client import CveMatch, enrich_with_epss, lookup_cves, lookup_epss

__all__ = [
    "CveMatch",
    "KnownVulnerableVersionResult",
    "VersionProbe",
    "VersionProber",
    "detect_known_vulnerable_version",
    "enrich_with_epss",
    "lookup_cves",
    "lookup_epss",
]
