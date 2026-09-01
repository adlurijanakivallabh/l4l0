"""Known-vulnerable-version detector — hermetic tests (Prober-injection pattern).

Uses the real default registry runner (no validator import, no fake oracle) —
same pattern as test_cloud_bucket.py. The oracle's own decide() branch is
covered separately in tests/phase3/test_known_vulnerable_version_oracle.py.
"""

from __future__ import annotations

from reachagent.cve_intel.detector import (
    VersionProbe,
    VersionProber,
    detect_known_vulnerable_version,
)
from reachagent.cve_intel.nvd_client import CveMatch

_VERSION = "Apache Tomcat/7.0.92"
_MATCH = (CveMatch(cve_id="CVE-2019-0232", cvss_score=9.8, severity="critical", summary="x"),)


def test_confirmed_when_version_string_present_in_live_response() -> None:
    def fire_probe() -> VersionProbe:
        return VersionProbe(status=404, haystack=f"<address>{_VERSION}</address>")

    prober = VersionProber(fire_probe=fire_probe)
    result = detect_known_vulnerable_version(
        prober, version_string=_VERSION, cve_matches=_MATCH, evidence_ref="ref-1"
    )
    assert result.confirmed is True
    assert result.matches == _MATCH
    assert result.evidence_ref == "ref-1"


def test_not_confirmed_when_version_string_absent_from_live_response() -> None:
    def fire_probe() -> VersionProbe:
        return VersionProbe(status=200, haystack="server has been upgraded")

    prober = VersionProber(fire_probe=fire_probe)
    result = detect_known_vulnerable_version(prober, version_string=_VERSION, cve_matches=_MATCH)
    assert result.confirmed is False


def test_no_cve_matches_never_fires_a_probe_at_all() -> None:
    calls = {"n": 0}

    def fire_probe() -> VersionProbe:
        calls["n"] += 1
        return VersionProbe(status=200, haystack=_VERSION)

    prober = VersionProber(fire_probe=fire_probe)
    result = detect_known_vulnerable_version(prober, version_string=_VERSION, cve_matches=())
    assert result.confirmed is False
    assert calls["n"] == 0  # a harmless version banner is not worth an oracle call


def test_blank_version_string_never_fires_a_probe() -> None:
    calls = {"n": 0}

    def fire_probe() -> VersionProbe:
        calls["n"] += 1
        return VersionProbe(status=200, haystack="")

    prober = VersionProber(fire_probe=fire_probe)
    result = detect_known_vulnerable_version(prober, version_string="", cve_matches=_MATCH)
    assert result.confirmed is False
    assert calls["n"] == 0


def test_transport_failure_is_not_a_violation() -> None:
    def fire_probe() -> VersionProbe:
        raise ConnectionError("boom")

    prober = VersionProber(fire_probe=fire_probe)
    result = detect_known_vulnerable_version(prober, version_string=_VERSION, cve_matches=_MATCH)
    assert result.confirmed is False
