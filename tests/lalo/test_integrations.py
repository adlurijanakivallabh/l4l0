"""Tests for external MCP config, tool-claim evidence, CVE enrichment."""

from __future__ import annotations

import pytest

from lalo.confirmation.scoring import score_finding
from lalo.core.errors import ConfigError
from lalo.integrations import (
    CVEFact,
    ExternalMCPClient,
    ExternalMCPConfig,
    enrich_cves,
    tool_claim_to_evidence,
)
from lalo.models import Finding, Severity


def test_mcp_fails_closed_without_credential() -> None:
    with pytest.raises(ConfigError):
        ExternalMCPClient(
            ExternalMCPConfig(name="proxy", url="http://x", allowed_tools=frozenset({"a"}))
        )


def test_mcp_requires_explicit_allowlist() -> None:
    with pytest.raises(ConfigError):
        ExternalMCPClient(ExternalMCPConfig(name="proxy", url="http://x", credential="k"))


def test_mcp_filters_to_allowlist() -> None:
    client = ExternalMCPClient(
        ExternalMCPConfig(
            name="proxy",
            url="http://x",
            credential="k",
            allowed_tools=frozenset({"replay", "capture"}),
        )
    )
    assert client.filter_tools(["replay", "capture", "delete_everything"]) == ["replay", "capture"]


def test_tool_claim_is_weak_evidence_not_a_finding() -> None:
    ev = tool_claim_to_evidence("nuclei", "template matched: cve-x")
    assert ev.metadata["source"] == "external_tool"
    # A finding backed ONLY by a tool claim scores low (needs corroboration).
    f = Finding.create("possible issue", "misc", Severity.MEDIUM, "https://x/")
    f.evidence.append(ev)
    breakdown = score_finding(f)
    assert breakdown.total < 40.0  # not auto-confirmed on a tool's say-so


def test_cve_enrichment_ranks_by_epss_then_cvss() -> None:
    def source(product: str, version: str) -> list[CVEFact]:
        return [
            CVEFact("CVE-1", product, version, cvss=9.8, epss=0.2),
            CVEFact("CVE-2", product, version, cvss=6.1, epss=0.9),
        ]

    ranked = enrich_cves("nginx", "1.18.0", source)
    assert ranked[0].cve_id == "CVE-2"  # higher EPSS first
