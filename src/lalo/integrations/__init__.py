"""Integrations — external MCP servers, external-tool evidence, CVE/SCA intel.

External tools and MCP servers are evidence/fact sources feeding confidence
scoring — never standalone confirmation authorities. External MCP connections
fail closed without a dedicated credential and expose only an explicit per-
connection tool allowlist.
"""

from .cve import CVEFact, enrich_cves
from .evidence import tool_claim_to_evidence
from .mcp_client import ExternalMCPClient, ExternalMCPConfig

__all__ = [
    "CVEFact",
    "ExternalMCPClient",
    "ExternalMCPConfig",
    "enrich_cves",
    "tool_claim_to_evidence",
]
