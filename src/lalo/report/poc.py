"""Reproducible PoC generation (curl) from a finding's metadata."""

from __future__ import annotations

from ..core.redaction import safe_target_url
from ..models import Finding


def curl_poc(finding: Finding) -> str:
    """A minimal reproducible curl command for the finding's target/parameter."""
    url = safe_target_url(finding.target)
    param = finding.metadata.get("parameter")
    note = f"  # inject the {finding.vuln_class} payload into '{param}'" if param else ""
    return f"curl -sk '{url}'{note}"
