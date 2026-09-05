"""CVE/EPSS enrichment — a prioritization fact only, never a severity input.

No reference project does anything comparable: EPSS was grepped for across
all five ``REACHAGENT_COMPARISON.md`` files and found in none. This is an
original L4L0 addition, exactly as the governing plan expects for this
sub-concern — most of Phase 7-12's mechanisms (the reachability graph,
self-hosted OAST, the deterministic Confidence Score) are original for the
same reason: no reference happened to build the equivalent.

A reference agent's own dependency-finding model (``tools/reporting/tool.py``,
already read in full for Phase 12a) computes a *contextual* CVSS from a
source-to-sink usage-context breakdown rather than trusting a bare advisory
score — a different, complementary idea (adjusting severity for how a
dependency is actually used) from what this module does (a public,
third-party exploitation-likelihood signal, used only to help decide what
to look at first). EPSS is deliberately kept out of CVSS/severity
computation entirely — it answers "how likely is this to be exploited in
the wild," a probability about the broader internet, not "how severe is
this given what was actually proven here," which stays exclusively
evidence-based per :mod:`lalo.findings.cvss`.
"""

from __future__ import annotations

from dataclasses import dataclass

import httpx

from ..agent.tools import FunctionTool, ToolResult
from ..core.redaction import redact

_EPSS_API_URL = "https://api.first.org/data/v1/epss"


@dataclass(frozen=True)
class EPSSResult:
    cve: str
    score: float
    percentile: float


def fetch_epss_score(cve: str, *, client: httpx.Client | None = None) -> EPSSResult | None:
    """The current EPSS score/percentile for ``cve``, or ``None`` on any failure.

    Never raises: a network error, an unexpected response shape, or a CVE
    with no EPSS record all degrade to ``None`` — this is an optional
    prioritization convenience, never a required input to anything.
    """
    owns_client = client is None
    http_client = client or httpx.Client(timeout=10.0)
    try:
        response = http_client.get(_EPSS_API_URL, params={"cve": cve})
        response.raise_for_status()
        payload = response.json()
        entries = payload.get("data")
        if not isinstance(entries, list) or not entries:
            return None
        entry = entries[0]
        return EPSSResult(
            cve=str(entry["cve"]),
            score=float(entry["epss"]),
            percentile=float(entry["percentile"]),
        )
    except (httpx.HTTPError, ValueError, KeyError, TypeError):
        return None
    finally:
        if owns_client:
            http_client.close()


def build_epss_tool(*, client: httpx.Client | None = None) -> FunctionTool:
    def _lookup(args: dict[str, object]) -> ToolResult:
        cve = str(args.get("cve", "")).strip()
        if not cve:
            return ToolResult(observation="error: 'cve' is required", ok=False)
        result = fetch_epss_score(cve, client=client)
        if result is None:
            return ToolResult(observation=f"no EPSS data available for {redact(cve)}", ok=False)
        return ToolResult(
            observation=(
                f"EPSS for {result.cve}: score={result.score:.3f} "
                f"percentile={result.percentile:.3f} "
                "(exploitation-likelihood prioritization signal only - "
                "does not affect CVSS or confidence scoring)"
            ),
            ok=True,
        )

    return FunctionTool(
        name="fetch_epss_score",
        description=(
            "Look up a CVE's EPSS score (probability of exploitation in the wild) "
            "to help prioritize which known-CVE findings to investigate first. "
            "A prioritization signal only - it never changes a finding's CVSS or "
            'confidence score. args: {"cve": str, e.g. "CVE-2024-12345"}'
        ),
        func=_lookup,
    )
