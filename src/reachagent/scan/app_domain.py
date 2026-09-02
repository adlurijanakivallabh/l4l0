"""Application-domain inference (Build Order v2 W18).

A single bounded LLM call that infers WHAT the target application is — a hospital records
system, an ecommerce store, a banking portal, a SaaS admin panel, etc. — from the observed
surface (paths, methods, tech). The result is an advisory, order-only steering signal that
sharpens testing priority (hospital → IDOR/BOLA on patient records + PHI access control;
ecommerce → price/quantity tampering + coupon/business-logic; banking → transaction
authorization), fed into the same bounded ``signals`` dict ``rank_vuln_classes`` already reads.

It NEVER gates coverage (every class still runs), NEVER writes a finding, and fails open to an
empty result on any error — exactly like every other tuning signal.
"""

from __future__ import annotations

import logging

from reachagent.graph.store import ReachabilityGraph
from reachagent.llm.client import build_openai_compatible_client

_log = logging.getLogger(__name__)

_MAX_DOMAIN = 60
_PROMPT = (
    "You are profiling an authorized web/API pentest target to prioritize testing. From the "
    "observed surface below, name in 1-4 words WHAT this application is (e.g. 'hospital records "
    "system', 'ecommerce store', 'banking portal', 'SaaS admin', 'blog/CMS', 'unknown'). "
    'Reply ONLY as JSON: {{"domain": "<short label>", "rationale": "<one short sentence>"}}.\n\n'
    "Observed surface:\n{surface}"
)


def _surface_digest(graph: ReachabilityGraph, *, max_paths: int = 40) -> str:
    paths = sorted({ep.path for _n, ep in graph.endpoints() if ep.path})[:max_paths]
    techs = sorted({h.technology for _n, h in graph.hosts() if h.technology})
    lines = []
    if techs:
        lines.append("technology: " + ", ".join(techs)[:200])
    lines.append("paths:")
    lines.extend(f"  {p[:120]}" for p in paths)
    return "\n".join(lines)


def classify_app_domain(graph: ReachabilityGraph, *, client: object | None = None) -> str:
    """Return a short app-domain label ("hospital records system", ...) or "" on any failure.

    ``client`` (any object exposing ``propose_json``) is injectable for tests; otherwise the
    configured provider is used. Fails open — the caller treats "" as "no profile".
    """
    if not list(graph.endpoints()):
        return ""  # nothing to profile yet
    try:
        tuner = client if client is not None else build_openai_compatible_client()
        if tuner is None:
            return ""
        result = tuner.propose_json(  # type: ignore[attr-defined]
            _PROMPT.format(surface=_surface_digest(graph)), max_tokens=200
        )
    except Exception as exc:  # noqa: BLE001 — inference must never break the scan
        _log.warning("app-domain inference failed (%s); no profile", exc)
        return ""
    domain = str(result.get("domain", "") if isinstance(result, dict) else "").strip()
    if not domain or domain.lower() in {"unknown", "n/a", "none"}:
        return ""
    return domain[:_MAX_DOMAIN]
