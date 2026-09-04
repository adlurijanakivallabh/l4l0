"""Hermetic: vuln-class targeting is proposal-only, no flag gate (v4 R3).

No provider configured -> empty tuple, checked before ever reaching
propose_vuln_targets's own broader safe-default fallback (7 classes, meant
for a genuine provider-call failure); a provider's proposal -> sink-
compatible subset in priority order. Neither path ever writes a Finding —
proposal-only either way.
"""

from __future__ import annotations

from unittest.mock import patch

from reachagent.graph.nodes import Endpoint, Host, Parameter
from reachagent.graph.store import ReachabilityGraph
from reachagent.recon.vuln_tuning import VULN_CLASS_ALLOWLIST, VulnTargetChoice
from reachagent.scan.entrypoint import _live_vuln_classes_for


def _graph_one_param() -> tuple[ReachabilityGraph, object]:
    g = ReachabilityGraph()
    g.add_host(Host(address="127.0.0.1", hostname="127.0.0.1", source="test"))
    ep = g.add_endpoint(Endpoint(method="POST", path="/upload"))
    param = g.add_parameter(ep, Parameter(name="file", location="body"))

    class _Sel:
        identity_node = "identity:seed"
        endpoint_node = ep
        parameter_node = param

    return g, _Sel()


def _graph_path_param() -> tuple[ReachabilityGraph, object]:
    g = ReachabilityGraph()
    g.add_host(Host(address="127.0.0.1", hostname="127.0.0.1", source="test"))
    ep = g.add_endpoint(Endpoint(method="GET", path="/files/{path}"))
    param = g.add_parameter(ep, Parameter(name="path", location="path"))

    class _Sel:
        identity_node = "identity:seed"
        endpoint_node = ep
        parameter_node = param

    return g, _Sel()


def test_no_provider_returns_empty_zero_regression() -> None:
    """v4 R3: no flag needed — no provider configured is checked before ever
    reaching propose_vuln_targets's own broader safe-default fallback (7
    classes, meant for a genuine provider-call failure, not "no LLM at
    all") — still the original empty-tuple, zero-regression contract."""
    g, sel = _graph_one_param()
    got = _live_vuln_classes_for(sel, g, "http://127.0.0.1:5000")
    assert got == ()
    assert len(list(g.findings())) == 0


def test_live_proposal_uses_chosen_vuln_class_proposal_only() -> None:
    g, sel = _graph_path_param()
    chosen = VulnTargetChoice(vuln_classes=("path_traversal", "sqli"))
    with patch("reachagent.llm.client.build_openai_compatible_client", return_value=object()):
        with patch("reachagent.recon.vuln_tuning.propose_vuln_targets", return_value=chosen):
            got = _live_vuln_classes_for(sel, g, "http://127.0.0.1:5000")
    assert all(c in VULN_CLASS_ALLOWLIST for c in got)
    assert isinstance(got, tuple)  # sink-compatible subset, in LLM priority order
    assert len(list(g.findings())) == 0


def test_live_proposal_outside_allowlist_fallback_still_safe_proposal_only() -> None:
    g, sel = _graph_one_param()
    evil = VulnTargetChoice(vuln_classes=("evil-class",))  # type: ignore[arg-type]
    with patch("reachagent.llm.client.build_openai_compatible_client", return_value=object()):
        with patch("reachagent.recon.vuln_tuning.propose_vuln_targets", return_value=evil):
            got = _live_vuln_classes_for(sel, g, "http://127.0.0.1:5000")
    assert got == ()
    assert len(list(g.findings())) == 0
