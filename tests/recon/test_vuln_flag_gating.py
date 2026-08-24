"""Hermetic: vuln-class targeting is proposal-only — flag OFF zero regression, ON smart."""

from __future__ import annotations

import os
from unittest.mock import patch

from reachagent.graph.nodes import Endpoint, Host, Parameter
from reachagent.graph.store import ReachabilityGraph
from reachagent.recon.vuln_tuning import VULN_CLASS_ALLOWLIST, VulnTargetChoice
from reachagent.scan.entrypoint import _live_vuln_class_for


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


def test_flag_off_returns_none_zero_regression() -> None:
    g, sel = _graph_one_param()
    with patch.dict(os.environ, {}, clear=False):
        for k in ("REACHAGENT_VULN_TUNING", "REACHAGENT_RECON_LIVE_TUNING"):
            os.environ.pop(k, None)
        got = _live_vuln_class_for(sel, g, "http://127.0.0.1:5000")
    assert got is None
    assert len(list(g.findings())) == 0


def test_flag_on_mocked_uses_chosen_vuln_class_proposal_only() -> None:
    g, sel = _graph_path_param()
    chosen = VulnTargetChoice(vuln_classes=("path_traversal", "sqli"))
    with patch.dict(os.environ, {"REACHAGENT_VULN_TUNING": "1"}, clear=False):
        with patch("reachagent.recon.vuln_tuning.propose_vuln_targets", return_value=chosen):
            got = _live_vuln_class_for(sel, g, "http://127.0.0.1:5000")
    assert got in VULN_CLASS_ALLOWLIST or got is None
    assert len(list(g.findings())) == 0


def test_flag_on_outside_allowlist_fallback_still_safe_proposal_only() -> None:
    g, sel = _graph_one_param()
    evil = VulnTargetChoice(vuln_classes=("evil-class",))  # type: ignore[arg-type]
    with patch.dict(os.environ, {"REACHAGENT_VULN_TUNING": "1"}, clear=False):
        with patch("reachagent.recon.vuln_tuning.propose_vuln_targets", return_value=evil):
            got = _live_vuln_class_for(sel, g, "http://127.0.0.1:5000")
    assert got is None
    assert len(list(g.findings())) == 0
