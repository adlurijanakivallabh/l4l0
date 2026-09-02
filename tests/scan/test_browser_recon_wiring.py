"""scan_all_classes -> scan.browser_recon wiring (Build Order v2 W11).

run_browser_recon itself is fully covered by tests/scan/test_browser_recon_driver.py
and tests/phase3/test_browser_recon.py; this file only proves the orchestrator
wiring: called with real firer/identity/graph, its facts land in the scan's own
graph, and a failure never aborts the scan.
"""

from __future__ import annotations

import httpx

from reachagent.scan.orchestrator import scan_all_classes


def _clean_handler(request: httpx.Request) -> httpx.Response:
    return httpx.Response(404, text="not found")


def test_browser_recon_is_called_with_the_scans_own_graph_and_firer(monkeypatch) -> None:  # noqa: ANN001
    from reachagent.payloads import PayloadLibrary

    calls: list[dict] = []

    def fake_run_browser_recon(*, graph, firer, base_url, identity, events):  # noqa: ANN001
        calls.append({"graph": graph, "firer": firer, "base_url": base_url, "identity": identity})
        return 0

    monkeypatch.setattr("reachagent.scan.browser_recon.run_browser_recon", fake_run_browser_recon)

    result = scan_all_classes(
        base_url="https://safe.example",
        in_scope="safe.example",
        transport=httpx.MockTransport(_clean_handler),
        library=PayloadLibrary.from_file(),
    )

    assert len(calls) == 1
    assert calls[0]["graph"] is result["graph"]
    assert calls[0]["base_url"] == "https://safe.example"
    assert calls[0]["firer"] is not None
    assert calls[0]["identity"]


def test_browser_recon_new_endpoints_land_in_the_scans_graph(monkeypatch) -> None:  # noqa: ANN001
    from reachagent.graph.nodes import Endpoint
    from reachagent.payloads import PayloadLibrary

    def fake_run_browser_recon(*, graph, firer, base_url, identity, events):  # noqa: ANN001
        graph.add_endpoint(
            Endpoint(method="POST", path="/api/spa-only", content_type="application/json")
        )
        return 1

    monkeypatch.setattr("reachagent.scan.browser_recon.run_browser_recon", fake_run_browser_recon)

    result = scan_all_classes(
        base_url="https://safe.example",
        in_scope="safe.example",
        transport=httpx.MockTransport(_clean_handler),
        library=PayloadLibrary.from_file(),
    )

    paths = {ep.path for _n, ep in result["graph"].endpoints()}
    assert "/api/spa-only" in paths
    assert result["graph"].findings() == []  # never a Finding either way


def test_browser_recon_failure_never_aborts_the_scan(monkeypatch) -> None:  # noqa: ANN001
    from reachagent.payloads import PayloadLibrary

    def _boom(**kwargs):  # noqa: ANN003
        raise RuntimeError("playwright crashed")

    monkeypatch.setattr("reachagent.scan.browser_recon.run_browser_recon", _boom)

    events: list = []
    result = scan_all_classes(
        base_url="https://safe.example",
        in_scope="safe.example",
        transport=httpx.MockTransport(_clean_handler),
        library=PayloadLibrary.from_file(),
        events=events,
    )

    assert result["graph"] is not None
    assert any("browser recon failed" in e.message for e in events)
