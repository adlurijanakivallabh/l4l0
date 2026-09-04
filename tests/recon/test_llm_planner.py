"""Tool catalog — hermetic tests.

v4 R3 removed the rest of this file's coverage (`plan_execution`,
`validate_execution_plan`, the upfront 5-phase schema) along with the dead
code itself — see `llm/planner.py`'s module docstring. `select_recon_tools`/
`validate_recon_selection` (the part still used) has its own coverage in
tests/recon/test_recon_adaptive.py.
"""

from __future__ import annotations

from reachagent.llm.planner import build_tool_catalog


def test_catalog_is_built_from_all_existing_runner_names() -> None:
    catalog = {entry.name: entry for entry in build_tool_catalog()}
    assert len(catalog) == 35  # three passive/event-driven recon adapters added
    assert {
        "nmap",
        "httpx",
        "arjun",
        "jwt-tool",
        "testssl",
        "bbot",
        "dnsrecon",
        "urlfinder",
    } <= set(catalog)
    assert catalog["nuclei"].signal_gated
    assert catalog["arjun"].phase == "insertion-points"
