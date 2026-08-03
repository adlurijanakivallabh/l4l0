"""Role-bounded tool access is enforced by module membership (plan §13).

These tests assert the CLAUDE.md non-negotiables structurally: the Explorer
subset must never expose ``write_finding``; the Coordinator must never expose
``fire_request`` or ``run_oracle``; only the Validator exposes ``run_oracle`` and
``write_finding``. If a future edit leaks a tool across a role boundary, this
test fails.

Phase 3 extension: the MCP-exposed ``run_oracle`` must dispatch to all six §7
oracle families via the registry (not hardcoded to DIFFERENTIAL), and no
detector module may import ``reachagent.tools.validator`` directly — the MCP
boundary is the only path to a confirmed verdict in a live run.
"""

from __future__ import annotations

import ast
import importlib
from pathlib import Path

from reachagent.mcp import server
from reachagent.tools import coordinator, explorer, validator


def _tool_names(module: object) -> set[str]:
    return {
        name
        for name in vars(module)
        if callable(getattr(module, name)) and not name.startswith("_")
    }


def test_explorer_never_exposes_write_finding() -> None:
    names = _tool_names(explorer)
    assert "write_finding" not in names
    assert "run_oracle" not in names
    # fire_browser (Phase 3 Task 5) is the fifth Explorer tool — the browser-side
    # transport for DOM XSS discovery. It is Explorer-owned like the other four
    # and, critically, has no write_finding/run_oracle path (asserted above).
    assert names == {
        "fingerprint_parameter",
        "get_payloads",
        "fire_request",
        "classify_response",
        "fire_browser",
    }


def test_fire_browser_is_explorer_only_and_unreachable_from_other_roles() -> None:
    # The named, concrete boundary proof required by the v1.4.1 plan edit:
    # fire_browser lives on the Explorer and nowhere else. Coordinator and
    # Validator must not expose it under any wiring.
    assert "fire_browser" in _tool_names(explorer)
    assert "fire_browser" not in _tool_names(coordinator)
    assert "fire_browser" not in _tool_names(validator)


def test_coordinator_never_fires_or_runs_oracles() -> None:
    names = _tool_names(coordinator)
    assert "fire_request" not in names
    assert "run_oracle" not in names
    assert names == {"query_graph", "score_and_select", "check_budget"}


def test_only_validator_confirms_and_writes_findings() -> None:
    names = _tool_names(validator)
    assert names == {"run_oracle", "write_finding", "mark_inconclusive"}


# ---------------------------------------------------------------------------
# Phase 3: MCP run_oracle dispatches all six §7 families (not hardcoded DIFF)
# ---------------------------------------------------------------------------


def _built() -> object:
    return server.build_server(base_url="http://test.local", scope_hosts=["test.local"])


def _call(mcp: object, name: str, **kwargs: object) -> object:
    """Invoke a registered tool's underlying function by name (hand-call).

    Mirrors tests/phase1/test_mcp_server.py: ``tool.fn`` returns the dataclass
    (attribute access), whereas ``mcp.call_tool`` returns a serialized dict.
    """
    tool = mcp._tool_manager._tools[name]  # type: ignore[attr-defined]
    return tool.fn(**kwargs)


def test_mcp_run_oracle_dispatches_structural_path_traversal() -> None:
    mcp = _built()
    verdict = _call(
        mcp,
        "run_oracle",
        mechanism="structural",
        evidence={
            "check_type": "path_traversal",
            "probe_status": 200,
            "sentinel": "root:x:0:0",
            "response_body": "...root:x:0:0:root:/root:/bin/bash...",
            "evidence_ref": "pt/test",
        },
    )
    assert verdict.mechanism == "structural"  # type: ignore[attr-defined]
    assert verdict.confirmed is True  # type: ignore[attr-defined]
    assert verdict.is_violation is True  # type: ignore[attr-defined]


def test_mcp_run_oracle_dispatches_structural_file_upload() -> None:
    mcp = _built()
    verdict = _call(
        mcp,
        "run_oracle",
        mechanism="structural",
        evidence={
            "check_type": "file_upload_bypass",
            "baseline_status": 200,
            "probe_status": 200,
            "evidence_ref": "fu/test",
        },
    )
    assert verdict.mechanism == "structural"  # type: ignore[attr-defined]
    assert verdict.is_violation is True  # type: ignore[attr-defined]


def test_mcp_run_oracle_dispatches_timing_statistical() -> None:
    mcp = _built()
    # probe mean >> baseline mean → confirmed
    verdict = _call(
        mcp,
        "run_oracle",
        mechanism="timing_statistical",
        evidence={
            "probe_latencies_ms": [5000.0] * 10,
            "baseline_latencies_ms": [100.0] * 10,
            "evidence_ref": "timing/test",
        },
    )
    assert verdict.mechanism == "timing_statistical"  # type: ignore[attr-defined]
    assert verdict.is_violation is True  # type: ignore[attr-defined]


def test_mcp_run_oracle_dispatches_oob_callback() -> None:
    mcp = _built()
    nonce = "abc123"
    verdict = _call(
        mcp,
        "run_oracle",
        mechanism="oob_callback",
        evidence={
            "probe_nonce": nonce,
            "observed_nonces": [nonce],
            "evidence_ref": "oob/test",
        },
    )
    assert verdict.mechanism == "oob_callback"  # type: ignore[attr-defined]
    assert verdict.is_violation is True  # type: ignore[attr-defined]


def test_mcp_run_oracle_dispatches_execution_confirmation() -> None:
    mcp = _built()
    tag = "XSSTEST42"
    verdict = _call(
        mcp,
        "run_oracle",
        mechanism="execution_confirmation",
        evidence={
            "payload_tag": tag,
            "response_body": f"<script>{tag}</script>",
            "evidence_ref": "xss/test",
        },
    )
    assert verdict.mechanism == "execution_confirmation"  # type: ignore[attr-defined]
    assert verdict.is_violation is True  # type: ignore[attr-defined]


def test_mcp_run_oracle_dispatches_business_rule_invariant() -> None:
    mcp = _built()
    verdict = _call(
        mcp,
        "run_oracle",
        mechanism="business_rule_invariant",
        evidence={
            "rule": "single_use_reuse",
            "baseline_status": 200,
            "violating_status": 200,
            "evidence_ref": "biz/test",
        },
    )
    assert verdict.mechanism == "business_rule_invariant"  # type: ignore[attr-defined]
    assert verdict.is_violation is True  # type: ignore[attr-defined]


def test_mcp_run_oracle_differential_backward_compat() -> None:
    # Existing callers pass only evidence= (no mechanism=); must still work.
    mcp = _built()
    verdict = _call(
        mcp,
        "run_oracle",
        evidence={
            "axis": "cross_identity",
            "expectation": "probe_unauthorized",
            "baseline_status": 200,
            "probe_status": 200,
            "baseline_body": '{"ssn":"1"}',
            "probe_body": '{"ssn":"1"}',
            "evidence_ref": "bola/compat",
        },
    )
    assert verdict.mechanism == "differential"  # type: ignore[attr-defined]
    assert verdict.is_violation is True  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# Phase 3: no detector bypasses the MCP boundary (grep-clean proof)
# ---------------------------------------------------------------------------

_DETECTOR_PKGS = [
    "reachagent.sqli",
    "reachagent.nosql",
    "reachagent.ldap",
    "reachagent.xss",
    "reachagent.fileupload",
    "reachagent.pathtraversal",
]


def _source_files_for(pkg_name: str) -> list[Path]:
    pkg = importlib.import_module(pkg_name)
    pkg_path = Path(pkg.__file__).parent  # type: ignore[arg-type]
    return list(pkg_path.glob("*.py"))


def _imports_validator_directly(path: Path) -> bool:
    """Return True if the file contains a direct import of reachagent.tools.validator."""
    source = path.read_text()
    try:
        tree = ast.parse(source, filename=str(path))
    except SyntaxError:
        return False
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            module = node.module or ""
            if "reachagent.tools.validator" in module:
                return True
        if isinstance(node, ast.Import):
            for alias in node.names:
                if "reachagent.tools.validator" in alias.name:
                    return True
    return False


def test_no_detector_imports_validator_directly() -> None:
    """Grep-clean proof: no Phase 3 detector bypasses the MCP boundary (§13).

    Every detector must route oracle calls through the injectable OracleRunner
    seam (registry_runner default, MCP-backed in live runs). A direct import of
    reachagent.tools.validator in any detector module is a boundary violation.
    """
    violations: list[str] = []
    for pkg_name in _DETECTOR_PKGS:
        for path in _source_files_for(pkg_name):
            if _imports_validator_directly(path):
                violations.append(str(path))
    assert violations == [], (
        "Detector modules import reachagent.tools.validator directly — "
        "MCP boundary bypassed:\n" + "\n".join(violations)
    )
