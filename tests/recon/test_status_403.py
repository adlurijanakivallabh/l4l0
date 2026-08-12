"""401/403 ACL-surface classification (D5) — hermetic fixtures, no network."""

from __future__ import annotations

import ast
import json
from pathlib import Path

from reachagent.execution.audit import AuditLog
from reachagent.execution.scope import ScopeGuard
from reachagent.graph.store import ReachabilityGraph
from reachagent.oracles import OracleMechanism
from reachagent.recon.calibration import CalibrationResult
from reachagent.recon.tools.dirb import DirbRunner
from reachagent.recon.tools.feroxbuster import FeroxbusterRunner
from reachagent.recon.tools.ffuf import FfufRunner
from reachagent.recon.tools.gobuster import GobusterRunner

_TARGET = "target.test"


def _scope() -> ScopeGuard:
    return ScopeGuard.from_hosts([_TARGET])


def _wildcard_cal() -> CalibrationResult:
    return CalibrationResult(
        statuses=(200, 200, 200),
        sizes=(1, 1, 1),
        body_hashes=("a", "a", "a"),
        content_types=("text/html",) * 3,
        wildcard=True,
    )


def _endpoint_by_path(graph: ReachabilityGraph, path: str) -> object:
    matches = [ep for _, ep in graph.endpoints() if ep.path == path]
    assert len(matches) == 1, f"expected one endpoint {path}, got {len(matches)}"
    return matches[0]


# -- D2: third honest state — exists-restricted ----------------------------------


def test_gobuster_403_classified_restricted() -> None:
    g = ReachabilityGraph()
    a = AuditLog()
    GobusterRunner(graph=g, scope=_scope(), audit=a).ingest(
        f"https://{_TARGET}", "/admin (Status: 403) [Size: 1234]\n"
    )
    ep = _endpoint_by_path(g, "/admin")
    assert ep.access_restricted == "403"
    assert any(e.outcome == "discovered_restricted:403" for e in a.entries)


def test_ffuf_403_classified_restricted() -> None:
    g = ReachabilityGraph()
    a = AuditLog()
    blob = json.dumps({"results": [{"url": f"https://{_TARGET}/admin", "status": 403}]})
    FfufRunner(graph=g, scope=_scope(), audit=a).ingest(f"https://{_TARGET}", blob)
    ep = _endpoint_by_path(g, "/admin")
    assert ep.access_restricted == "403"
    assert any(e.outcome == "discovered_restricted:403" for e in a.entries)


def test_401_classified_restricted_too() -> None:
    g = ReachabilityGraph()
    a = AuditLog()
    GobusterRunner(graph=g, scope=_scope(), audit=a).ingest(
        f"https://{_TARGET}", "/api (Status: 401) [Size: 5]\n"
    )
    ep = _endpoint_by_path(g, "/api")
    assert ep.access_restricted == "401"
    assert any(e.outcome == "discovered_restricted:401" for e in a.entries)


def test_2xx_has_no_restricted_tag_or_audit() -> None:
    g = ReachabilityGraph()
    a = AuditLog()
    GobusterRunner(graph=g, scope=_scope(), audit=a).ingest(
        f"https://{_TARGET}", "/items (Status: 200) [Size: 5]\n"
    )
    ep = _endpoint_by_path(g, "/items")
    assert ep.access_restricted is None
    assert not any(e.outcome.startswith("discovered_restricted:") for e in a.entries)


def test_404_line_not_asserted() -> None:
    g = ReachabilityGraph()
    a = AuditLog()
    # gobuster does not emit 404 lines; a 405 line is asserted per current behavior.
    GobusterRunner(graph=g, scope=_scope(), audit=a).ingest(
        f"https://{_TARGET}", "/admin (Status: 405) [Size: 5]\n"
    )
    # 405 is not restricted and not skipped → asserted without a tag.
    ep = _endpoint_by_path(g, "/admin")
    assert ep.access_restricted is None


def test_dirb_and_ferox_403_classified_restricted() -> None:
    for cls, fixture in [
        (DirbRunner, f"+ https://{_TARGET}/admin (CODE:403|SIZE:1234)\n"),
        (FeroxbusterRunner, f'{{"url":"https://{_TARGET}/admin","status":403}}\n'),
    ]:
        g = ReachabilityGraph()
        a = AuditLog()
        cls(graph=g, scope=_scope(), audit=a).ingest(f"https://{_TARGET}", fixture)
        ep = _endpoint_by_path(g, "/admin")
        assert ep.access_restricted == "403", f"{cls.__name__} failed to classify"
        assert any(e.outcome == "discovered_restricted:403" for e in a.entries)


# -- D3: wildcard calibration still suppresses ALL -------------------------------


def test_wildcard_suppression_wins_over_403_classification() -> None:
    # A "403" under a catch-all is the tool's own noise — the target returns 200
    # for everything, so the restricted classification is untrustworthy too.
    g = ReachabilityGraph()
    a = AuditLog()
    runner = GobusterRunner(graph=g, scope=_scope(), audit=a)
    runner.calibration = _wildcard_cal()
    runner.ingest(f"https://{_TARGET}", "/admin (Status: 403) [Size: 1234]\n")
    assert list(g.endpoints()) == []
    assert any(e.outcome == "refused_wildcard_catchall" for e in a.entries)
    assert not any(e.outcome.startswith("discovered_restricted:") for e in a.entries)


# -- D4: recon-facts-only regression ---------------------------------------------


def test_classification_is_recon_facts_only_across_all_four() -> None:
    fixtures: list[tuple[object, str]] = [
        (GobusterRunner, "/a (Status: 200)\n/b (Status: 403)\n"),
        (FfufRunner, json.dumps({"results": [{"url": f"https://{_TARGET}/a", "status": 200}]})),
        (FeroxbusterRunner, f'{{"url":"https://{_TARGET}/b","status":403}}\n'),
        (DirbRunner, f"+ https://{_TARGET}/a (CODE:200|SIZE:1)\n"),
    ]
    for cls, fixture in fixtures:
        g = ReachabilityGraph()
        a = AuditLog()
        cls(graph=g, scope=_scope(), audit=a).ingest(f"https://{_TARGET}", fixture)
        assert g.findings() == [], f"{cls.__name__} wrote a finding"
        assert g.can_call_edges() == [], f"{cls.__name__} wrote a can_call"
        assert list(g.hosts()), f"{cls.__name__} wrote no Host"


def test_wrappers_import_no_validator() -> None:
    import reachagent.recon.tools as pkg

    pkg_dir = Path(pkg.__file__).parent
    forbidden = ("reachagent.tools.validator", "run_oracle", "write_finding", "Candidate")
    offenders: list[str] = []
    for name in ("gobuster.py", "ffuf.py", "feroxbuster.py", "dirb.py"):
        tree = ast.parse((pkg_dir / name).read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                if any(f in node.module for f in forbidden):
                    offenders.append(f"{name}: from {node.module}")
                for alias in node.names:
                    if any(f in alias.name for f in forbidden):
                        offenders.append(f"{name}: import {alias.name}")
            if isinstance(node, ast.Name) and node.id == "Candidate":
                offenders.append(f"{name}: bare Candidate")
    assert offenders == []


def test_six_oracle_families_unchanged() -> None:
    assert set(OracleMechanism) == {
        OracleMechanism.DIFFERENTIAL,
        OracleMechanism.STRUCTURAL,
        OracleMechanism.TIMING_STATISTICAL,
        OracleMechanism.OOB_CALLBACK,
        OracleMechanism.EXECUTION_CONFIRMATION,
        OracleMechanism.BUSINESS_RULE_INVARIANT,
    }
