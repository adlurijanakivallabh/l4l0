"""Hermetic tests for the white-box graph node types (Build Order 7):
SourceFile, PackageDependency, Secret, StaticAdvisory — writers, accessors,
idempotency, and the persistence round-trip.
"""

from __future__ import annotations

from reachagent.graph.nodes import PackageDependency, Secret, SourceFile, StaticAdvisory
from reachagent.graph.persistence import dump_graph, load_graph
from reachagent.graph.store import ReachabilityGraph


def test_add_source_file_and_read_it_back() -> None:
    graph = ReachabilityGraph()
    node = graph.add_source_file(
        SourceFile(
            path="app/db.py", rule_id="python.sql-injection", line=42, message="tainted query"
        )
    )
    files = graph.source_files()
    assert len(files) == 1
    fid, sf = files[0]
    assert fid == node
    assert sf.path == "app/db.py"
    assert sf.line == 42


def test_source_file_id_is_idempotent_on_repeated_scan() -> None:
    graph = ReachabilityGraph()
    sf = SourceFile(path="app/db.py", rule_id="python.sql-injection", line=42, message="x")
    first = graph.add_source_file(sf)
    second = graph.add_source_file(sf)
    assert first == second
    assert len(graph.source_files()) == 1


def test_different_line_or_rule_is_a_distinct_node() -> None:
    graph = ReachabilityGraph()
    graph.add_source_file(
        SourceFile(path="app/db.py", rule_id="python.sql-injection", line=42, message="a")
    )
    graph.add_source_file(
        SourceFile(path="app/db.py", rule_id="python.sql-injection", line=99, message="b")
    )
    graph.add_source_file(SourceFile(path="app/db.py", rule_id="python.xss", line=42, message="c"))
    assert len(graph.source_files()) == 3


def test_add_package_dependency_and_read_it_back() -> None:
    graph = ReachabilityGraph()
    node = graph.add_package_dependency(
        PackageDependency(
            ecosystem="pypi", name="requests", version="2.25.0", manifest="requirements.txt"
        )
    )
    deps = graph.package_dependencies()
    assert len(deps) == 1
    did, dep = deps[0]
    assert did == node
    assert dep.name == "requests"
    assert dep.version == "2.25.0"


def test_same_package_version_from_two_manifests_is_one_node() -> None:
    graph = ReachabilityGraph()
    graph.add_package_dependency(
        PackageDependency(
            ecosystem="pypi", name="requests", version="2.25.0", manifest="requirements.txt"
        )
    )
    graph.add_package_dependency(
        PackageDependency(ecosystem="pypi", name="requests", version="2.25.0", manifest="setup.py")
    )
    assert len(graph.package_dependencies()) == 1


def test_add_secret_never_needs_the_secret_value() -> None:
    graph = ReachabilityGraph()
    node = graph.add_secret(
        Secret(path="config/.env", line=3, detector="AWS", verified=True, source="trufflehog")
    )
    secrets = graph.secrets()
    assert len(secrets) == 1
    sid, secret = secrets[0]
    assert sid == node
    assert secret.detector == "AWS"
    assert secret.verified is True
    # No field on the dataclass could even hold a raw secret value.
    assert not hasattr(secret, "value")
    assert not hasattr(secret, "raw")


def test_add_static_advisory_never_touches_finding() -> None:
    graph = ReachabilityGraph()
    node = graph.add_static_advisory(
        StaticAdvisory(
            ecosystem="pypi",
            package="requests",
            version="2.25.0",
            cve_id="CVE-2023-32681",
            manifest="requirements.txt",
            cvss_score=6.1,
            epss_score=0.02,
        )
    )
    advisories = graph.static_advisories()
    assert len(advisories) == 1
    aid, advisory = advisories[0]
    assert aid == node
    assert advisory.cve_id == "CVE-2023-32681"
    # A StaticAdvisory is never a Finding -- confirmed by construction, not by
    # a status flag: it never appears in findings() at all.
    assert graph.findings() == []


def test_static_advisory_id_is_idempotent_per_cve() -> None:
    graph = ReachabilityGraph()
    advisory = StaticAdvisory(
        ecosystem="pypi",
        package="requests",
        version="2.25.0",
        cve_id="CVE-2023-32681",
        manifest="requirements.txt",
    )
    first = graph.add_static_advisory(advisory)
    second = graph.add_static_advisory(advisory)
    assert first == second
    assert len(graph.static_advisories()) == 1


def test_persistence_round_trip_preserves_all_four_new_node_types(tmp_path) -> None:  # noqa: ANN001
    from reachagent.execution.audit import AuditLog
    from reachagent.graph.chain_solver import ChainSolver

    graph = ReachabilityGraph()
    graph.add_source_file(
        SourceFile(path="app/db.py", rule_id="python.sql-injection", line=42, message="x")
    )
    graph.add_package_dependency(
        PackageDependency(
            ecosystem="pypi", name="requests", version="2.25.0", manifest="requirements.txt"
        )
    )
    graph.add_secret(Secret(path="config/.env", line=3, detector="AWS"))
    graph.add_static_advisory(
        StaticAdvisory(
            ecosystem="pypi",
            package="requests",
            version="2.25.0",
            cve_id="CVE-2023-32681",
            manifest="requirements.txt",
            cvss_score=6.1,
        )
    )

    path = tmp_path / "graph.json"
    dump_graph(graph, ChainSolver(graph), AuditLog(), path)
    loaded_graph, _solver, _audit = load_graph(path)

    assert len(loaded_graph.source_files()) == 1
    assert len(loaded_graph.package_dependencies()) == 1
    assert len(loaded_graph.secrets()) == 1
    assert len(loaded_graph.static_advisories()) == 1
    _aid, loaded_advisory = loaded_graph.static_advisories()[0]
    assert loaded_advisory.cve_id == "CVE-2023-32681"
    assert loaded_advisory.cvss_score == 6.1
