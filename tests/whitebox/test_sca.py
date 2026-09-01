"""Hermetic tests for whitebox/sca.py (Build Order 7) — manifest parsing +
NVD reuse. A fake HttpClient is always injected; no real network calls.
"""

from __future__ import annotations

import pytest

import reachagent.cve_intel.nvd_client as nvd_module
from reachagent.graph.store import ReachabilityGraph
from reachagent.whitebox.sca import parse_package_json, parse_requirements_txt, scan_dependencies


@pytest.fixture(autouse=True)
def _reset_nvd_module_state(monkeypatch):  # noqa: ANN001
    """lookup_cves/lookup_epss cache and rate-limit at module scope (Build
    Order 4) -- without resetting them, one test's cached "requests:2.6.0"
    CVE match would leak into another test expecting a clean/empty result."""
    monkeypatch.setattr(nvd_module, "_nvd_cache", {})
    monkeypatch.setattr(nvd_module, "_epss_cache", {})
    monkeypatch.setattr(
        nvd_module, "_nvd_limiter", nvd_module._RateLimiter(max_requests=5, window_seconds=30.0)
    )
    monkeypatch.setattr(
        nvd_module, "_epss_limiter", nvd_module._RateLimiter(max_requests=10, window_seconds=30.0)
    )


class _FakeCveClient:
    """An HttpClient whose .get() always fails -- lookup_cves's own fail-open
    design (Build Order 4) swallows this and returns [], so this proves
    scan_dependencies still writes a clean PackageDependency node with no
    advisory when CVE lookup is unavailable, never an exception."""

    def get(self, url, *, params):  # noqa: ANN001, ANN201
        raise AssertionError("no real network call expected in a hermetic test")


def test_parse_requirements_txt_keeps_only_pinned_versions(tmp_path) -> None:  # noqa: ANN001
    path = tmp_path / "requirements.txt"
    path.write_text(
        "requests==2.6.0\n"
        "flask>=2.0\n"
        "# a comment\n"
        "\n"
        "-e git+https://example.test/pkg.git\n"
        "django==1.11.0  # trailing comment\n"
    )

    pairs = parse_requirements_txt(path)

    assert pairs == [("requests", "2.6.0"), ("django", "1.11.0")]


def test_parse_requirements_txt_missing_file_returns_empty(tmp_path) -> None:  # noqa: ANN001
    assert parse_requirements_txt(tmp_path / "nonexistent.txt") == []


def test_parse_package_json_keeps_only_exact_semver(tmp_path) -> None:  # noqa: ANN001
    path = tmp_path / "package.json"
    path.write_text(
        '{"dependencies": {"lodash": "4.17.4", "express": "^4.17.1"}, '
        '"devDependencies": {"jest": "27.0.0", "eslint": "latest"}}'
    )

    pairs = parse_package_json(path)

    assert sorted(pairs) == [("jest", "27.0.0"), ("lodash", "4.17.4")]


def test_parse_package_json_malformed_json_returns_empty(tmp_path) -> None:  # noqa: ANN001
    path = tmp_path / "package.json"
    path.write_text("not json {{{")

    assert parse_package_json(path) == []


def test_scan_dependencies_writes_dependency_nodes_with_no_cve_matches(tmp_path) -> None:  # noqa: ANN001
    (tmp_path / "requirements.txt").write_text("requests==2.6.0\n")

    graph = ReachabilityGraph()
    nodes = scan_dependencies(str(tmp_path), graph, client=_FakeCveClient())

    deps = graph.package_dependencies()
    assert len(deps) == 1
    _did, dep = deps[0]
    assert dep.name == "requests"
    assert dep.ecosystem == "pypi"
    assert dep.manifest == "requirements.txt"
    assert len(nodes) == 1  # the dependency node only -- no advisory (rate limit exhausted -> [])
    assert graph.static_advisories() == []


def test_scan_dependencies_writes_a_static_advisory_for_a_known_cve(tmp_path) -> None:  # noqa: ANN001
    (tmp_path / "requirements.txt").write_text("requests==2.6.0\n")

    class _NvdShapedClient:
        def get(self, url, *, params):  # noqa: ANN001, ANN201
            class _Response:
                status_code = 200

                def json(self) -> dict:
                    return {
                        "vulnerabilities": [
                            {
                                "cve": {
                                    "id": "CVE-2015-2296",
                                    "descriptions": [{"lang": "en", "value": "x"}],
                                    "metrics": {
                                        "cvssMetricV31": [
                                            {
                                                "baseSeverity": "MEDIUM",
                                                "cvssData": {"baseScore": 5.0},
                                            }
                                        ]
                                    },
                                }
                            }
                        ]
                    }

            return _Response()

    graph = ReachabilityGraph()
    scan_dependencies(str(tmp_path), graph, client=_NvdShapedClient())

    advisories = graph.static_advisories()
    assert len(advisories) == 1
    _aid, advisory = advisories[0]
    assert advisory.cve_id == "CVE-2015-2296"
    assert advisory.package == "requests"
    assert advisory.cvss_score == 5.0
    # Never a Finding -- structurally impossible, not just untested.
    assert graph.findings() == []


def test_scan_dependencies_skips_vendored_and_git_directories(tmp_path) -> None:  # noqa: ANN001
    vendored = tmp_path / "node_modules" / "some-pkg"
    vendored.mkdir(parents=True)
    (vendored / "package.json").write_text('{"dependencies": {"left-pad": "1.0.0"}}')
    (tmp_path / "package.json").write_text('{"dependencies": {"lodash": "4.17.4"}}')

    graph = ReachabilityGraph()
    scan_dependencies(str(tmp_path), graph, client=_FakeCveClient())

    names = {dep.name for _did, dep in graph.package_dependencies()}
    assert names == {"lodash"}


def test_scan_dependencies_on_a_repo_with_no_manifests_writes_nothing(tmp_path) -> None:  # noqa: ANN001
    graph = ReachabilityGraph()
    nodes = scan_dependencies(str(tmp_path), graph, client=_FakeCveClient())

    assert nodes == ()
    assert graph.package_dependencies() == []
