"""Software composition analysis — manifest parsing + live NVD reuse (Build Order 7).

No new external tool dependency: parses standard, well-known manifest formats
(``requirements.txt``, ``package.json``) — structured data extraction, not
hand-written vulnerability detection — and reuses the already-built,
rate-limited/cached/EPSS-enriching NVD client (``cve_intel/nvd_client.py``,
Build Order 4) for the actual CVE match. "Less code, more outcome": no
``trivy``/``pip-audit`` dependency needed for the CVE-lookup half of SCA.

Writes a ``PackageDependency`` fact for every parsed, exactly-pinned
dependency, and a ``StaticAdvisory`` — never a ``Finding``, see
``graph/nodes.py`` — for each one with a known CVE. Bounded manifest
discovery (at most ``_MAX_MANIFESTS`` files, skipping common vendored/
dependency directories) so a large repo can't turn this into an unbounded
filesystem crawl. NVD's own rate limit (Build Order 4, ~5 req/30s without an
API key) naturally bounds how many distinct package/version pairs get
checked per scan for a dependency-heavy repo — lookups beyond that budget
fail open (no advisory written for them), never block the scan.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from pathlib import Path

from reachagent.cve_intel.nvd_client import HttpClient, enrich_with_epss, lookup_cves
from reachagent.graph.nodes import PackageDependency, StaticAdvisory
from reachagent.graph.store import ReachabilityGraph

_MAX_MANIFESTS = 20
_SKIP_DIRS = frozenset(
    {".git", "node_modules", "venv", ".venv", "__pycache__", "dist", "build", ".tox"}
)
_REQUIREMENT_LINE = re.compile(
    r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*==\s*([A-Za-z0-9.\-+]+)\s*(?:;.*)?$"
)
_EXACT_SEMVER = re.compile(r"\d+\.\d+\.\d+")


def _find_manifests(repo_path: Path, filename: str) -> list[Path]:
    found: list[Path] = []
    for path in repo_path.rglob(filename):
        if any(part in _SKIP_DIRS for part in path.parts):
            continue
        found.append(path)
        if len(found) >= _MAX_MANIFESTS:
            break
    return found


def parse_requirements_txt(path: Path) -> list[tuple[str, str]]:
    """Pinned-only (``name==version``) requirements — an unpinned/range spec
    carries no single version to look up a CVE against, so it is skipped,
    never guessed."""
    pairs: list[tuple[str, str]] = []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return pairs
    for raw_line in text.splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line or line.startswith(("-", "git+", "http://", "https://")):
            continue
        match = _REQUIREMENT_LINE.match(line)
        if match:
            pairs.append((match.group(1), match.group(2)))
    return pairs


def parse_package_json(path: Path) -> list[tuple[str, str]]:
    """Exact-pinned dependency versions from ``dependencies``/``devDependencies``.

    A semver RANGE (``^1.2.3``, ``~1.2.3``, ``*``, ``latest``) carries no
    single resolved version to look up — skipped, never guessed. A lockfile
    would have the resolved version; parsing ``package-lock.json``/
    ``yarn.lock`` is out of scope for this pass, a disclosed limit.
    """
    pairs: list[tuple[str, str]] = []
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError):
        return pairs
    if not isinstance(data, dict):
        return pairs
    for key in ("dependencies", "devDependencies"):
        deps = data.get(key)
        if not isinstance(deps, dict):
            continue
        for name, version in deps.items():
            if (
                isinstance(name, str)
                and isinstance(version, str)
                and _EXACT_SEMVER.fullmatch(version)
            ):
                pairs.append((name, version))
    return pairs


_MANIFEST_PARSERS: tuple[tuple[str, str, Callable[[Path], list[tuple[str, str]]]], ...] = (
    ("requirements.txt", "pypi", parse_requirements_txt),
    ("package.json", "npm", parse_package_json),
)


def scan_dependencies(
    repo_path: str,
    graph: ReachabilityGraph,
    *,
    client: HttpClient | None = None,
) -> tuple[str, ...]:
    """Discover manifests, write ``PackageDependency`` facts, and write a
    ``StaticAdvisory`` for each dependency with a known CVE. Returns every
    node id written (both kinds). Fails open throughout: a missing/
    unreadable/malformed manifest yields no facts for it, never an exception.
    """
    root = Path(repo_path)
    nodes: list[str] = []
    for filename, ecosystem, parser in _MANIFEST_PARSERS:
        for manifest_path in _find_manifests(root, filename):
            manifest_label = str(manifest_path.relative_to(root))
            for name, version in parser(manifest_path):
                dep_node = graph.add_package_dependency(
                    PackageDependency(
                        ecosystem=ecosystem, name=name, version=version, manifest=manifest_label
                    )
                )
                nodes.append(dep_node)
                matches = enrich_with_epss(lookup_cves(name, version, client=client), client=client)
                for match in matches:
                    advisory_node = graph.add_static_advisory(
                        StaticAdvisory(
                            ecosystem=ecosystem,
                            package=name,
                            version=version,
                            cve_id=match.cve_id,
                            manifest=manifest_label,
                            cvss_score=match.cvss_score,
                            epss_score=match.epss_score,
                            summary=match.summary,
                        )
                    )
                    nodes.append(advisory_node)
    return tuple(nodes)
