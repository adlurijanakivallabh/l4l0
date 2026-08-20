"""WPScan passive recon wrapper — WordPress stack facts as Host attributes (§9).

Mirrors whatweb.py: technology/detected_version onto Host (and Endpoint where
path-specific) — never a Technology node. WPScan passive only (no active
checks). Facts only — no candidate/Finding/can_call, no run_oracle.
"""

from __future__ import annotations

import json
from typing import Any

from reachagent.graph.nodes import Endpoint, Host
from reachagent.recon.tools.base import ReconToolRunner


def _host_of(target: str) -> str:
    stripped = target.split("://", 1)[-1]
    return stripped.split("/", 1)[0].split(":", 1)[0]


class WpscanPassiveRunner(ReconToolRunner):
    """Emit Host tech/version from WPScan passive JSON (§9). Facts only."""

    name = "wpscan"
    binary = "wpscan"

    def command(self, target: str) -> list[str]:
        """wpscan --url <target> --enumerate vp,vt --format json --detection-mode passive."""
        return [
            "wpscan",
            "--url",
            target,
            "--enumerate",
            "vp,vt",
            "--format",
            "json",
            "--detection-mode",
            "passive",
        ]

    def parse(self, target: str, raw_output: str) -> tuple[str, ...]:
        """Parse WPScan JSON into Host technology attributes."""
        written: list[str] = []
        try:
            parsed = json.loads(raw_output)
        except json.JSONDecodeError:
            return ()
        if not isinstance(parsed, dict):
            return ()
        host_addr = _host_of(str(parsed.get("target_url", target)))
        version = None
        # WPScan nests version under parsed["version"]["number"] or ["version"] as string/dict
        ver_obj = parsed.get("version")
        if isinstance(ver_obj, dict) and ver_obj.get("number"):
            version = str(ver_obj["number"])
        elif isinstance(ver_obj, str):
            version = ver_obj
        # Plugins / themes list version per entry — collect tech names
        tech_parts: list[str] = ["wordpress"] if _has_wordpress(parsed) else []
        plugins = parsed.get("plugins", {}) if isinstance(parsed.get("plugins"), dict) else {}
        if isinstance(plugins, dict):
            for name in plugins:
                tech_parts.append(f"plugin:{name}")
        themes = parsed.get("themes", {}) if isinstance(parsed.get("themes"), dict) else {}
        if isinstance(themes, dict):
            for name in themes:
                tech_parts.append(f"theme:{name}")
        # main_theme list variant
        mt = parsed.get("main_theme")
        if isinstance(mt, dict) and mt.get("slug") and f"theme:{mt['slug']}" not in tech_parts:
            tech_parts.append(f"theme:{mt['slug']}")
        technology = ", ".join(sorted(set(tech_parts))) or None
        host_node = self.graph.add_host(
            Host(
                address=host_addr,
                hostname=host_addr,
                source=self.name,
                technology=technology,
                detected_version=version,
            )
        )
        written.append(host_node)
        # Interesting findings may carry endpoint paths (e.g. /wp-json/)
        for finding in (
            parsed.get("interesting_findings", [])
            if isinstance(parsed.get("interesting_findings"), list)
            else []
        ):
            if not isinstance(finding, dict):
                continue
            url = str(finding.get("url", ""))
            if url and _host_of(url) == host_addr:
                path = _path_of(url)
                if path and path != "/":
                    ep = self.graph.add_endpoint(
                        Endpoint(
                            method="GET", path=path, technology=technology, detected_version=version
                        )
                    )
                    self.graph.add_resolves_to(host_node, ep)
                    written.append(ep)
        return tuple(written)


def _has_wordpress(parsed: dict[str, Any]) -> bool:  # noqa: ANN401
    # Heuristic: version present or interesting_findings mention WordPress
    if parsed.get("version"):
        return True
    for f in (
        parsed.get("interesting_findings", [])
        if isinstance(parsed.get("interesting_findings"), list)
        else []
    ):
        if isinstance(f, dict) and "wordpress" in str(f.get("type", "")).lower():
            return True
    return bool(parsed.get("plugins") or parsed.get("themes") or parsed.get("main_theme"))


def _path_of(url: str) -> str:
    after = url.split("://", 1)[-1] if "://" in url else url
    slash = after.find("/")
    if slash == -1:
        return "/"
    path = after[slash:].split("#", 1)[0]
    return path or "/"
