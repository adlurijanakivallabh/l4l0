"""Shared URL helpers — single stdlib source for host/path (ponytail: deduped 15× split://)."""

from __future__ import annotations

import urllib.parse


def host_of(url: str) -> str:
    """Bare host from URL/bare target, port+userinfo stripped — stdlib ``urlparse``."""
    try:
        if "://" not in url:
            url = "http://" + url
        hostname = urllib.parse.urlparse(url).hostname
        if hostname:
            return hostname
        bare = url.split("://", 1)[-1].split("/", 1)[0]
        return bare.split(":", 1)[0].split("@", 1)[-1].strip("[]")
    except Exception:
        return url.split("/", 1)[0].split(":", 1)[0].split("@", 1)[-1]


def path_of(url: str) -> str:
    """Path+query from URL, fallback ``/`` — stdlib ``urlparse``."""
    try:
        parsed = urllib.parse.urlparse(url if "://" in url else f"http://{url}")
        path = parsed.path or "/"
        if parsed.query:
            path += f"?{parsed.query}"
        return path.split("#", 1)[0] or "/"
    except Exception:
        after = url.split("://", 1)[-1] if "://" in url else url
        slash = after.find("/")
        return (after[slash:].split("#", 1)[0] if slash != -1 else "/") or "/"


# GUI live-feed preview cap — independent of any LLM-context truncation a caller
# applies separately. Shared by both the recon-tier (ReconToolRunner) and
# signal-gated (SignalGatedToolRunner) bases so an operator sees real tool
# stdout ("what wordlist hit, what nmap printed"), not just an outcome enum.
_PREVIEW_MAX_LINES = 20
_PREVIEW_MAX_CHARS = 1_500


def output_preview(raw: str) -> str:
    """A short, human-readable slice of real tool stdout, bounded for display."""
    lines = raw.splitlines()[:_PREVIEW_MAX_LINES]
    preview = "\n".join(lines)[:_PREVIEW_MAX_CHARS]
    if len(raw.splitlines()) > _PREVIEW_MAX_LINES or len(raw) > _PREVIEW_MAX_CHARS:
        preview += "\n…"
    return preview


def available_memory_mb() -> float | None:
    """Free-for-allocation memory in MB, or ``None`` when it can't be measured.

    Reads ``/proc/meminfo``'s ``MemAvailable`` (Linux-only — the whole recon
    toolchain this guards is Linux-oriented already). Advisory hygiene, not a
    security gate: an unmeasurable platform (no ``/proc/meminfo``, unexpected
    format) returns ``None`` and never blocks a scan.
    """
    try:
        with open("/proc/meminfo", encoding="utf-8") as fh:
            for line in fh:
                if line.startswith("MemAvailable:"):
                    return int(line.split()[1]) / 1024
    except (OSError, ValueError, IndexError):
        return None
    return None
