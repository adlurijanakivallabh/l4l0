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
