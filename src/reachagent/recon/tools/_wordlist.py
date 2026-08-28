"""Preferred wordlist resolver — best-available on-disk default (§9 audit).

Per-tool REACHAGENT_*_WORDLIST env wins; otherwise prefer raft-medium-dirs /
directory-list-2.3-medium when on-disk, else fall back to dirb/common.txt.
SecLists / OneListForAll vendored elsewhere (~/SecLists, /usr/share/seclists)
— no payload vendoring here, just path preference. ponytail: Path.exists
check per-invocation; one-liner helper, not a config file.
"""

from __future__ import annotations

import os
from pathlib import Path as _Path

_DIRECTORY_CANDIDATES = (
    "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt",
    "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
    "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt",
    # x8 param list — only for x8 runner preference below
)

_X8_CANDIDATES = (
    "/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt",
    "/usr/share/wordlists/seclists/Discovery/Web-Content/burp-parameter-names.txt",
)

_PURPOSE_CANDIDATES = {
    "directory": _DIRECTORY_CANDIDATES,
    "api": (
        "/usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt",
        "/usr/share/seclists/Discovery/Web-Content/api/api-seen-in-wild.txt",
        *_DIRECTORY_CANDIDATES,
    ),
    "dns": (
        "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
        "/usr/share/seclists/Discovery/DNS/namelist.txt",
        *_DIRECTORY_CANDIDATES,
    ),
    "parameter": _X8_CANDIDATES,
}


def preferred_wordlist(
    env_var: str,
    *,
    x8: bool = False,
    purpose: str = "directory",
) -> str:
    explicit = os.environ.get(env_var)
    if explicit:
        return explicit
    candidates = _X8_CANDIDATES if x8 else _PURPOSE_CANDIDATES.get(purpose, _DIRECTORY_CANDIDATES)
    for cand in candidates:
        if _Path(cand).exists():
            return cand
    return "/usr/share/wordlists/dirb/common.txt"
