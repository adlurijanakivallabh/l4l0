"""Preferred wordlist resolver — best-available on-disk default (§9 audit).

Per-tool REACHAGENT_*_WORDLIST env wins outright (an explicit path is never
second-guessed). Otherwise, for "directory" purpose only (content-discovery
tools — gobuster/ffuf/feroxbuster/dirb), a size tier (v3 V2:
REACHAGENT_WORDLIST_SIZE, "medium" unset/invalid = today's exact prior
default, never changed) and an optional technology hint
(REACHAGENT_WORDLIST_TECH, e.g. "wordpress") narrow the on-disk candidate
list — both validated against a fixed, curated table of REAL vendored
SecLists paths, never an arbitrary path string. Falls back to dirb/common.txt
if nothing on the candidate list exists on disk.

This resolver is the floor half only — an operator-set default via these two
env vars. The autonomous half (an LLM deciding to escalate size/tech after a
first content-discovery pass yields zero endpoints) lives in
``recon/wordlist_escalation.py``, mirroring ``recon/depth_escalation.py``'s
nmap pattern: it temporarily raises these same env vars for one follow-up
pass, so this module never needs to know an escalation happened.
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
    "dns": (
        "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
        "/usr/share/seclists/Discovery/DNS/namelist.txt",
        *_DIRECTORY_CANDIDATES,
    ),
}

# v3 V2: size tiers, all real vendored SecLists/DirBuster paths — "medium" is
# exactly _DIRECTORY_CANDIDATES (today's prior, unchanged default).
_SIZE_CANDIDATES: dict[str, tuple[str, ...]] = {
    "small": (
        "/usr/share/seclists/Discovery/Web-Content/raft-small-directories.txt",
        "/usr/share/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-small.txt",
    ),
    "medium": _DIRECTORY_CANDIDATES,
    "large": (
        "/usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt",
        "/usr/share/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-big.txt",
        "/usr/share/wordlists/dirbuster/directory-list-2.3-big.txt",
    ),
}

# v3 V2: technology-specific wordlists, keyed off the same fingerprint labels
# Host.technology/Endpoint.technology already use elsewhere in this codebase.
# A bounded, curated table — an unrecognized hint is ignored, never turned
# into an arbitrary path lookup.
_TECH_CANDIDATES: dict[str, tuple[str, ...]] = {
    "wordpress": ("/usr/share/seclists/Discovery/Web-Content/CMS/wordpress.fuzz.txt",),
    "joomla": ("/usr/share/seclists/Discovery/Web-Content/CMS/joomla-plugins.fuzz.txt",),
}


# Public: the valid size-tier / tech-hint keys, for cross-module validation
# (mirrors nmap.py's SAFE_SCRIPT_CATEGORIES) — recon/wordlist_escalation.py
# validates an LLM's choice against these without reaching into this
# module's own private path tables.
SIZE_TIERS: frozenset[str] = frozenset(_SIZE_CANDIDATES)
TECH_HINTS: frozenset[str] = frozenset(_TECH_CANDIDATES)


def _first_existing(candidates: tuple[str, ...]) -> str | None:
    for cand in candidates:
        if _Path(cand).exists():
            return cand
    return None


def preferred_wordlist(
    env_var: str,
    *,
    x8: bool = False,
    purpose: str = "directory",
) -> str:
    explicit = os.environ.get(env_var)
    if explicit:
        return explicit
    if purpose == "directory" and not x8:
        tech = os.environ.get("REACHAGENT_WORDLIST_TECH", "").strip().lower()
        tech_match = _first_existing(_TECH_CANDIDATES.get(tech, ()))
        if tech_match:
            return tech_match
        size = os.environ.get("REACHAGENT_WORDLIST_SIZE", "medium").strip().lower()
        candidates = _SIZE_CANDIDATES.get(size, _DIRECTORY_CANDIDATES)
    else:
        candidates = (
            _X8_CANDIDATES if x8 else _PURPOSE_CANDIDATES.get(purpose, _DIRECTORY_CANDIDATES)
        )
    return _first_existing(candidates) or "/usr/share/wordlists/dirb/common.txt"
