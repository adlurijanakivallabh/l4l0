"""Recon-tier tool wrappers — transport-tier fact-emitters (§9, §13; v1.8).

One wrapper per recon tool — nmap, amass, subfinder, gobuster, whatweb — each a
:class:`~reachagent.recon.tools.base.ReconToolRunner`. They write **only**
transport-tier graph facts (``Host``/``Service`` nodes, ``runs_service``/
``resolves_to`` edges, ``Endpoint`` nodes for discovered paths, tech/version
attributes) and nothing else: no ``can_call``, no candidate, no ``Finding``, no
``run_oracle``. This is the recon-tier invariant (§9) — the same architectural
role as :class:`~reachagent.recon.mapper.SurfaceMapper`, a fact source, never an
Explorer/Validator/Coordinator tool.

Every wrapper is scope-gated at the execution layer *before spawning* (§10),
invokes its tool via an argument array with ``shell=False`` (command-injection
guard), skips cleanly when its binary is absent (optional recon source, §13), and
audits every invocation. Live spawning is off unless ``REACHAGENT_RECON_LIVE`` is
set; the default (and every test) parses recorded fixtures via ``ingest`` —
network-free and reproducible.
"""

from __future__ import annotations

from reachagent.recon.tools.base import (
    RECON_ENV_LIVE,
    ReconOutcome,
    ReconResult,
    ReconToolRunner,
)
from reachagent.recon.tools.gobuster import GobusterRunner
from reachagent.recon.tools.nmap import NmapRunner
from reachagent.recon.tools.subdomains import AmassRunner, SubfinderRunner
from reachagent.recon.tools.whatweb import WhatWebRunner

__all__ = [
    "RECON_ENV_LIVE",
    "AmassRunner",
    "GobusterRunner",
    "NmapRunner",
    "ReconOutcome",
    "ReconResult",
    "ReconToolRunner",
    "SubfinderRunner",
    "WhatWebRunner",
]
