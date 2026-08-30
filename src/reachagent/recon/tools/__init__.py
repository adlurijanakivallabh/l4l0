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

from reachagent.recon.tools.arjun import ArjunRunner
from reachagent.recon.tools.base import (
    RECON_ENV_LIVE,
    ReconOutcome,
    ReconResult,
    ReconToolRunner,
)
from reachagent.recon.tools.bbot import BbotRunner
from reachagent.recon.tools.commix import CommixRunner
from reachagent.recon.tools.dalfox import DalfoxRunner
from reachagent.recon.tools.dirb import DirbRunner
from reachagent.recon.tools.dnsrecon import DnsreconRunner
from reachagent.recon.tools.dnsx import DnsxRunner
from reachagent.recon.tools.feroxbuster import FeroxbusterRunner
from reachagent.recon.tools.ffuf import FfufRunner
from reachagent.recon.tools.gobuster import GobusterRunner
from reachagent.recon.tools.httpx_runner import HttpxRunner
from reachagent.recon.tools.jwt_tool import JwtToolRunner
from reachagent.recon.tools.katana import KatanaRunner
from reachagent.recon.tools.masscan import MasscanRunner
from reachagent.recon.tools.naabu import NaabuRunner
from reachagent.recon.tools.nikto import NiktoRunner
from reachagent.recon.tools.nmap import NmapRunner
from reachagent.recon.tools.nuclei import NucleiRunner
from reachagent.recon.tools.paramspider import ParamSpiderRunner
from reachagent.recon.tools.rustscan import RustscanRunner
from reachagent.recon.tools.shuffledns import ShuffleDnsRunner
from reachagent.recon.tools.signal_gated import (
    SignalGatedMetadata,
    SignalGatedOutcome,
    SignalGatedResult,
    SignalGatedToolRunner,
    reconfirm_candidate,
)
from reachagent.recon.tools.sqlmap import SqlmapRunner
from reachagent.recon.tools.subdomains import AmassRunner, SubfinderRunner
from reachagent.recon.tools.theharvester import TheHarvesterRunner
from reachagent.recon.tools.tls_probe import SslscanRunner, SslyzeRunner, TestsslRunner
from reachagent.recon.tools.url_discovery import GauRunner, WaybackUrlsRunner
from reachagent.recon.tools.urlfinder import UrlfinderRunner
from reachagent.recon.tools.wafw00f import Wafw00fRunner
from reachagent.recon.tools.whatweb import WhatWebRunner
from reachagent.recon.tools.wpscan_passive import WpscanPassiveRunner
from reachagent.recon.tools.x8 import X8Runner

__all__ = [
    "RECON_ENV_LIVE",
    "AmassRunner",
    "ArjunRunner",
    "BbotRunner",
    "CommixRunner",
    "DalfoxRunner",
    "DnsxRunner",
    "DnsreconRunner",
    "DirbRunner",
    "FeroxbusterRunner",
    "FfufRunner",
    "GauRunner",
    "GobusterRunner",
    "HttpxRunner",
    "JwtToolRunner",
    "KatanaRunner",
    "MasscanRunner",
    "NiktoRunner",
    "NaabuRunner",
    "NmapRunner",
    "NucleiRunner",
    "ParamSpiderRunner",
    "ReconOutcome",
    "ReconResult",
    "ReconToolRunner",
    "RustscanRunner",
    "SignalGatedOutcome",
    "SignalGatedMetadata",
    "SignalGatedResult",
    "SignalGatedToolRunner",
    "SqlmapRunner",
    "SslscanRunner",
    "SslyzeRunner",
    "SubfinderRunner",
    "ShuffleDnsRunner",
    "TestsslRunner",
    "TheHarvesterRunner",
    "WaybackUrlsRunner",
    "UrlfinderRunner",
    "Wafw00fRunner",
    "WhatWebRunner",
    "WpscanPassiveRunner",
    "X8Runner",
    "reconfirm_candidate",
]
