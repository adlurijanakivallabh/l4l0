"""Recon — total surface discovery.

A scope-gated runner framework wrapping best-in-class external tools (executed on
the host or inside the runtime container), plus pure-Python JS/source-map mining
and OpenAPI/spec ingestion. Every discovered fact is host-side validated against
the engagement before it lands in the graph; runners are fact/signal sources,
never confirmation authorities.
"""

from .executor import ContainerExecutor, ExecOutput, Executor, HostExecutor
from .jsmine import mine_javascript
from .orchestrator import run_recon
from .runners import DEFAULT_RUNNERS, ReconFact, ReconRunner
from .spec import ingest_openapi

__all__ = [
    "DEFAULT_RUNNERS",
    "ContainerExecutor",
    "ExecOutput",
    "Executor",
    "HostExecutor",
    "ReconFact",
    "ReconRunner",
    "ingest_openapi",
    "mine_javascript",
    "run_recon",
]
