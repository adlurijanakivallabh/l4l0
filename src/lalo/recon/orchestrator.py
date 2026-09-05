"""Recon orchestration: run available runners, scope-validate, merge into the graph."""

from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import urlsplit

from ..execution.scope import ScopeGuard
from ..graph.store import ReachGraph
from .executor import Executor
from .runners import DEFAULT_RUNNERS, ReconFact, ReconRunner


@dataclass
class ReconReport:
    added: int = 0
    skipped_out_of_scope: int = 0
    runners_ran: list[str] = field(default_factory=list)
    runners_skipped: list[str] = field(default_factory=list)


def _host_of(value: str) -> str | None:
    if "://" in value:
        return urlsplit(value).hostname
    return None


def _apply(fact: ReconFact, scope: ScopeGuard, graph: ReachGraph, report: ReconReport) -> None:
    if fact.kind in ("endpoint",):
        host = _host_of(fact.value)
        if host is not None and not scope.check(fact.value).allowed:
            report.skipped_out_of_scope += 1
            return
        method = str(fact.metadata.get("method", "GET"))
        graph.add_endpoint(fact.value, method)
        report.added += 1
    elif fact.kind in ("host", "subdomain"):
        if not scope.engagement.in_engagement(fact.value):
            report.skipped_out_of_scope += 1
            return
        graph.add_host(fact.value)
        report.added += 1
    elif fact.kind == "service":
        host = str(fact.metadata.get("host", ""))
        port = fact.metadata.get("port")
        if host and not scope.engagement.in_engagement(host):
            report.skipped_out_of_scope += 1
            return
        graph.add_service(host, int(port) if isinstance(port, int) else 0)
        report.added += 1
    elif fact.kind == "fingerprint":
        graph.add_fingerprint(fact.value, **fact.metadata)
        report.added += 1


def run_recon(
    target: str,
    executor: Executor,
    scope: ScopeGuard,
    graph: ReachGraph,
    *,
    runners: list[ReconRunner] | None = None,
) -> ReconReport:
    """Run each available runner against ``target`` and merge scope-valid facts."""
    report = ReconReport()
    for runner in runners if runners is not None else DEFAULT_RUNNERS:
        if not executor.has_binary(runner.binary):
            report.runners_skipped.append(runner.name)
            continue
        report.runners_ran.append(runner.name)
        for fact in runner.run(target, executor):
            _apply(fact, scope, graph, report)
    return report
