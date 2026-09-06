"""A real live-target run: fire at an actual running VAmPI container, record what
was found with the real record_finding tool, and score it with the eval harness.

Requires VAmPI's vulnerable instance already running locally, e.g.:
    docker run -d --rm -p 5000:5000 erev0s/vampi

Marked ``live`` (this project's existing pytest marker convention, see
pyproject.toml) and skipped when nothing answers at the expected port -
matching test_runtime.py's own established
``skipif(not docker_available(), ...)`` pattern for its live Docker tests,
rather than relying solely on a marker to be excluded from a default run.
Its own standing discipline is that a lab-target container is brought up
only for a live run and torn down immediately after, never left running
between sessions.

This exercises the real, already-built pieces that exist today (Phase 3's
HttpFirer/ScopeGuard firing a genuine request at a live target, Phase 12's
record_finding recording a real captured response, this phase's own
scoring reading the resulting graph) rather than a full autonomous
AgentLoop run - wiring a live LLM-driven scan end to end is out of scope
for this project's current phase set (see Phase 17's own commit for the
explicit reasoning) and would need its own dedicated integration pass.
"""

from __future__ import annotations

import socket

import httpx
import pytest

from lalo.agent.tools import ToolRegistry
from lalo.eval.cases import BenchmarkCase, run_case
from lalo.eval.scoring import score_composite
from lalo.execution.firer import HttpFirer
from lalo.execution.scope import ScopeGuard
from lalo.execution.target import Engagement
from lalo.findings.tool import build_record_finding_tool
from lalo.graph.model import ReachabilityGraph

VAMPI_HOST = "127.0.0.1"
VAMPI_PORT = 5000
VAMPI_URL = f"http://{VAMPI_HOST}:{VAMPI_PORT}"


def _vampi_reachable() -> bool:
    try:
        with socket.create_connection((VAMPI_HOST, VAMPI_PORT), timeout=0.5):
            return True
    except OSError:
        return False


_ACCESS_CONTROL_CVSS = {
    "attack_vector": "N",
    "attack_complexity": "L",
    "privileges_required": "N",
    "user_interaction": "N",
    "scope": "U",
    "confidentiality": "L",
    "integrity": "N",
    "availability": "N",
}


@pytest.mark.live
@pytest.mark.skipif(not _vampi_reachable(), reason="VAmPI is not running on 127.0.0.1:5000")
def test_live_vampi_unauthenticated_user_listing_scores_as_a_true_positive() -> None:
    engagement = Engagement.from_specs(["127.0.0.1:5000"])
    scope = ScopeGuard(engagement=engagement)
    firer = HttpFirer(scope, client=httpx.Client())

    result = firer.fire("GET", f"{VAMPI_URL}/users/v1")
    assert result.fired is True
    assert result.status == 200
    body = result.body.decode("utf-8")
    assert "username" in body  # VAmPI's known unauthenticated user-enumeration primitive

    graph = ReachabilityGraph()
    registry = ToolRegistry([build_record_finding_tool(graph)])
    record_result = registry.dispatch(
        "record_finding",
        {
            "title": "Unauthenticated user enumeration via /users/v1",
            "description": "The /users/v1 endpoint returns the full user list with no auth.",
            "vuln_class": "access-control",
            "target": f"{VAMPI_URL}/users/v1",
            "evidence": [body],
            "evidence_excerpt": "username",
            "counterevidence": "No authentication header was required and none was sent.",
            "severity_change_conditions": "Exposed password hashes would raise severity.",
            "remediation": "Apply input validation and least-privilege fixes.",
            "cvss_breakdown": _ACCESS_CONTROL_CVSS,
        },
    )
    assert record_result.ok is True

    case = BenchmarkCase(
        name="vampi-live-smoke",
        description="A narrow live smoke case: one known VAmPI primitive, not the full target.",
        ground_truth_classes=frozenset({"access-control"}),
    )
    case_result = run_case(case, graph)
    assert case_result.found_classes == frozenset({"access-control"})

    composite = score_composite([case_result])
    assert composite.mean_recall == 1.0
    assert composite.mean_precision == 1.0
    assert composite.case_count == 1
