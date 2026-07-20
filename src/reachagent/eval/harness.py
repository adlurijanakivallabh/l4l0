"""VAmPI evaluation harness — the Phase 1 numeric gate (plan §14, §15; Task 9).

Drives the full detection pipeline **through the Task 8 MCP tools** — every
fingerprint / get_payloads / fire / classify / run_oracle / write_finding call
goes through ``mcp.call_tool`` (the real MCP dispatch boundary a human in Claude
Code, or the Phase 5 Coordinator, uses), never a direct Python call into a tool
function. The harness itself only does target *setup* — ``/createdb``, login,
registering the malicious user, and performing the state-changing exploit write —
directly over HTTP, mirroring the Task 3 split where recon seeds the graph and
detection runs through the tool layer. Setup is target manipulation, not part of
ReachAgent's detection pipeline, and ``fire_request`` deliberately injects a
single parameter (it is not a general HTTP client that can build VAmPI's
multi-field register/login bodies), so that split is also a real constraint, not
just a stylistic choice.

Scope (docs/phase1-tasks.md Task 9 scope note): the numeric gate is measured on
**BOLA / IDOR / mass-assignment only** — JWT is deferred past Phase 1 with the
structural oracle family (§7, §15). VAmPI's other toggled behaviours (SQLi,
user/password enumeration, RegexDoS) are outside the Phase 1 differential-oracle
scope and are not scored.

The gate (verbatim, §14/§15):
  * toggle **ON**  → ≥90% precision and ≥80% recall vs. VAmPI's ground truth
  * toggle **OFF** → exactly zero confirmed findings

Both runs are reproducible: each begins by re-seeding VAmPI (``/createdb``) so
users and books are deterministic, discovers the per-seed randomised book titles
live, and drives the identical tool sequence against whichever toggle instance it
targets.

Ground truth (from VAmPI source, gated on its ``vuln`` flag):
  * **BOLA** — ``GET /books/v1/{title}`` returns any user's secret regardless of
    ownership (``books.py: get_by_title`` under ``vuln``). Confirmed by a
    cross-identity diff of two read-only GETs: the owner obtaining the victim's
    secret == the victim's own view.
  * **mass-assignment** — ``POST /users/v1/register`` honours a client ``admin``
    flag (``users.py: register_user`` under ``vuln``). Confirmed by a read-only
    re-read of ``/users/v1/_debug``: the injected user's ``admin`` diverges from a
    control user's.
  * **IDOR** — ``PUT /users/v1/{username}/password`` updates *another* user's
    password (``users.py: update_password`` under ``vuln``). Confirmed by a
    read-only re-read: the victim's ``password`` in ``/users/v1/_debug`` diverges
    before vs. after the cross-user write.
Under the secure toggle each is fixed, so the correct confirmed count is zero.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from itertools import count
from typing import TYPE_CHECKING

import httpx

from reachagent.execution.audit import AuditLog
from reachagent.execution.firer import RequestFirer
from reachagent.execution.scope import ScopeGuard
from reachagent.graph.nodes import Endpoint, Parameter
from reachagent.graph.store import ReachabilityGraph
from reachagent.mcp import server
from reachagent.payloads import PayloadLibrary
from reachagent.tools.explorer_context import ExplorerContext

if TYPE_CHECKING:
    from reachagent.execution.firer import FireResult
    from reachagent.oracles.base import OracleVerdict

# The three classes the Phase 1 gate scores (JWT deferred, see module docstring).
GROUND_TRUTH_CLASSES: tuple[str, ...] = ("bola", "mass_assignment", "idor")

# VAmPI's seeded non-admin users (users.py: init_db_users). ``name1`` is the
# "owner"/attacker baseline; ``name2`` is the cross-user victim.
_OWNER = ("name1", "pass1")
_VICTIM = ("name2", "pass2")
_HTTP_TIMEOUT = 10.0


# ---------------------------------------------------------------------------
# Metrics — pure and unit-testable without a live VAmPI.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class GroundTruth:
    """Whether each scored class is genuinely vulnerable in a given toggle state.

    For VAmPI this is trivial (all three are vulnerable iff the toggle is on), but
    keeping it explicit lets the metric functions stay honest and lets a test feed
    a mixed truth table to exercise precision/recall independent of the target.
    """

    vulnerable: dict[str, bool]

    @classmethod
    def for_toggle(cls, *, toggle_on: bool) -> GroundTruth:
        return cls(vulnerable=dict.fromkeys(GROUND_TRUTH_CLASSES, toggle_on))


@dataclass
class ScenarioResult:
    """One scored class: whether ReachAgent confirmed it, and whether it should."""

    vuln_class: str
    confirmed: bool
    expected: bool
    detail: str = ""

    @property
    def is_true_positive(self) -> bool:
        return self.confirmed and self.expected

    @property
    def is_false_positive(self) -> bool:
        return self.confirmed and not self.expected

    @property
    def is_false_negative(self) -> bool:
        return not self.confirmed and self.expected


def precision_recall(scenarios: list[ScenarioResult]) -> tuple[float, float]:
    """Precision and recall over scored scenarios (pure; no I/O).

    Precision is 1.0 when nothing was confirmed (no false positives is perfect
    precision), and recall is 1.0 when nothing was expected — the vacuous cases,
    made explicit so the toggle-off run (zero expected) doesn't divide by zero.
    """
    tp = sum(1 for s in scenarios if s.is_true_positive)
    fp = sum(1 for s in scenarios if s.is_false_positive)
    fn = sum(1 for s in scenarios if s.is_false_negative)
    precision = 1.0 if tp + fp == 0 else tp / (tp + fp)
    recall = 1.0 if tp + fn == 0 else tp / (tp + fn)
    return precision, recall


@dataclass
class ToggleRun:
    """The scored outcome of driving the pipeline against one toggle instance."""

    toggle_on: bool
    scenarios: list[ScenarioResult] = field(default_factory=list)

    @property
    def confirmed_count(self) -> int:
        return sum(1 for s in self.scenarios if s.confirmed)

    @property
    def precision(self) -> float:
        return precision_recall(self.scenarios)[0]

    @property
    def recall(self) -> float:
        return precision_recall(self.scenarios)[1]


@dataclass
class GateResult:
    """Both toggle runs plus the pass/fail verdict against the §14/§15 thresholds."""

    on_run: ToggleRun
    off_run: ToggleRun
    min_precision: float = 0.90
    min_recall: float = 0.80

    @property
    def on_passes(self) -> bool:
        return self.on_run.precision >= self.min_precision and self.on_run.recall >= self.min_recall

    @property
    def off_passes(self) -> bool:
        return self.off_run.confirmed_count == 0

    @property
    def passed(self) -> bool:
        return self.on_passes and self.off_passes

    def report(self) -> str:
        """A compact, human-readable gate report with the actual measured numbers."""
        lines = [
            "VAmPI Phase 1 gate — measured results",
            "=" * 44,
            f"  scored classes: {', '.join(GROUND_TRUTH_CLASSES)}",
            "",
            "  toggle ON (vulnerable):",
            f"    precision = {self.on_run.precision:.2%} (need ≥ {self.min_precision:.0%})",
            f"    recall    = {self.on_run.recall:.2%} (need ≥ {self.min_recall:.0%})",
        ]
        for s in self.on_run.scenarios:
            mark = "✓ confirmed" if s.confirmed else "✗ missed"
            lines.append(f"      - {s.vuln_class:<16} {mark}  {s.detail}")
        lines += [
            "",
            "  toggle OFF (secure):",
            f"    confirmed findings = {self.off_run.confirmed_count} (need exactly 0)",
        ]
        for s in self.off_run.scenarios:
            mark = "⚠ FALSE POSITIVE" if s.confirmed else "· clean"
            lines.append(f"      - {s.vuln_class:<16} {mark}  {s.detail}")
        lines += ["", f"  GATE: {'PASSED' if self.passed else 'FAILED'}"]
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Target configuration + direct setup (NOT part of the detection pipeline).
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class VampiTarget:
    """Connection detail for one VAmPI instance (one toggle state)."""

    base_url: str
    toggle_on: bool

    @property
    def api(self) -> str:
        return self.base_url.rstrip("/")

    @property
    def host(self) -> str:
        return httpx.URL(self.base_url).host


def _seed(target: VampiTarget) -> None:
    """Re-seed VAmPI (``/createdb``) so each run is reproducible.

    VAmPI's threaded dev server can answer ``/createdb`` with a 500 even though it
    repopulates (the response body still says "Database populated."), so the
    status is intentionally not asserted here — the subsequent logins are the real
    readiness check.
    """
    try:
        httpx.get(f"{target.api}/createdb", timeout=_HTTP_TIMEOUT)
    except httpx.HTTPError:
        pass


def _login(target: VampiTarget, username: str, password: str) -> str | None:
    """Log in directly (setup) and return the raw JWT, or ``None`` on failure."""
    resp = httpx.post(
        f"{target.api}/users/v1/login",
        json={"username": username, "password": password},
        timeout=_HTTP_TIMEOUT,
    )
    if resp.status_code == 200:
        token = resp.json().get("auth_token")
        return token if isinstance(token, str) else None
    return None


def _register(target: VampiTarget, username: str, password: str, email: str, *, admin: bool) -> int:
    """Register a user directly (mass-assignment setup). Returns the status code."""
    resp = httpx.post(
        f"{target.api}/users/v1/register",
        json={"username": username, "password": password, "email": email, "admin": admin},
        timeout=_HTTP_TIMEOUT,
    )
    return resp.status_code


def _change_password(target: VampiTarget, token: str, victim: str, new_password: str) -> int:
    """Perform the IDOR exploit write directly (state-changing setup).

    This is the *attack action* whose effect the pipeline then confirms via a
    read-only re-read — the mutation itself is target manipulation, kept out of
    the scored tool pipeline like all other setup.
    """
    resp = httpx.put(
        f"{target.api}/users/v1/{victim}/password",
        headers={"Authorization": f"Bearer {token}"},
        json={"password": new_password},
        timeout=_HTTP_TIMEOUT,
    )
    return resp.status_code


def _discover_book(target: VampiTarget, token: str, owner: str) -> str | None:
    """Find ``owner``'s book title (randomised per seed) via the public list."""
    resp = httpx.get(
        f"{target.api}/books/v1",
        headers={"Authorization": f"Bearer {token}"},
        timeout=_HTTP_TIMEOUT,
    )
    if resp.status_code != 200:
        return None
    for entry in resp.json().get("Books", []):
        if entry.get("user") == owner:
            title = entry.get("book_title")
            return title if isinstance(title, str) else None
    return None


# ---------------------------------------------------------------------------
# MCP plumbing — sessions share one graph + handle registries so the
# cross-identity oracle can resolve fire_refs minted under different identities.
# ---------------------------------------------------------------------------


@dataclass
class _SharedState:
    """One graph + handle registries shared across every per-identity session.

    Each identity fires through its own token-authenticated firer (the §10
    isolated-session model), but all fires/verdicts land in one registry and one
    graph, so ``run_oracle`` can diff two responses obtained under *different*
    identities (the whole point of the cross-identity differential oracle) and
    every confirmed finding aggregates in a single reachability graph.
    """

    graph: ReachabilityGraph = field(default_factory=ReachabilityGraph)
    fires: dict[str, FireResult] = field(default_factory=dict)
    verdicts: dict[str, OracleVerdict] = field(default_factory=dict)
    fire_seq: count[int] = field(default_factory=count)
    verdict_seq: count[int] = field(default_factory=count)


def _session_as(target: VampiTarget, token: str | None, shared: _SharedState) -> server._Session:
    """A bound MCP session whose firer authenticates as one identity (§10, §13)."""
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    client = httpx.Client(headers=headers, timeout=_HTTP_TIMEOUT)
    firer = RequestFirer(client, ScopeGuard.from_hosts([target.host]), AuditLog())
    ctx = ExplorerContext(
        graph=shared.graph,
        firer=firer,
        library=PayloadLibrary.from_file(),
        base_url=target.api,
    )
    return server._Session(
        ctx=ctx,
        _fires=shared.fires,
        _verdicts=shared.verdicts,
        _fire_seq=shared.fire_seq,
        _verdict_seq=shared.verdict_seq,
    )


def _mcp_for(session: server._Session) -> object:
    """Register the role-bounded tools on a fresh FastMCP bound to ``session``."""
    from mcp.server.fastmcp import FastMCP

    mcp = FastMCP("reachagent-eval")
    server.register_tools(mcp, session)
    return mcp


def _call(mcp: object, name: str, **arguments: object) -> dict[str, object]:
    """Invoke a tool through the real MCP dispatch boundary; return the structured result.

    Uses ``mcp.call_tool`` — the same path a Claude Code client hits — not the
    underlying function, so the harness exercises the actual MCP layer end to end
    (Task 9 DoD). ``call_tool`` returns ``(content, structured)``; we take the
    structured dict.
    """
    _content, structured = asyncio.run(mcp.call_tool(name, arguments))  # type: ignore[attr-defined]
    return dict(structured)


def _read_only_fire(mcp: object, session: server._Session, identity: str, path: str) -> str:
    """Fingerprint (canary-first) then fire one read-only GET via MCP; return the fire_ref.

    Seeds the endpoint/parameter into the shared graph, then runs the §9 pipeline
    prefix (``fingerprint_parameter`` → ``fire_request``) through ``call_tool``.
    Everything except the graph seeding crosses the MCP boundary.
    """
    ep = session.graph.add_endpoint(Endpoint(method="GET", path=path))
    param = session.graph.add_parameter(ep, Parameter(name="probe", location="query"))
    _call(mcp, "fingerprint_parameter", identity=identity, endpoint_node=ep, param_node=param)
    fired = _call(
        mcp,
        "fire_request",
        identity=identity,
        endpoint_node=ep,
        param_node=param,
        payload="",
        method="GET",
    )
    return str(fired["fire_ref"])


def _confirm(
    mcp: object,
    *,
    vuln_class: str,
    axis: str,
    expectation: str,
    baseline_ref: str,
    probe_ref: str,
    evidence_ref: str,
    json_field: str | None = None,
    baseline_select: str | None = None,
    probe_select: str | None = None,
) -> bool:
    """Run the oracle by fire_ref and, on a violation, commit the finding — all via MCP.

    Returns ``True`` iff the oracle reached ``confirmed_violation`` and the finding
    was written. The oracle diffs bodies server-side (secrets never cross the
    wire), and only a genuine ``confirmed_violation`` verdict lets ``write_finding``
    commit (the Task 6/7 gate). ``axis`` is provenance only — the ``expectation``
    drives the verdict (§7) — but it is recorded faithfully per class.
    """
    verdict = _call(
        mcp,
        "run_oracle",
        evidence={
            "axis": axis,
            "expectation": expectation,
            "baseline_fire_ref": baseline_ref,
            "probe_fire_ref": probe_ref,
            "json_field": json_field,
            "baseline_select": baseline_select,
            "probe_select": probe_select,
            "evidence_ref": evidence_ref,
        },
    )
    if not verdict.get("is_violation"):
        return False
    _call(mcp, "write_finding", verdict_ref=str(verdict["verdict_ref"]), vuln_class=vuln_class)
    return True


# ---------------------------------------------------------------------------
# Per-class detection — each confirmation runs end to end through MCP.
# ---------------------------------------------------------------------------


def _detect_bola(
    target: VampiTarget, shared: _SharedState, tokens: dict[str, str]
) -> ScenarioResult:
    """BOLA: the owner reading the victim's book obtains the victim's own secret.

    Two read-only GETs of the same book URL under two identities; the oracle
    projects ``secret`` and checks the cross-identity diff. Under vuln the owner's
    cross-read equals the victim's legitimate view (same secret) → violation;
    secure returns 404 to the owner → not equivalent → denied.
    """
    expected = target.toggle_on
    victim_token = tokens.get(_VICTIM[0])
    owner_token = tokens.get(_OWNER[0])
    if not victim_token or not owner_token:
        return ScenarioResult("bola", False, expected, "setup failed: missing tokens")
    book = _discover_book(target, victim_token, _VICTIM[0])
    if book is None:
        return ScenarioResult("bola", False, expected, "setup failed: no victim book")
    path = f"/books/v1/{book}"

    victim_sess = _session_as(target, victim_token, shared)
    owner_sess = _session_as(target, owner_token, shared)
    baseline = _read_only_fire(_mcp_for(victim_sess), victim_sess, _VICTIM[0], path)
    probe = _read_only_fire(_mcp_for(owner_sess), owner_sess, _OWNER[0], path)

    confirmed = _confirm(
        _mcp_for(owner_sess),
        vuln_class="bola",
        axis="cross_identity",
        expectation="probe_unauthorized",
        baseline_ref=baseline,
        probe_ref=probe,
        json_field="secret",
        evidence_ref=f"bola/{path}",
    )
    return ScenarioResult("bola", confirmed, expected, f"cross-read of {path}")


def _detect_mass_assignment(
    target: VampiTarget, shared: _SharedState, tokens: dict[str, str]
) -> ScenarioResult:
    """Mass-assignment: a registered user's client-supplied ``admin`` flag sticks.

    Setup registers ``evilma`` with ``admin=true`` directly; confirmation is a
    read-only re-read of ``/users/v1/_debug`` through MCP, comparing the injected
    user's ``admin`` against a control user's (``RESPONSES_INVARIANT`` — a secure
    app answers identically). Under vuln they diverge (True vs False) → violation;
    secure ignores the flag so both are False → identical → inconclusive.
    """
    expected = target.toggle_on
    owner_token = tokens.get(_OWNER[0])
    if not owner_token:
        return ScenarioResult("mass_assignment", False, expected, "setup failed: missing token")
    _register(target, "evilma", "x", "evilma@example.com", admin=True)

    sess = _session_as(target, owner_token, shared)
    mcp = _mcp_for(sess)
    ref = _read_only_fire(mcp, sess, _OWNER[0], "/users/v1/_debug")

    confirmed = _confirm(
        mcp,
        vuln_class="mass_assignment",
        axis="cross_request",
        expectation="responses_invariant",
        baseline_ref=ref,
        probe_ref=ref,
        json_field="admin",
        baseline_select=f"username:{_OWNER[0]}",
        probe_select="username:evilma",
        evidence_ref="mass_assignment/register",
    )
    return ScenarioResult("mass_assignment", confirmed, expected, "admin flag on register")


def _detect_idor(
    target: VampiTarget, shared: _SharedState, tokens: dict[str, str]
) -> ScenarioResult:
    """IDOR: the owner changing the victim's password actually mutates the victim.

    Reads ``/users/v1/_debug`` before, performs the cross-user password PUT
    directly (the exploit write, setup), reads the dump again — both reads through
    MCP. The oracle projects the victim's ``password`` and checks divergence
    (``RESPONSES_INVARIANT``): under vuln it changes → violation; secure updates
    the *caller's* own password so the victim's is unchanged → identical.
    """
    expected = target.toggle_on
    owner_token = tokens.get(_OWNER[0])
    if not owner_token:
        return ScenarioResult("idor", False, expected, "setup failed: missing token")

    sess = _session_as(target, owner_token, shared)
    mcp = _mcp_for(sess)
    before = _read_only_fire(mcp, sess, _OWNER[0], "/users/v1/_debug")
    _change_password(target, owner_token, _VICTIM[0], "hijacked_by_reachagent")
    after = _read_only_fire(mcp, sess, _OWNER[0], "/users/v1/_debug")

    confirmed = _confirm(
        mcp,
        vuln_class="idor",
        axis="cross_request",
        expectation="responses_invariant",
        baseline_ref=before,
        probe_ref=after,
        json_field="password",
        baseline_select=f"username:{_VICTIM[0]}",
        probe_select=f"username:{_VICTIM[0]}",
        evidence_ref="idor/password-change",
    )
    return ScenarioResult("idor", confirmed, expected, "cross-user password change")


# ---------------------------------------------------------------------------
# Top-level runner.
# ---------------------------------------------------------------------------


def run_toggle(target: VampiTarget) -> ToggleRun:
    """Run the full scored pipeline against one toggle instance, through MCP."""
    _seed(target)
    tokens: dict[str, str] = {}
    for user, pw in (_OWNER, _VICTIM):
        tok = _login(target, user, pw)
        if tok is not None:
            tokens[user] = tok

    run = ToggleRun(toggle_on=target.toggle_on)
    # Each class gets its own shared state so a state-changing setup (the IDOR
    # password write) can't perturb another class's baseline within the same run.
    run.scenarios.append(_detect_bola(target, _SharedState(), tokens))
    run.scenarios.append(_detect_mass_assignment(target, _SharedState(), tokens))
    run.scenarios.append(_detect_idor(target, _SharedState(), tokens))
    return run


def evaluate(*, on_base_url: str, off_base_url: str) -> GateResult:
    """Drive both toggle instances through MCP and return the scored gate result.

    ``on_base_url`` is VAmPI with ``vulnerable=1``; ``off_base_url`` with
    ``vulnerable=0``. Both are driven with the identical tool sequence, so the only
    variable is the target's behaviour — which is what makes the toggle-off zero
    the meaningful control it is (§14/§15).
    """
    on_run = run_toggle(VampiTarget(base_url=on_base_url, toggle_on=True))
    off_run = run_toggle(VampiTarget(base_url=off_base_url, toggle_on=False))
    return GateResult(on_run=on_run, off_run=off_run)
