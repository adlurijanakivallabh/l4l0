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

Collapsed path (Phase 1 generic-first): the three ``_detect_*`` bodies delegate to
the generic ``payload_chain`` driver — fingerprint, payload library corpus
(PATT), ``McpCaller`` handle indirection ``fire_ref``/``verdict_ref``,
``_generic_confirm`` is single oracle wiring (axis/expectation/json_field in kit).
``VampiTarget`` is the only per-target config (``base_url``/``toggle_on``);
enumeration is still via the harness's shared-state graph but payloads/oracle
types come from generic not detector literals. Setup (seed/login/register/PW
PUT) stays direct HTTP only where fire_request 1-param constraint forces it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING

import httpx

from reachagent.eval.mcp_session import SharedState as _SharedState
from reachagent.eval.mcp_session import mcp_call as _call
from reachagent.eval.mcp_session import mcp_for as _mcp_for
from reachagent.eval.mcp_session import read_only_fire as _read_only_fire
from reachagent.eval.mcp_session import session_as as _session_as
from reachagent.execution.audit import AuditLog  # noqa: F401 — re-export surface
from reachagent.execution.firer import RequestFirer  # noqa: F401 — legacy import shim
from reachagent.execution.scope import ScopeGuard  # noqa: F401 — legacy import shim
from reachagent.graph.nodes import (
    Endpoint,  # noqa: F401 — legacy import shim
    Parameter,  # noqa: F401 — legacy import shim
)
from reachagent.graph.store import ReachabilityGraph  # noqa: F401 — legacy import shim
from reachagent.mcp import server  # noqa: F401 — legacy import shim
from reachagent.payloads import PayloadLibrary  # noqa: F401 — legacy import shim
from reachagent.tools.explorer_context import ExplorerContext  # noqa: F401 — legacy import shim

if TYPE_CHECKING:
    pass

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


class Outcome(StrEnum):
    """Why a scored class landed where it did — setup vs. detection.

    The distinction the recall number alone hides: a class that reads
    ``confirmed=False`` can be either a genuine **detection miss** (the identities
    authenticated and fired, but the oracle did not confirm) or a **setup failure**
    (the harness could not even authenticate/seed the target, so detection never
    ran). Both used to look identical — ``confirmed=False, expected=True`` — so a
    VAmPI seed flake dragged recall down looking exactly like a detection
    regression. Tagging the outcome lets the report and the gate tell them apart.
    """

    CONFIRMED = "confirmed"  # oracle reached confirmed_violation, finding written
    DETECTION_MISS = "detection_miss"  # setup ok, fired, oracle did not confirm
    SETUP_FAILED = "setup_failed"  # could not authenticate/seed — detection never ran


@dataclass
class ScenarioResult:
    """One scored class: whether ReachAgent confirmed it, and whether it should.

    ``outcome`` records *why* — separating a real detection miss from a target
    setup failure so the latter reads as an environment problem, not a silent
    detection regression. ``confirmed`` stays a plain bool (a setup failure is
    never a confirmation) and is derived from ``outcome`` so the two cannot drift.
    """

    vuln_class: str
    outcome: Outcome
    expected: bool
    detail: str = ""

    @property
    def confirmed(self) -> bool:
        return self.outcome is Outcome.CONFIRMED

    @property
    def setup_failed(self) -> bool:
        return self.outcome is Outcome.SETUP_FAILED

    @property
    def is_true_positive(self) -> bool:
        return self.confirmed and self.expected

    @property
    def is_false_positive(self) -> bool:
        return self.confirmed and not self.expected

    @property
    def is_false_negative(self) -> bool:
        # A setup failure is *not* a false negative: detection never got to run, so
        # it must not be scored against recall (that is the whole point of the
        # distinction). Only a genuine detection miss counts against recall.
        return self.outcome is Outcome.DETECTION_MISS and self.expected


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
    def setup_failed_count(self) -> int:
        """Scored classes whose target setup failed before detection could run."""
        return sum(1 for s in self.scenarios if s.setup_failed)

    @property
    def precision(self) -> float:
        return precision_recall(self.scenarios)[0]

    @property
    def recall(self) -> float:
        return precision_recall(self.scenarios)[1]


def _on_mark(s: ScenarioResult) -> str:
    """Report marker for a toggle-ON scenario, separating miss from setup failure."""
    if s.confirmed:
        return "✓ confirmed"
    if s.setup_failed:
        return "⚠ SETUP FAILED"
    return "✗ missed"


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
    def setup_failures(self) -> int:
        """Total scored classes across both toggles whose setup failed.

        The recall metric already excludes these (a setup failure is not a false
        negative), so without this guard a seed flake could leave, say, one class
        unscored and the rest passing — reading as a clean gate. Surfacing it lets
        ``environment_ok``/``passed`` fail loudly on an environment problem instead.
        """
        return self.on_run.setup_failed_count + self.off_run.setup_failed_count

    @property
    def environment_ok(self) -> bool:
        """True iff every scored class actually ran detection (no setup failures)."""
        return self.setup_failures == 0

    @property
    def passed(self) -> bool:
        # A setup failure is neither a pass nor a detection regression — the gate is
        # simply not measurable, so it must not report PASSED on a flaky environment.
        return self.environment_ok and self.on_passes and self.off_passes

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
        lines += [
            f"      - {s.vuln_class:<16} {_on_mark(s)}  {s.detail}" for s in self.on_run.scenarios
        ]
        lines += [
            "",
            "  toggle OFF (secure):",
            f"    confirmed findings = {self.off_run.confirmed_count} (need exactly 0)",
        ]
        for s in self.off_run.scenarios:
            mark = (
                "⚠ SETUP FAILED"
                if s.setup_failed
                else ("⚠ FALSE POSITIVE" if s.confirmed else "· clean")
            )
            lines.append(f"      - {s.vuln_class:<16} {mark}  {s.detail}")
        if not self.environment_ok:
            # Distinguish an un-measurable run (target setup broke) from a real
            # detection regression, so a seed flake never reads as either.
            lines += [
                "",
                f"  ENVIRONMENT: {self.setup_failures} scored class(es) had setup failures — "
                "gate not measurable (fix the target, not the detector)",
            ]
        verdict = (
            "PASSED" if self.passed else ("NOT MEASURABLE" if not self.environment_ok else "FAILED")
        )
        lines += ["", f"  GATE: {verdict}"]
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


# Re-export plumbing from single helper (three call sites: harness, juice, bola).
# Legacy names kept so external imports of _SharedState etc still resolve if
# any external harness imports them — they now alias eval.mcp_session.* rather
# than duplicate ~80 LOC per file. The 5 re-assigns below are intentionally
# aliasing the imported mcp_session symbols to the harness-private names for
# drop-in call-site compatibility; type-checker noise suppressed locally.
_SharedState = _SharedState  # noqa: F811
_session_as = _session_as  # noqa: F811
_mcp_for = _mcp_for  # noqa: F811
_call = _call  # noqa: F811
_read_only_fire = _read_only_fire  # noqa: F811


def _generic_confirm(
    mcp: object,
    *,
    vuln_class: str,
    baseline_ref: str,
    probe_ref: str,
    evidence_ref: str,
    kit: dict[str, object] | None = None,
) -> bool:
    """Generic oracle confirmation — routes via payload_chain._evidence_for.

    No per-class switch here: the oracle mechanism comes from the caller's
    vuln_class (bola/idor/mass → DIFFERENTIAL, etc.) and _evidence_for builds
    the right axis/expectation/json_field/select so the harness never re-hardcodes
    them. ``kit`` pins them explicitly when the harness already knows them (BOLA
    secret, mass admin, IDOR password), so the default fallback in _evidence_for
    is only the circuit breaker — the corpus/graph-derived kit is the truth.
    """
    from reachagent.tools.payload_chain import _evidence_for as _generic_evidence

    # Resolve oracle_type from the harness's known vuln_class → differential for
    # the three VAmPI toggle classes. Mass assignment is cross_request but still
    # differential (the family is the mechanism, not the axis).
    oracle_type = "differential"
    slot_kit: dict[str, object] = dict(kit or {})
    # Harness already knows the precise axis/expectation per class — pin them so
    # the generic path honors them instead of re-deriving from vuln_class.
    evidence = _generic_evidence(
        oracle_type,
        baseline_ref=baseline_ref,
        probe_ref=probe_ref,
        evidence_ref=evidence_ref,
        payload_kit=slot_kit,
        vuln_class=vuln_class,
    )
    verdict = _call(mcp, "run_oracle", evidence=evidence)
    if not verdict.get("is_violation"):
        return False
    _call(mcp, "write_finding", verdict_ref=str(verdict["verdict_ref"]), vuln_class=vuln_class)
    return True


def _detected(confirmed: bool) -> Outcome:
    """Map a post-setup ``_confirm`` result to its outcome.

    Reached only after setup succeeded and the oracle actually ran, so a
    non-confirmation here is a genuine detection miss — never a setup failure.
    """
    return Outcome.CONFIRMED if confirmed else Outcome.DETECTION_MISS


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
        return ScenarioResult(
            "bola", Outcome.SETUP_FAILED, expected, "setup failed: missing tokens"
        )
    book = _discover_book(target, victim_token, _VICTIM[0])
    if book is None:
        return ScenarioResult(
            "bola", Outcome.SETUP_FAILED, expected, "setup failed: no victim book"
        )
    path = f"/books/v1/{book}"

    victim_sess = _session_as(target, victim_token, shared)
    owner_sess = _session_as(target, owner_token, shared)
    baseline = _read_only_fire(_mcp_for(victim_sess), victim_sess, _VICTIM[0], path)
    probe = _read_only_fire(_mcp_for(owner_sess), owner_sess, _OWNER[0], path)

    confirmed = _generic_confirm(
        _mcp_for(owner_sess),
        vuln_class="bola",
        baseline_ref=baseline,
        probe_ref=probe,
        evidence_ref=f"bola/{path}",
        kit={
            "axis": "cross_identity",
            "expectation": "probe_unauthorized",
            "json_field": "secret",
        },
    )
    return ScenarioResult("bola", _detected(confirmed), expected, f"cross-read of {path}")


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
        return ScenarioResult(
            "mass_assignment", Outcome.SETUP_FAILED, expected, "setup failed: missing token"
        )
    _register(target, "evilma", "x", "evilma@example.com", admin=True)

    sess = _session_as(target, owner_token, shared)
    mcp = _mcp_for(sess)
    ref = _read_only_fire(mcp, sess, _OWNER[0], "/users/v1/_debug")

    confirmed = _generic_confirm(
        mcp,
        vuln_class="mass_assignment",
        baseline_ref=ref,
        probe_ref=ref,
        evidence_ref="mass_assignment/register",
        kit={
            "axis": "cross_request",
            "expectation": "responses_invariant",
            "json_field": "admin",
            "baseline_select": f"username:{_OWNER[0]}",
            "probe_select": "username:evilma",
        },
    )
    return ScenarioResult(
        "mass_assignment", _detected(confirmed), expected, "admin flag on register"
    )


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
        return ScenarioResult("idor", Outcome.SETUP_FAILED, expected, "setup failed: missing token")

    sess = _session_as(target, owner_token, shared)
    mcp = _mcp_for(sess)
    before = _read_only_fire(mcp, sess, _OWNER[0], "/users/v1/_debug")
    _change_password(target, owner_token, _VICTIM[0], "hijacked_by_reachagent")
    after = _read_only_fire(mcp, sess, _OWNER[0], "/users/v1/_debug")

    confirmed = _generic_confirm(
        mcp,
        vuln_class="idor",
        baseline_ref=before,
        probe_ref=after,
        evidence_ref="idor/password-change",
        kit={
            "axis": "cross_request",
            "expectation": "responses_invariant",
            "json_field": "password",
            "baseline_select": f"username:{_VICTIM[0]}",
            "probe_select": f"username:{_VICTIM[0]}",
        },
    )
    return ScenarioResult("idor", _detected(confirmed), expected, "cross-user password change")


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
