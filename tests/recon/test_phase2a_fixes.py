"""Phase 2a (a)-item fixes — JWT corpus, firer retry+honest attrs, target dispatch, OOB shapes."""

from __future__ import annotations

import ast
from pathlib import Path

import httpx
import pytest

import reachagent.execution.firer as _firer_mod
from reachagent.execution.audit import AuditLog
from reachagent.execution.firer import ReadOnlyFirstError, RequestFirer
from reachagent.execution.scope import ScopeGuard
from reachagent.graph.nodes import FindingStatus
from reachagent.graph.store import ReachabilityGraph
from reachagent.oracles import OracleMechanism
from reachagent.oracles.oob_callback import OOBCallbackEvidence, OOBCallbackOracle
from reachagent.oracles.structural import StructuralCheckType, StructuralEvidence, StructuralOracle
from reachagent.payloads import build_library
from reachagent.payloads.payload_resolver import required_slots, resolve, template_refs
from reachagent.scan.entrypoint import detect_target_type, scan_target

_TARGET = "target.test"

_NMAP_XML = (
    '<?xml version="1.0"?><nmaprun><host><address addr="93.184.216.34"'
    ' addrtype="ipv4"/><ports><port protocol="tcp" portid="80">'
    '<state state="open"/><service name="http"/></port></ports></host></nmaprun>'
)


def _scope() -> ScopeGuard:
    return ScopeGuard.from_hosts([_TARGET, "93.184.216.34"])


# -- Item 1: JWT technique corpus → structural JWT_FORGERY ---------------------


def test_jwt_templates_resolve_to_precomputed_tokens() -> None:
    assert resolve("jwt_forgery/none-alg") == "eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiJ9."
    assert resolve("jwt_forgery/weak-secret") == (
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9.GdYrDf_hp3IHBhv_b91SSCh7N2Lp19bHJXciDzy8C_c"
    )
    assert resolve("jwt_forgery/hs256-key-confusion") == (
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9.z3cU1wl_qNMB3_6Br3I7esH0TmClpmk6MbEtq9Q86-E"
    )


def test_jwt_templates_need_no_slots() -> None:
    # Every JWT segment is base64url — no live {slot} position exists, so all
    # three are fully-formed fixed tokens (required_slots empty).
    for ref in (
        "jwt_forgery/none-alg",
        "jwt_forgery/weak-secret",
        "jwt_forgery/hs256-key-confusion",
    ):
        assert required_slots(ref) == frozenset()


def test_jwt_library_rows_load_and_sink_match() -> None:
    lib = build_library()
    entries = lib.get_payloads("jwt_forgery", None)
    refs = {e.payload_ref for e in entries}
    assert refs == {
        "jwt_forgery/none-alg",
        "jwt_forgery/weak-secret",
        "jwt_forgery/hs256-key-confusion",
    }
    # All three are structural, sink-less authz entries.
    assert all(e.oracle_type is OracleMechanism.STRUCTURAL for e in entries)
    assert all(e.inferred_sink_type is None for e in entries)
    assert all(e.graph_edge_on_success == "can_call" for e in entries)
    # No orphan template — every template maps to a real catalog row.
    catalog = {e.payload_ref for e in lib.all_entries()}
    assert template_refs() <= catalog


def test_jwt_forgery_decide_table() -> None:
    oracle = StructuralOracle()
    v = oracle.run(
        StructuralEvidence(
            check_type=StructuralCheckType.JWT_FORGERY, baseline_status=200, probe_status=200
        )
    )
    assert v.status is FindingStatus.CONFIRMED_VIOLATION
    v = oracle.run(
        StructuralEvidence(
            check_type=StructuralCheckType.JWT_FORGERY, baseline_status=200, probe_status=401
        )
    )
    assert v.status is FindingStatus.CONFIRMED_DENIED
    # Baseline must be a valid-token 2xx — a failed baseline is inconclusive.
    v = oracle.run(
        StructuralEvidence(
            check_type=StructuralCheckType.JWT_FORGERY, baseline_status=500, probe_status=200
        )
    )
    assert v.status is FindingStatus.INCONCLUSIVE


# -- Item 2/3: firer transient retry + honest audit attrs ----------------------


def _seq_handler(statuses: list[int]) -> tuple[object, object]:
    state = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:  # noqa: ARG001
        s = statuses[min(state["n"], len(statuses) - 1)]
        state["n"] += 1
        return httpx.Response(s, text="x")

    return handler, state


def _firer_with(
    handler: object, monkeypatch: pytest.MonkeyPatch
) -> tuple[RequestFirer, AuditLog, object]:
    monkeypatch.setattr(_firer_mod, "_RETRY_BACKOFF", (0.0, 0.0))
    a = AuditLog()
    client = httpx.Client(transport=httpx.MockTransport(handler))  # type: ignore[arg-type]
    f = RequestFirer(client, _scope(), a)
    return f, a, client


def test_retry_recovers_503_then_200(monkeypatch) -> None:  # noqa: ANN001
    handler, state = _seq_handler([503, 503, 200])
    f, a, _client = _firer_with(handler, monkeypatch)
    result = f.fire("u", "GET", f"https://{_TARGET}/x")
    assert result.status_code == 200
    assert state["n"] == 3
    assert a.entries[-1].outcome == "fired:200:recovered"
    # Intermediate transient-gateway responses audited honestly.
    assert [e.outcome for e in a.entries] == ["fired:503", "fired:503", "fired:200:recovered"]


def test_500_is_a_meaningful_response_not_retried(monkeypatch) -> None:  # noqa: ANN001
    # A plain 500 is an application signal (e.g. the SQL-error fingerprint
    # canary) — returned immediately, never triple-fired.
    handler, state = _seq_handler([500])
    f, a, _client = _firer_with(handler, monkeypatch)
    result = f.fire("u", "GET", f"https://{_TARGET}/x")
    assert result.status_code == 500
    assert state["n"] == 1
    assert a.entries[-1].outcome == "fired:500"


def test_clean_success_no_recovery_suffix(monkeypatch) -> None:  # noqa: ANN001
    handler, state = _seq_handler([200])
    f, a, _client = _firer_with(handler, monkeypatch)
    f.fire("u", "GET", f"https://{_TARGET}/x")
    assert state["n"] == 1
    assert a.entries[-1].outcome == "fired:200"


def test_all_transient_gateway_is_final_answer_no_false_recovery(monkeypatch) -> None:  # noqa: ANN001
    handler, state = _seq_handler([503, 503, 503])
    f, a, _client = _firer_with(handler, monkeypatch)
    result = f.fire("u", "GET", f"https://{_TARGET}/x")
    assert result.status_code == 503
    assert state["n"] == 3
    # No :recovered — a 503 is not a recovered success.
    assert a.entries[-1].outcome == "fired:503"


def test_transport_error_exhausted_is_unrecoverable(monkeypatch) -> None:  # noqa: ANN001
    def handler(request: httpx.Request) -> httpx.Response:  # noqa: ARG001
        raise httpx.ConnectError("boom")

    monkeypatch.setattr(_firer_mod, "_RETRY_BACKOFF", (0.0, 0.0))
    a = AuditLog()
    client = httpx.Client(transport=httpx.MockTransport(handler))  # type: ignore[arg-type]
    f = RequestFirer(client, _scope(), a)
    with pytest.raises(httpx.ConnectError):
        f.fire("u", "GET", f"https://{_TARGET}/x")
    # Each attempt audited; final marked unrecoverable.
    assert [e.outcome for e in a.entries] == [
        "error:ConnectError",
        "error:ConnectError",
        "error:ConnectError:unrecoverable",
    ]


def test_state_changing_post_never_retried(monkeypatch) -> None:  # noqa: ANN001
    # Clear read-only first (a 200 GET), then POST returns 500 — single attempt.
    seq_handler, state = _seq_handler([200, 500])
    f, a, _client = _firer_with(seq_handler, monkeypatch)
    f.fire("u", "GET", f"https://{_TARGET}/x")
    r = f.fire("u", "POST", f"https://{_TARGET}/x")
    assert r.status_code == 500
    # One attempt for the POST (no retry on a mutation).
    assert state["n"] == 2
    assert a.entries[-1].outcome == "fired:500"
    assert not a.entries[-1].outcome.endswith(":recovered")


def test_state_changing_refused_before_read_only_never_sent(monkeypatch) -> None:  # noqa: ANN001
    def handler(request: httpx.Request) -> httpx.Response:  # noqa: ARG001
        raise AssertionError("must not send")

    monkeypatch.setattr(_firer_mod, "_RETRY_BACKOFF", (0.0, 0.0))
    a = AuditLog()
    client = httpx.Client(transport=httpx.MockTransport(handler))  # type: ignore[arg-type]
    f = RequestFirer(client, _scope(), a)
    with pytest.raises(ReadOnlyFirstError):
        f.fire("u", "POST", f"https://{_TARGET}/x")
    assert a.entries[-1].outcome == "refused_read_only_first"


# -- Item 4: target-type dispatch -----------------------------------------------


def test_detect_target_type() -> None:
    assert detect_target_type("example.com") == "domain"
    assert detect_target_type("https://example.com") == "domain"
    assert detect_target_type("https://example.com/admin?q=1") == "url"
    assert detect_target_type("93.184.216.34") == "ip"
    assert detect_target_type("http://93.184.216.34") == "ip"
    assert detect_target_type("10.0.0.0/24") == "cidr"
    assert detect_target_type("example.com:8443") == "host_port"


def test_domain_target_dispatches_to_subdomain_not_nmap() -> None:
    g = ReachabilityGraph()
    a = AuditLog()
    result = scan_target(
        base_url="https://example.com",
        in_scope="*.example.com",
        dry_run=True,
        graph=g,
        audit=a,
        fixtures={"subfinder": "api.example.com\n", "nmap": _NMAP_XML},
    )
    assert result["dry_run"] is True
    assert result["fired"] == 0
    assert any(h.hostname == "api.example.com" for _, h in g.hosts())
    # nmap not in the domain tool set → its fixture is not ingested.
    assert not any(h.address == "93.184.216.34" for _, h in g.hosts())


def test_ip_target_dispatches_to_nmap_not_subdomain() -> None:
    g = ReachabilityGraph()
    a = AuditLog()
    result = scan_target(
        base_url="http://93.184.216.34",
        in_scope="93.184.216.34",
        dry_run=True,
        graph=g,
        audit=a,
        fixtures={"nmap": _NMAP_XML, "subfinder": "api.example.com\n"},
    )
    assert result["dry_run"] is True
    assert result["fired"] == 0
    assert any(h.address == "93.184.216.34" for _, h in g.hosts())
    # subfinder not in the IP tool set → not ingested.
    assert not any(h.hostname == "api.example.com" for _, h in g.hosts())


# -- Item 5: OOB blind XXE / Log4Shell shapes -----------------------------------


def test_oob_templates_resolve_with_nonce_and_collab() -> None:
    xxe = resolve("sqli_blind/oob-xxe-exfil", nonce="ra-xxe1", collab="oob.example")
    assert "ra-xxe1.oob.example" in xxe
    assert "SYSTEM" in xxe and "/xxe" in xxe
    log4 = resolve("command_injection/log4shell-oob", nonce="ra-log1", collab="oob.example")
    assert "ra-log1.oob.example" in log4
    assert "${jndi:ldap://" in log4


def test_oob_templates_require_nonce_and_collab() -> None:
    for ref in ("sqli_blind/oob-xxe-exfil", "command_injection/log4shell-oob"):
        assert required_slots(ref) == {"nonce", "collab"}
    from reachagent.payloads.payload_resolver import MissingSlotError

    with pytest.raises(MissingSlotError):
        resolve("sqli_blind/oob-xxe-exfil", nonce="ra-xxe1")


def test_oob_oracle_confirms_on_probe_nonce() -> None:
    oracle = OOBCallbackOracle()
    v = oracle.run(
        OOBCallbackEvidence(probe_nonce="ra-xxe1", observed_nonces=frozenset({"ra-xxe1"}))
    )
    assert v.status is FindingStatus.CONFIRMED_VIOLATION
    v = oracle.run(OOBCallbackEvidence(probe_nonce="ra-xxe1", observed_nonces=frozenset({"other"})))
    assert v.status is FindingStatus.INCONCLUSIVE


# -- Invariants: six families, stimulus-only payloads, no tier leak ------------


def test_six_oracle_families_unchanged() -> None:
    assert set(OracleMechanism) == {
        OracleMechanism.DIFFERENTIAL,
        OracleMechanism.STRUCTURAL,
        OracleMechanism.TIMING_STATISTICAL,
        OracleMechanism.OOB_CALLBACK,
        OracleMechanism.EXECUTION_CONFIRMATION,
        OracleMechanism.BUSINESS_RULE_INVARIANT,
    }


def test_payload_resolver_imports_no_validator_or_candidate() -> None:
    import reachagent.payloads.payload_resolver as mod

    tree = ast.parse(Path(mod.__file__).read_text(encoding="utf-8"))
    forbidden = (
        "reachagent.tools.validator",
        "reachagent.tools.candidate",
        "run_oracle",
        "write_finding",
        "Candidate",
    )
    offenders: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            if any(f in node.module for f in forbidden):
                offenders.append(f"from {node.module}")
            for alias in node.names:
                if any(f in alias.name for f in forbidden):
                    offenders.append(f"import {alias.name}")
        if isinstance(node, ast.Name) and node.id == "Candidate":
            offenders.append("bare Candidate symbol")
    assert offenders == []


def test_new_payload_entries_are_stimulus_only_and_correctly_tagged() -> None:
    lib = build_library()
    for ref in (
        "jwt_forgery/none-alg",
        "jwt_forgery/weak-secret",
        "jwt_forgery/hs256-key-confusion",
        "sqli_blind/oob-xxe-exfil",
        "command_injection/log4shell-oob",
    ):
        matches = [e for e in lib.all_entries() if e.payload_ref == ref]
        assert len(matches) == 1, f"expected one catalog row for {ref}"
        entry = matches[0]
        assert entry.oracle_type in set(OracleMechanism)  # a real §7 family
        assert resolve(ref, nonce="ra-x", collab="oob.example")  # stimulus resolves
