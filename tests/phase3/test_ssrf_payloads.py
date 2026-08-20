"""SSRF payload set (Task 24) — blind/non-blind/token families + structural SSRF_RESPONSE."""

from __future__ import annotations

import ast
from pathlib import Path

import httpx

from reachagent.execution.audit import AuditLog
from reachagent.execution.firer import RequestFirer
from reachagent.execution.scope import ScopeGuard
from reachagent.graph.edges import FindingEdge, StructuralEdge
from reachagent.graph.nodes import Finding, FindingStatus, SinkType
from reachagent.graph.store import ReachabilityGraph
from reachagent.oracles import OracleMechanism
from reachagent.oracles.oob_callback import OOBCallbackEvidence, OOBCallbackOracle
from reachagent.oracles.structural import StructuralCheckType, StructuralEvidence, StructuralOracle
from reachagent.payloads import build_library
from reachagent.payloads.payload_resolver import required_slots, resolve, resolve_entry
from reachagent.tools import validator

_BLIND = {
    "ssrf/blind/http-callback",
    "ssrf/blind/http-callback-bare",
    "ssrf/blind/https-callback",
    "ssrf/blind/dns-only-callback",
    "ssrf/blind/file-scheme",
    "ssrf/blind/gopher-callback",
    "ssrf/blind/redirect-chain-callback",
    "ssrf/blind/internal-proxy-callback",
    "ssrf/token/oob-aws-creds-callback",
}
_NONBLIND = {
    "ssrf/nonblind/aws-imds-meta",
    "ssrf/nonblind/aws-imds-user-data",
    "ssrf/nonblind/aws-imds-instance-id",
    "ssrf/nonblind/aws-imds-iam-roles",
    "ssrf/nonblind/gcp-metadata",
    "ssrf/nonblind/azure-imds",
    "ssrf/nonblind/alibaba-ecs-meta",
    "ssrf/nonblind/digitalocean-meta",
    "ssrf/nonblind/openstack-meta",
    "ssrf/nonblind/kubernetes-api",
    "ssrf/nonblind/docker-socket",
    "ssrf/nonblind/internal-admin",
    "ssrf/token/aws-imds-iam-role",
    "ssrf/token/gcp-service-account-token",
    "ssrf/token/azure-managed-identity-token",
}
_TOKEN = {
    "ssrf/token/aws-imds-iam-role",
    "ssrf/token/gcp-service-account-token",
    "ssrf/token/azure-managed-identity-token",
    "ssrf/token/oob-aws-creds-callback",
}


# -- Sink-match + tagging --------------------------------------------------------


def test_ssrf_entries_load_and_sink_match() -> None:
    lib = build_library()
    entries = lib.get_payloads("ssrf", SinkType.URL)
    assert len(entries) >= 20
    refs = {e.payload_ref for e in entries}
    assert _BLIND <= refs and _NONBLIND <= refs
    # Oracle routing matches the three families.
    blind = [e for e in entries if e.payload_ref in _BLIND]
    nonblind = [e for e in entries if e.payload_ref in _NONBLIND]
    assert all(e.oracle_type is OracleMechanism.OOB_CALLBACK for e in blind)
    assert all(e.oracle_type is OracleMechanism.STRUCTURAL for e in nonblind)
    # Token entries carry the derived_credential edge.
    token = [e for e in entries if e.payload_ref in _TOKEN]
    assert all(e.graph_edge_on_success == "derived_credential" for e in token)
    # Non-token SSRF entries reach an internal resource.
    reaching = [e for e in entries if e.payload_ref not in _TOKEN]
    assert all(e.graph_edge_on_success == "reaches" for e in reaching)


def test_graph_edge_values_are_real_six_edges() -> None:
    real_edges = {*(e.value for e in StructuralEdge), *(e.value for e in FindingEdge)}
    lib = build_library()
    for entry in lib.get_payloads("ssrf", SinkType.URL):
        assert entry.graph_edge_on_success in real_edges


# -- Blind SSRF → OOB ------------------------------------------------------------


def test_blind_template_resolves_with_unique_nonce_and_confirms() -> None:
    nonce = "ra-ssrf-test"
    value = resolve("ssrf/blind/http-callback", nonce=nonce, collab="oob.example")
    assert f"{nonce}.oob.example" in value
    assert required_slots("ssrf/blind/http-callback") == {"nonce", "collab"}
    oracle = OOBCallbackOracle()
    v = oracle.run(OOBCallbackEvidence(probe_nonce=nonce, observed_nonces=frozenset({nonce})))
    assert v.status is FindingStatus.CONFIRMED_VIOLATION
    v = oracle.run(OOBCallbackEvidence(probe_nonce=nonce, observed_nonces=frozenset()))
    assert v.status is FindingStatus.INCONCLUSIVE


def test_all_blind_templates_carry_the_nonce() -> None:
    for ref in sorted(_BLIND):
        value = resolve(ref, nonce="ra-n", collab="oob.example")
        assert "ra-n.oob.example" in value, f"{ref} dropped the nonce"


# -- Non-blind SSRF → STRUCTURAL SSRF_RESPONSE -----------------------------------


def test_structural_decide_sentinel_in_body_confirms() -> None:
    oracle = StructuralOracle()
    v = oracle.run(
        StructuralEvidence(
            check_type=StructuralCheckType.SSRF_RESPONSE,
            probe_status=200,
            sentinel="ami-id",
            response_body="ami-id: i-1234567890abcdef0\ninstance-id: i-123",
        )
    )
    assert v.status is FindingStatus.CONFIRMED_VIOLATION
    # Sentinel absent → inconclusive (a plain 2xx is not proof of an SSRF fetch).
    v = oracle.run(
        StructuralEvidence(
            check_type=StructuralCheckType.SSRF_RESPONSE,
            probe_status=200,
            sentinel="ami-id",
            response_body="<html>not metadata</html>",
        )
    )
    assert v.status is FindingStatus.INCONCLUSIVE
    # Non-2xx → inconclusive, not a denial.
    v = oracle.run(
        StructuralEvidence(
            check_type=StructuralCheckType.SSRF_RESPONSE,
            probe_status=403,
            sentinel="ami-id",
            response_body="forbidden",
        )
    )
    assert v.status is FindingStatus.INCONCLUSIVE


def test_nonblind_templates_resolve_to_metadata_urls() -> None:
    for ref in ("ssrf/nonblind/aws-imds-meta", "ssrf/nonblind/gcp-metadata"):
        value = resolve(ref)
        assert value.startswith("http")
        assert required_slots(ref) == frozenset()


# -- End-to-end: payload → fire → run_oracle → write_finding ----------------------


def test_end_to_end_ssrf_payload_to_confirmed_finding() -> None:
    # The target echoes its (SSRF-triggered) fetch of AWS IMDS metadata.
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="ami-id: i-1234567890abcdef0\ninstance-id: i-123")

    graph = ReachabilityGraph()
    firer = RequestFirer(
        httpx.Client(transport=httpx.MockTransport(handler)),
        ScopeGuard.from_hosts(["vampi.test"]),
        AuditLog(),
    )
    lib = build_library()
    entry = next(
        e
        for e in lib.get_payloads("ssrf", SinkType.URL)
        if e.payload_ref == "ssrf/nonblind/aws-imds-meta"
    )
    payload = resolve_entry(entry)
    assert payload == "http://169.254.169.254/latest/meta-data/"

    # Fire the SSRF payload through the target (scope + read-only gates hold).
    result = firer.fire(
        "user_a", "GET", f"http://vampi.test/fetch?url={payload}", state_changing=False
    )
    body = result.body.decode(errors="replace")
    assert "ami-id" in body

    # The MCP-backed run_oracle → write_finding seam.
    verdict = validator.run_oracle(
        OracleMechanism.STRUCTURAL,
        StructuralEvidence(
            check_type=StructuralCheckType.SSRF_RESPONSE,
            probe_status=result.status_code,
            sentinel="ami-id",
            response_body=body,
        ),
    )
    assert verdict.is_violation
    node = validator.write_finding(
        graph, Finding(vuln_class="ssrf", severity="high", oracle_used="", evidence_ref=""), verdict
    )
    assert node
    assert len(graph.findings()) == 1
    assert graph.findings()[0][1].vuln_class == "ssrf"


# -- Invariants ------------------------------------------------------------------


def test_six_oracle_families_unchanged() -> None:
    assert set(OracleMechanism) == {
        OracleMechanism.DIFFERENTIAL,
        OracleMechanism.STRUCTURAL,
        OracleMechanism.TIMING_STATISTICAL,
        OracleMechanism.OOB_CALLBACK,
        OracleMechanism.EXECUTION_CONFIRMATION,
        OracleMechanism.BUSINESS_RULE_INVARIANT,
    }


def test_structural_imports_no_validator() -> None:
    import reachagent.oracles.structural as mod

    tree = ast.parse(Path(mod.__file__).read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            assert "reachagent.tools.validator" not in node.module
            assert "reachagent.tools.candidate" not in node.module
