"""The ``record_finding`` agent tool — validate, ground, score CVSS, dedup, land.

Pure tool-interface wiring over the deterministic pieces built in this
module: :func:`~lalo.findings.model.validate_finding_fields` gates only the
call shape (never a truth judgment), a real
:class:`~lalo.findings.model.Finding` is constructed from the validated
fields so mypy can catch a future rename/type drift between what this tool
writes and what the dataclass declares, :func:`~lalo.findings.grounding.is_grounded`
checks the claimed excerpt against real captured evidence,
:func:`~lalo.findings.cvss.compute_cvss` scores severity from the breakdown,
and :func:`~lalo.findings.dedup.find_duplicate` merges repeat evidence into
one node instead of filing a second finding for the same
class+target+param. Every field is redacted before it ever reaches the
graph, since the graph is JSON-persisted to disk.

A finding lands unconditionally the moment its required fields are present —
per CLAUDE.md, nothing here withholds a finding for weak or ungrounded
evidence. An excerpt that fails the grounding check is recorded with
``evidence_grounded=False`` so :mod:`~lalo.findings.confidence` (next slice
of this phase) can score it down and flag it, never drop it.
"""

from __future__ import annotations

import uuid
from typing import Any

from ..agent.tools import FunctionTool, ToolResult
from ..core.redaction import redact, safe_target_url
from ..graph.model import EdgeKind, NodeKind, ReachabilityGraph
from .cvss import compute_cvss
from .dedup import dedup_key, find_duplicate
from .grounding import is_grounded
from .model import Finding, validate_finding_fields


def _as_evidence_list(raw: object) -> list[str]:
    if not isinstance(raw, list):
        return []
    return [str(item) for item in raw if str(item).strip()]


def _as_str_dict(raw: object) -> dict[str, str]:
    if not isinstance(raw, dict):
        return {}
    return {str(k): str(v) for k, v in raw.items()}


def _sanitize_source_location(value: str) -> str | None:
    """Reject a ``source_location`` shaped like a path-traversal or
    filesystem-escape attempt rather than an ordinary repo-relative
    ``path/to/file.py:123`` reference: a ``..`` segment, a leading ``/``
    (absolute path), or a backslash (a Windows drive-letter/UNC path).

    This is report-output data integrity, not a testing restriction: it never
    rejects the finding, never blocks the agent, and carries no allowlist of
    "acceptable" paths - it only stops :mod:`~lalo.report.sarif` from ever
    embedding an escape-shaped string verbatim into SARIF's
    ``artifactLocation.uri``. A value that fails this shape check is simply
    dropped by the caller; every other field the agent reported still lands.
    """
    if ".." in value or value.startswith("/") or "\\" in value:
        return None
    return value


def _link_enabling_finding(
    graph: ReachabilityGraph, finding_id: str, args: dict[str, object]
) -> str:
    """Add an :data:`EdgeKind.ENABLES` edge from an already-recorded finding
    to ``finding_id``, if ``args`` declares one via ``enabled_by_finding_id``.

    This is the only place anything in the codebase ever creates an ENABLES
    edge — without it, :meth:`~lalo.graph.model.ReachabilityGraph.
    all_enabling_chains` and :mod:`~lalo.findings.confidence`'s own
    ``chained_impact_success`` component (both already built and tested)
    have no real data to ever act on. An agent declares this explicitly when
    it recognizes a genuine attack-chain step (this IDOR's access is what
    let it reach that RCE) — never inferred automatically, matching this
    project's authoritative-filed-reports discipline elsewhere.

    Returns a short suffix for the caller's own observation string — never
    raises, and an unresolvable reference is a warning, not a failure: the
    finding being recorded right now is real regardless of whether its
    claimed chain predecessor can be verified.
    """
    raw = args.get("enabled_by_finding_id")
    if not raw:
        return ""
    enabled_by_id = str(raw).strip()
    if not enabled_by_id:
        return ""
    known = graph.has_node(enabled_by_id)
    if not known or graph.node(enabled_by_id).get("kind") != NodeKind.FINDING.value:
        return (
            f" (WARNING: enabled_by_finding_id {enabled_by_id!r} is not a known "
            "finding - no chain link recorded)"
        )
    graph.add_edge(enabled_by_id, finding_id, EdgeKind.ENABLES)
    return f" (chained: enabled by {enabled_by_id})"


def build_record_finding_tool(graph: ReachabilityGraph) -> FunctionTool:
    def _record_finding(args: dict[str, object]) -> ToolResult:
        evidence = _as_evidence_list(args.get("evidence"))
        fields = {**args, "evidence": evidence}
        errors = validate_finding_fields(fields)
        if errors:
            return ToolResult(observation="error: " + "; ".join(errors), ok=False)

        vuln_class = str(fields["vuln_class"])
        # Redacted immediately, before anything derives from it: a target can
        # legitimately embed a secret (a password-reset link, a session id in
        # the path), and safe_target_url() understands URL structure (strips
        # userinfo, redacts sensitive query values, keeps scheme/host/path
        # readable) in a way the generic redact() does not. Every downstream
        # use - the dedup key, the graph node, the observation string, and
        # (via the graph) the payload later shown to the LLM adversarial
        # reviewer - reads this already-redacted value, never the raw one.
        target = safe_target_url(str(fields["target"]))
        param = redact(str(args["param"])) if args.get("param") else None
        excerpt = str(fields["evidence_excerpt"])
        grounded = is_grounded(excerpt, evidence)
        cvss_breakdown = _as_str_dict(args.get("cvss_breakdown"))
        cvss = compute_cvss(cvss_breakdown)
        identities_raw = args.get("identities_confirmed")
        identities = [str(i) for i in identities_raw] if isinstance(identities_raw, list) else []
        reproduced = bool(args.get("reproduced", False))
        source_location = None
        source_location_note = ""
        if args.get("source_location"):
            candidate = redact(str(args["source_location"]))
            source_location = _sanitize_source_location(candidate)
            if source_location is None:
                source_location_note = (
                    f" (WARNING: source_location {candidate!r} looked like a path-escape "
                    "attempt - dropped, finding recorded without it)"
                )

        key = dedup_key(vuln_class, target, param)
        existing_id = find_duplicate(graph, key)
        if existing_id is not None:
            existing = graph.node(existing_id)
            merged_evidence = [*existing.get("evidence", []), *[redact(e) for e in evidence]]
            merged_identities = sorted(
                set(existing.get("identities_confirmed", [])) | set(identities)
            )
            # Strongest-signal-wins, not first-writer-wins: a later filing of
            # the SAME dedup_key can be materially more (or less) severe than
            # the first one L4L0 happened to see - keeping whichever score is
            # higher means a weaker duplicate never waters down an already-
            # established stronger signal, and a stronger duplicate correctly
            # upgrades an initially-underestimated one, mirroring the
            # strongest-signal-across-merged-observations principle a studied
            # reference agent's own reconciliation logic applies for the
            # analogous cross-producer case.
            existing_score = float(existing.get("cvss_score", 0.0))
            merge_fields: dict[str, object] = {
                "evidence": merged_evidence,
                "identities_confirmed": merged_identities,
                "reproduced": existing.get("reproduced", False) or reproduced,
                "evidence_grounded": existing.get("evidence_grounded", False) or grounded,
            }
            if cvss.score > existing_score:
                merge_fields["cvss_score"] = cvss.score
                merge_fields["cvss_severity"] = cvss.severity
                merge_fields["cvss_vector"] = cvss.vector
            graph.add_node(existing_id, NodeKind.FINDING, **merge_fields)
            chain_note = _link_enabling_finding(graph, existing_id, args)
            return ToolResult(
                observation=(
                    f"merged into existing finding {existing_id} "
                    f"(same {vuln_class} on {target}"
                    + (f" param={param}" if param else "")
                    + f") - now {len(merged_evidence)} evidence item(s), "
                    f"grounded={existing.get('evidence_grounded', False) or grounded}"
                    f"{chain_note}"
                ),
                ok=True,
            )

        # A real, type-checked intermediate rather than a dict built from
        # loose local variables: Finding is otherwise never constructed
        # anywhere in the codebase, so mypy has nothing to catch a future
        # rename/type drift between what this tool writes and what Finding
        # itself declares. Everything Finding doesn't cover (the computed
        # CVSS fields, evidence_grounded, dedup_key) is added alongside it.
        finding = Finding(
            title=redact(str(fields["title"])),
            description=redact(str(fields["description"])),
            vuln_class=vuln_class,
            target=target,
            evidence=[redact(e) for e in evidence],
            evidence_excerpt=redact(excerpt),
            counterevidence=redact(str(fields["counterevidence"])),
            severity_change_conditions=redact(str(fields["severity_change_conditions"])),
            remediation=redact(str(fields["remediation"])),
            cvss_breakdown=cvss_breakdown,
            param=param,
            reproduced=reproduced,
            identities_confirmed=identities,
            source_location=source_location,
        )
        finding_id = f"finding-{uuid.uuid4().hex[:12]}"
        attrs: dict[str, Any] = {
            "dedup_key": key,
            "title": finding.title,
            "description": finding.description,
            "vuln_class": finding.vuln_class,
            "target": finding.target,
            "param": finding.param,
            "evidence": finding.evidence,
            "evidence_excerpt": finding.evidence_excerpt,
            "evidence_grounded": grounded,
            "counterevidence": finding.counterevidence,
            "severity_change_conditions": finding.severity_change_conditions,
            "remediation": finding.remediation,
            "cvss_breakdown": finding.cvss_breakdown,
            "cvss_score": cvss.score,
            "cvss_severity": cvss.severity,
            "cvss_vector": cvss.vector,
            "reproduced": finding.reproduced,
            "identities_confirmed": finding.identities_confirmed,
            "source_location": finding.source_location,
        }
        graph.add_node(finding_id, NodeKind.FINDING, **attrs)
        for i, blob in enumerate(evidence):
            evidence_id = f"{finding_id}-evidence-{i}"
            graph.add_node(evidence_id, NodeKind.EVIDENCE, content=redact(blob))
            graph.add_edge(evidence_id, finding_id, EdgeKind.SUPPORTS)

        grounding_note = "" if grounded else " (WARNING: evidence_excerpt not found in evidence)"
        chain_note = _link_enabling_finding(graph, finding_id, args)
        return ToolResult(
            observation=(
                f"recorded {finding_id}: {vuln_class} on {target} - "
                f"cvss={cvss.score:.1f} ({cvss.severity}){grounding_note}"
                f"{source_location_note}{chain_note}"
            ),
            ok=True,
        )

    return FunctionTool(
        name="record_finding",
        description=(
            "File a vulnerability finding. Lands immediately and unconditionally once "
            "required fields are present - it is never blocked on how strong the "
            "evidence is, only on whether the fields are filled in. args: "
            '{"title": str, "description": str, '
            '"vuln_class": str (a short, hyphenated slug matching the recalled skill\'s '
            'own name - e.g. "sql-injection", "access-control", "jwt", "xss", "ssrf" - '
            "never a full sentence, a CWE id, or an OWASP category name; coverage "
            'reporting and eval scoring both match this field by exact name), "target": str, '
            '"evidence": list[str] (raw captured proof - response bodies, OAST hits, '
            'command output), "evidence_excerpt": str (the specific proof text - must '
            "literally appear in one of the evidence entries: copy it verbatim, "
            "character-for-character, from that entry - do not paraphrase it, wrap it in "
            "your own label or brackets, or re-pretty-print JSON with different spacing "
            "than you wrote in evidence itself; an excerpt that only LOOKS like the proof "
            'is flagged as ungrounded and scored lower), "counterevidence": str '
            "(the strongest case against this finding, or what you checked and found "
            'none of), "severity_change_conditions": str (what would raise/lower '
            'severity), "remediation": str (concrete steps to fix or mitigate this), '
            '"cvss_breakdown": {"attack_vector": "N|A|L|P", '
            '"attack_complexity": "L|H", "privileges_required": "N|L|H", '
            '"user_interaction": "N|R", "scope": "U|C", "confidentiality": "N|L|H", '
            '"integrity": "N|L|H", "availability": "N|L|H"}, "param": str (optional), '
            '"reproduced": bool (optional, default false), "identities_confirmed": '
            "list[str] (optional, identity names this was reproduced under), "
            '"source_location": str (optional, "path/to/file.py:123" - set this when '
            "you traced the vulnerability to a specific line in a source repository "
            "you were given access to; omit it entirely when working black-box; a value "
            "shaped like a path escape - containing '..', starting with '/', or containing "
            "a backslash - is dropped rather than recorded, the rest of the finding is "
            "unaffected), "
            '"enabled_by_finding_id": str (optional - the id of an already-recorded '
            "finding whose exploitation is what let you reach THIS one, e.g. an IDOR "
            "that exposed the credentials used here. Only declare a real attack-chain "
            "step you actually traced, never a guess.)}"
        ),
        func=_record_finding,
    )
