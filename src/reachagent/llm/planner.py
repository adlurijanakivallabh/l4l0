"""Validated, proposal-only scan planning for the GUI path.

The planner turns one model JSON response into an immutable plan made entirely
from ReachAgent-owned names.  It deliberately has no execution imports: a
caller must translate the accepted tool names into the existing scoped runners.
"""

from __future__ import annotations

import json
import os
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from typing import Protocol

from reachagent.llm.client import build_openai_compatible_client, extract_json_object
from reachagent.recon.live_tuning import RECON_PROFILES
from reachagent.recon.tools import (
    AmassRunner,
    ArjunRunner,
    BbotRunner,
    CommixRunner,
    DalfoxRunner,
    DirbRunner,
    DnsreconRunner,
    DnsxRunner,
    FeroxbusterRunner,
    FfufRunner,
    GauRunner,
    GobusterRunner,
    HttpxRunner,
    JwtToolRunner,
    KatanaRunner,
    MasscanRunner,
    NaabuRunner,
    NiktoRunner,
    NmapRunner,
    NucleiRunner,
    ParamSpiderRunner,
    RustscanRunner,
    ShuffleDnsRunner,
    SqlmapRunner,
    SslscanRunner,
    SslyzeRunner,
    SubfinderRunner,
    TestsslRunner,
    TheHarvesterRunner,
    UrlfinderRunner,
    Wafw00fRunner,
    WaybackUrlsRunner,
    WhatWebRunner,
    WpscanPassiveRunner,
    X8Runner,
)
from reachagent.scan.orchestrator import ALL_CLASSES

PHASE_ORDER = (
    "recon",
    "surface",
    "insertion-points",
    "payloads",
    "verification",
    "chains",
    "report",
)
TARGET_TYPES = frozenset({"domain", "url", "ip", "cidr", "host_port"})


class PlannerClient(Protocol):
    """The small model boundary needed by :func:`plan_execution`."""

    def propose_json(self, prompt: str, *, max_tokens: int = 512) -> dict[str, object]: ...


class AnthropicPlannerClient:
    """Small Anthropic adapter for the same JSON-only planner boundary."""

    def __init__(self, *, api_key: str | None = None, model: str | None = None) -> None:
        self.api_key = api_key or os.environ.get("ANTHROPIC_API_KEY", "")
        self.model = model or os.environ.get(
            "REACHAGENT_ANTHROPIC_MODEL", "claude-3-5-sonnet-20240620"
        )

    def propose_json(self, prompt: str, *, max_tokens: int = 512) -> dict[str, object]:
        if not self.api_key:
            raise RuntimeError("ANTHROPIC_API_KEY is required for LLM scans")
        try:
            import anthropic  # type: ignore
        except Exception as exc:  # noqa: BLE001 - optional provider dependency
            raise RuntimeError(f"anthropic SDK not available: {exc}") from exc
        client = anthropic.Anthropic(api_key=self.api_key)
        response = client.messages.create(
            model=self.model,
            max_tokens=max_tokens,
            messages=[{"role": "user", "content": prompt}],
        )
        text = "".join(
            getattr(block, "text", "")
            for block in response.content
            if getattr(block, "type", "") == "text"
        )
        value = extract_json_object(text)
        return value


def build_planner_client(provider: str | None = None) -> PlannerClient:
    """Build the selected provider adapter; never silently switches providers."""

    if provider is None:
        from reachagent.llm.runtime import selected_provider

        provider = selected_provider()
    selected = provider.strip().lower()
    if not selected or selected == "anthropic":
        return AnthropicPlannerClient()
    client = build_openai_compatible_client(provider=selected)
    if client is None:
        raise RuntimeError(f"unsupported LLM provider: {provider!r}")
    return client


class PlanValidationError(ValueError):
    """A model proposal is outside the declarative execution catalog."""


@dataclass(frozen=True)
class ToolCatalogEntry:
    """One existing wrapper the model may select by name, never by command."""

    name: str
    phase: str
    target_types: frozenset[str]
    description: str = ""
    signal_gated: bool = False
    capabilities: tuple[str, ...] = ()
    produces: tuple[str, ...] = ()
    passive: bool = False
    estimated_cost: int = 1


@dataclass(frozen=True)
class PlanningContext:
    """Bounded facts passed to the model; not an execution capability."""

    target: str
    target_type: str
    in_scope: tuple[str, ...]
    graph_facts: Mapping[str, str]
    operator_prompt: str = ""
    payload_refs: tuple[str, ...] = ()
    max_request_budget: int = 80
    max_tool_budget: int = 16

    def __post_init__(self) -> None:
        if self.target_type not in TARGET_TYPES:
            raise ValueError(f"unknown target type: {self.target_type!r}")
        if self.max_request_budget < 1 or self.max_tool_budget < 1:
            raise ValueError("planner budgets must be positive")


@dataclass(frozen=True)
class PlanPhase:
    """One ordered, allowlist-only part of a scan plan."""

    name: str
    rationale: str
    tools: tuple[str, ...] = ()
    profile: str | None = None
    vuln_classes: tuple[str, ...] = ()
    payload_refs: tuple[str, ...] = ()


@dataclass(frozen=True)
class ExecutionPlan:
    """Immutable validated plan; execution remains outside this module."""

    rationale: str
    request_budget: int
    tool_budget: int
    phases: tuple[PlanPhase, ...]


def _entry(
    runner: type[object],
    phase: str,
    target_types: frozenset[str],
    *,
    description: str = "",
    signal_gated: bool = False,
    capabilities: tuple[str, ...] = (),
    produces: tuple[str, ...] = (),
    passive: bool = False,
    estimated_cost: int = 1,
) -> ToolCatalogEntry:
    name = getattr(runner, "name", "")
    if not isinstance(name, str) or not name:
        raise RuntimeError(f"runner {runner!r} has no catalog name")
    return ToolCatalogEntry(
        name,
        phase,
        target_types,
        description,
        signal_gated,
        capabilities,
        produces,
        passive,
        estimated_cost,
    )


def build_tool_catalog() -> tuple[ToolCatalogEntry, ...]:
    """Build the catalog from actual wrappers, with no command strings copied here."""

    web_targets = frozenset({"domain", "url"})
    tls_targets = frozenset({"host_port"})
    any_target = frozenset(TARGET_TYPES)
    entries = (
        # Network probes consume the extracted authority, so they are valid for
        # a URL/domain too (the dispatcher never passes a path to them).
        _entry(NmapRunner, "recon", any_target, description="Service/version scanner via -oX XML."),
        _entry(
            MasscanRunner,
            "recon",
            any_target,
            description="Ultra-fast rate-limited port scanner for large ranges.",
        ),
        _entry(
            RustscanRunner,
            "recon",
            any_target,
            description="Rapid port scanner, pipes into nmap for versioning.",
        ),
        _entry(
            NaabuRunner,
            "recon",
            any_target,
            description="Fast SYN port scanner. Lighter than nmap.",
        ),
        _entry(
            SubfinderRunner,
            "recon",
            web_targets,
            description="Passive subdomain discovery. Fast and stealthy.",
        ),
        _entry(
            AmassRunner, "recon", web_targets, description="Deep subdomain enum (passive + active)."
        ),
        _entry(
            BbotRunner,
            "recon",
            web_targets,
            description="Event-stream asset discovery (DNS, certificates, HTTP).",
        ),
        _entry(
            DnsreconRunner,
            "recon",
            web_targets,
            description="Structured DNS record and service discovery.",
        ),
        _entry(
            ShuffleDnsRunner,
            "recon",
            web_targets,
            description="Active DNS brute-force subdomain discovery.",
        ),
        _entry(DnsxRunner, "recon", web_targets, description="DNS resolution / A-record lookup."),
        _entry(
            TheHarvesterRunner, "recon", web_targets, description="OSINT email/hostname harvester."
        ),
        _entry(
            WhatWebRunner,
            "recon",
            web_targets,
            description="Web tech fingerprinter (CMS/framework/server).",
        ),
        _entry(
            HttpxRunner,
            "recon",
            web_targets,
            description="HTTP prober: live hosts + status/title/tech.",
        ),
        _entry(
            KatanaRunner,
            "recon",
            web_targets,
            description="JS-aware crawler: HTML links + JS files.",
        ),
        _entry(
            GobusterRunner,
            "recon",
            web_targets,
            description="Directory brute-force discovery via wordlist.",
        ),
        _entry(
            FfufRunner, "recon", web_targets, description="Flexible web fuzzer with JSON output."
        ),
        _entry(
            FeroxbusterRunner,
            "recon",
            web_targets,
            description="Recursive content discovery (JSON mode).",
        ),
        _entry(
            DirbRunner, "recon", web_targets, description="Classic content scanner, text output."
        ),
        _entry(
            WaybackUrlsRunner,
            "recon",
            web_targets,
            description="Passive URL discovery from archive snapshots.",
        ),
        _entry(
            GauRunner, "recon", web_targets, description="URL discovery: Crawl/URLScan/OTX/Wayback."
        ),
        _entry(
            UrlfinderRunner,
            "recon",
            web_targets,
            description="Passive URL discovery with source-attributed JSONL output.",
        ),
        _entry(Wafw00fRunner, "recon", web_targets, description="WAF fingerprinting."),
        _entry(
            TestsslRunner,
            "recon",
            tls_targets,
            description="TLS/SSL config checker: protocols + ciphers.",
        ),
        _entry(SslscanRunner, "recon", tls_targets, description="Fast TLS cipher-suite scanner."),
        _entry(
            SslyzeRunner,
            "recon",
            tls_targets,
            description="TLS analysis scanner (structured JSON).",
        ),
        _entry(
            WpscanPassiveRunner,
            "recon",
            web_targets,
            description="WordPress passive fingerprinter.",
        ),
        _entry(
            ArjunRunner,
            "insertion-points",
            web_targets,
            description="Hidden param discovery (response diff).",
        ),
        _entry(
            ParamSpiderRunner,
            "insertion-points",
            web_targets,
            description="Query-param mining from archived URLs.",
        ),
        _entry(
            X8Runner,
            "insertion-points",
            web_targets,
            description="Param brute-force + reflection check.",
        ),
        _entry(
            NucleiRunner,
            "verification",
            any_target,
            signal_gated=True,
            description="Template vuln scanner (gated on tech signal).",
        ),
        _entry(
            NiktoRunner,
            "verification",
            any_target,
            signal_gated=True,
            description="Server misconfig claims (gated on tech).",
        ),
        _entry(
            SqlmapRunner,
            "verification",
            any_target,
            signal_gated=True,
            description="SQL injection testing (gated on SQL sink).",
        ),
        _entry(
            DalfoxRunner,
            "verification",
            any_target,
            signal_gated=True,
            description="XSS scanner (gated on html_reflection).",
        ),
        _entry(
            CommixRunner,
            "verification",
            any_target,
            signal_gated=True,
            description="Command injection tester (gated on shell).",
        ),
        _entry(
            JwtToolRunner,
            "verification",
            any_target,
            signal_gated=True,
            description="JWT security analyzer (gated on auth path).",
        ),
    )
    if len({entry.name for entry in entries}) != len(entries):
        raise RuntimeError("recon catalog has duplicate wrapper names")

    # Keep the catalog descriptive enough for an LLM to choose a next tool from
    # observed graph state, without exposing command strings or accepting model
    # supplied flags. Defaults cover every existing adapter; the explicit map
    # records the useful distinction between passive enrichment and active
    # network/content discovery.
    metadata: dict[str, tuple[tuple[str, ...], tuple[str, ...], bool, int]] = {
        "nmap": (("port discovery", "service fingerprinting"), ("Host", "Service"), False, 3),
        "masscan": (("fast port discovery",), ("Host", "Service"), False, 2),
        "rustscan": (("fast port discovery",), ("Host", "Service"), False, 2),
        "naabu": (("verified port discovery",), ("Host", "Service"), False, 2),
        "subfinder": (("passive subdomain discovery",), ("Host",), True, 1),
        "amass": (("passive/active subdomain discovery",), ("Host",), True, 3),
        "bbot": (
            ("event-driven asset discovery", "DNS", "certificates", "HTTP"),
            ("Host", "Service", "Endpoint"),
            True,
            3,
        ),
        "dnsrecon": (("DNS records", "zone/service discovery"), ("Host",), True, 2),
        "shuffledns": (("active DNS brute force",), ("Host",), False, 2),
        "dnsx": (("DNS resolution",), ("Host",), True, 1),
        "theHarvester": (("passive OSINT host discovery",), ("Host",), True, 2),
        "whatweb": (("web technology fingerprinting",), ("Host", "Endpoint"), True, 1),
        "httpx": (
            ("HTTP reachability", "status/title/technology probing"),
            ("Host", "Endpoint"),
            True,
            1,
        ),
        "katana": (("scoped crawling", "JavaScript/XHR discovery"), ("Host", "Endpoint"), False, 2),
        "gobuster": (("directory/content discovery",), ("Host", "Endpoint"), False, 2),
        "ffuf": (("calibrated path/content discovery",), ("Host", "Endpoint"), False, 2),
        "feroxbuster": (("recursive content discovery",), ("Host", "Endpoint"), False, 2),
        "dirb": (("legacy content discovery",), ("Host", "Endpoint"), False, 2),
        "waybackurls": (("historical URL discovery",), ("Host", "Endpoint"), True, 1),
        "gau": (("multi-source historical URL discovery",), ("Host", "Endpoint"), True, 1),
        "urlfinder": (
            ("passive URL discovery", "source attribution"),
            ("Host", "Endpoint"),
            True,
            1,
        ),
        "wafw00f": (("WAF fingerprinting",), ("Host",), True, 1),
        "testssl": (("TLS protocol/cipher inventory",), ("Host",), True, 2),
        "sslscan": (("TLS protocol/cipher inventory",), ("Host",), True, 2),
        "sslyze": (("TLS protocol/cipher inventory",), ("Host",), True, 2),
        "wpscan": (("passive CMS fingerprinting",), ("Host", "Endpoint"), True, 2),
    }
    enriched: list[ToolCatalogEntry] = []
    for entry in entries:
        capabilities, produces, passive, estimated_cost = metadata.get(
            entry.name,
            ((entry.description,) if entry.description else ("recon facts",), ("Host",), False, 1),
        )
        enriched.append(
            replace(
                entry,
                capabilities=capabilities,
                produces=produces,
                passive=passive,
                estimated_cost=estimated_cost,
            )
        )
    return tuple(enriched)


def _bounded_facts(facts: Mapping[str, str]) -> dict[str, str]:
    """Keep graph context useful without creating an unbounded prompt."""

    return {
        str(key)[:80]: str(value)[:240]
        for key, value in sorted(facts.items(), key=lambda pair: str(pair[0]))[:50]
    }


def planning_prompt(
    context: PlanningContext, catalog: Sequence[ToolCatalogEntry] | None = None
) -> str:
    """Build the JSON-only prompt; the catalog exposes names, never command lines."""

    entries = tuple(catalog or build_tool_catalog())
    catalog_json = [
        {
            "name": entry.name,
            "phase": entry.phase,
            "target_types": sorted(entry.target_types),
            "description": entry.description,
            "signal_gated": entry.signal_gated,
            "capabilities": list(entry.capabilities),
            "produces": list(entry.produces),
            "passive": entry.passive,
            "estimated_cost": entry.estimated_cost,
        }
        for entry in entries
    ]
    context_json = {
        "target": context.target[:500],
        "target_type": context.target_type,
        "in_scope": list(context.in_scope),
        "graph_facts": _bounded_facts(context.graph_facts),
        "operator_goal": context.operator_prompt[:500],
        "allowed_payload_refs": list(context.payload_refs[:100]),
        "max_request_budget": context.max_request_budget,
        "max_tool_budget": context.max_tool_budget,
    }
    schema = {
        "rationale": "short plan rationale",
        "request_budget": "positive integer <= max_request_budget",
        "tool_budget": "positive integer <= max_tool_budget",
        "phases": [
            {
                "name": "one allowed phase",
                "rationale": "short phase rationale",
                "tools": ["catalog names only"],
                "profile": "optional recon profile name",
                "vuln_classes": ["ALL_CLASSES names only"],
                "payload_refs": ["allowed_payload_refs only"],
            }
        ],
    }
    return (
        "You are a constrained ReachAgent planner for an AUTHORIZED lab assessment. "
        "Choose only catalog names and allowlisted classes/payload refs. Never include a command, "
        "URL, request body, headers, state-changing option, or a finding. "
        "Signal-gated tools remain conditional on graph evidence. "
        "Keep phases in the supplied order and do not repeat a tool.\n"
        "The optional profile field is valid only on the phase whose name is "
        "exactly 'recon'; omit profile from every other phase. If no profile "
        "fits, omit it from recon too.\n"
        f"Allowed phases: {json.dumps(PHASE_ORDER)}\n"
        f"Allowed recon profiles (use ONLY these names in the recon phase's optional"
        f" profile field; omit profile entirely if none fits): "
        f"{json.dumps(sorted(RECON_PROFILES))}\n"
        f"Catalog: {json.dumps(catalog_json, sort_keys=True)}\n"
        f"Classes: {json.dumps(ALL_CLASSES)}\n"
        f"Context: {json.dumps(context_json, sort_keys=True)}\n"
        f"Response schema: {json.dumps(schema, sort_keys=True)}"
    )


@dataclass(frozen=True)
class ReconSelection:
    """One bounded, allowlist-validated recon continuation decision."""

    tools: tuple[str, ...]
    rationale: str
    stop: bool = False


def recon_selection_prompt(
    context: PlanningContext,
    *,
    state: Mapping[str, str],
    available_tools: Sequence[str],
    completed_tools: Sequence[str] = (),
) -> str:
    """Build a compact prompt for adaptive recon tool selection.

    The model receives only bounded facts and catalog metadata. It chooses the
    next fact-emitters; it never receives command strings or a way to alter the
    execution/oracle boundary.
    """

    catalog = {
        entry.name: {
            "capabilities": list(entry.capabilities),
            "produces": list(entry.produces),
            "passive": entry.passive,
            "estimated_cost": entry.estimated_cost,
            "description": entry.description,
        }
        for entry in build_tool_catalog()
        if entry.phase == "recon" and entry.name in set(available_tools)
    }
    schema = {
        "tools": ["catalog names only; zero or more not-yet-completed tools"],
        "rationale": "why these tools are the best next bounded fact sources",
        "stop": "true only when additional recon has low expected value",
    }
    state_json = {
        str(key)[:80]: str(value)[:2_000]
        for key, value in sorted(state.items(), key=lambda pair: str(pair[0]))[:40]
    }
    return (
        "You are the adaptive recon planner for an authorized web/API assessment. "
        "Choose only fact-emitting recon tools from the supplied catalog. The next "
        "decision must use the current bounded graph/audit state, avoid completed "
        "tools, and stay within the remaining tool budget. Do not emit commands, "
        "flags, URLs, payloads, exploit claims, or vulnerability verdicts. "
        "Return exactly one JSON object matching the schema. Set stop=true only "
        "when the marginal coverage of every remaining tool is low; otherwise "
        "select one or more concrete next tools and explain the evidence gap.\n"
        f"Target: {context.target[:500]}\n"
        f"Target type: {context.target_type}\n"
        f"Operator goal: {context.operator_prompt[:500]}\n"
        f"Completed tools: {json.dumps(list(completed_tools))}\n"
        f"Available tools: {json.dumps(list(available_tools))}\n"
        f"Current state: {json.dumps(state_json, sort_keys=True)}\n"
        f"Catalog: {json.dumps(catalog, sort_keys=True)}\n"
        f"Remaining tool budget: {context.max_tool_budget}\n"
        f"Response schema: {json.dumps(schema, sort_keys=True)}"
    )


def validate_recon_selection(
    raw: Mapping[str, object],
    *,
    context: PlanningContext,
    available_tools: Sequence[str],
    completed_tools: Sequence[str] = (),
    max_tools: int | None = None,
) -> ReconSelection:
    """Reject unknown, repeated, signal-gated, or incompatible selections."""

    _reject_unknown_keys(raw, frozenset({"tools", "rationale", "stop"}), "recon selection")
    rationale = _required_string(raw.get("rationale"), "recon selection rationale")
    stop = raw.get("stop")
    if not isinstance(stop, bool):
        raise PlanValidationError("recon selection stop must be a boolean")
    tools = _string_list(raw.get("tools"), "recon selection tools")
    available = set(available_tools)
    completed = set(completed_tools)
    catalog = {entry.name: entry for entry in build_tool_catalog()}
    selected: list[str] = []
    for name in tools:
        entry = catalog.get(name)
        if entry is None or name not in available:
            raise PlanValidationError(f"recon selection contains unavailable tool: {name!r}")
        if entry.phase != "recon" or entry.signal_gated:
            raise PlanValidationError(f"recon selection tool is not a fact emitter: {name!r}")
        if context.target_type not in entry.target_types:
            raise PlanValidationError(
                f"recon selection tool {name!r} is incompatible with {context.target_type!r}"
            )
        if name in completed:
            raise PlanValidationError(f"recon selection repeats completed tool: {name!r}")
        selected.append(name)
    limit = max_tools if max_tools is not None else context.max_tool_budget
    if limit < 1:
        raise PlanValidationError("recon selection tool limit must be positive")
    if len(selected) > limit:
        raise PlanValidationError("recon selection exceeds the remaining tool budget")
    if not selected and not stop:
        raise PlanValidationError("recon selection must choose a tool or set stop=true")
    return ReconSelection(tuple(selected), rationale, stop)


def select_recon_tools(
    context: PlanningContext,
    client: PlannerClient,
    *,
    state: Mapping[str, str],
    available_tools: Sequence[str],
    completed_tools: Sequence[str] = (),
    max_tools: int | None = None,
) -> ReconSelection:
    """Ask the configured LLM for the next recon tools and validate its answer.

    Validation-only failures get at most two bounded fixer turns; provider
    failures still propagate immediately so a strict scan cannot silently
    continue with an unreasoned sequence.
    """

    raw = client.propose_json(
        recon_selection_prompt(
            context,
            state=state,
            available_tools=available_tools,
            completed_tools=completed_tools,
        ),
        max_tokens=1_024,
    )
    last_error: PlanValidationError | None = None
    for _attempt in range(3):
        try:
            return validate_recon_selection(
                raw,
                context=context,
                available_tools=available_tools,
                completed_tools=completed_tools,
                max_tools=max_tools,
            )
        except PlanValidationError as exc:
            last_error = exc
            if _attempt == 2:
                break
            raw = client.propose_json(
                "The recon selection JSON was rejected by strict validation. "
                f"VALIDATION ERROR: {exc}. Return one corrected JSON object only; "
                "preserve the evidence-based intent, choose only available fact "
                "emitters, and never include commands or vulnerability claims.\n"
                f"Previous JSON: {json.dumps(raw, sort_keys=True)[:4_000]}",
                max_tokens=1_024,
            )
    raise last_error or PlanValidationError("recon selection failed without a validation error")


def _mapping(value: object, label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise PlanValidationError(f"{label} must be an object")
    if not all(isinstance(key, str) for key in value):
        raise PlanValidationError(f"{label} keys must be strings")
    return value


def _string(value: object, label: str, *, required: bool = True) -> str | None:
    if value is None and not required:
        return None
    if not isinstance(value, str) or not value.strip():
        raise PlanValidationError(f"{label} must be a non-empty string")
    text = value.strip()
    if len(text) > 500:
        raise PlanValidationError(f"{label} exceeds 500 characters")
    return text


def _required_string(value: object, label: str) -> str:
    text = _string(value, label)
    if text is None:  # defensive for the optional helper's return type
        raise PlanValidationError(f"{label} is required")
    return text


def _positive_int(value: object, label: str, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= maximum:
        raise PlanValidationError(f"{label} must be an integer from 1 to {maximum}")
    return value


def _string_list(value: object, label: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
        raise PlanValidationError(f"{label} must be a list of non-empty strings")
    values = tuple(item.strip() for item in value)
    if len(values) != len(set(values)):
        raise PlanValidationError(f"{label} must not contain duplicates")
    return values


def _reject_unknown_keys(raw: Mapping[str, object], allowed: frozenset[str], label: str) -> None:
    unexpected = sorted(set(raw) - allowed)
    if unexpected:
        raise PlanValidationError(f"{label} contains unsupported fields: {', '.join(unexpected)}")


def validate_execution_plan(
    raw: Mapping[str, object],
    context: PlanningContext,
    *,
    catalog: Sequence[ToolCatalogEntry] | None = None,
) -> ExecutionPlan:
    """Validate model JSON without executing anything or falling back silently."""

    _reject_unknown_keys(
        raw,
        frozenset({"rationale", "request_budget", "tool_budget", "phases"}),
        "plan",
    )
    rationale = _required_string(raw.get("rationale"), "plan rationale")
    request_budget = _positive_int(
        raw.get("request_budget"), "request_budget", context.max_request_budget
    )
    tool_budget = _positive_int(raw.get("tool_budget"), "tool_budget", context.max_tool_budget)
    phases_raw = raw.get("phases")
    if not isinstance(phases_raw, list) or not phases_raw:
        raise PlanValidationError("phases must be a non-empty list")

    catalog_by_name = {entry.name: entry for entry in (catalog or build_tool_catalog())}
    profiles = frozenset(RECON_PROFILES)
    allowed_classes = frozenset(ALL_CLASSES)
    allowed_payloads = frozenset(context.payload_refs)
    phases: list[PlanPhase] = []
    used_tools: set[str] = set()
    last_phase = -1

    for index, value in enumerate(phases_raw):
        phase_raw = _mapping(value, f"phases[{index}]")
        _reject_unknown_keys(
            phase_raw,
            frozenset({"name", "rationale", "tools", "profile", "vuln_classes", "payload_refs"}),
            f"phases[{index}]",
        )
        name = _string(phase_raw.get("name"), f"phases[{index}].name")
        if name not in PHASE_ORDER:
            raise PlanValidationError(f"unknown phase: {name!r}")
        phase_position = PHASE_ORDER.index(name)
        if phase_position <= last_phase:
            raise PlanValidationError("phases must be unique and follow the allowed order")
        last_phase = phase_position
        phase_rationale = _required_string(phase_raw.get("rationale"), f"phases[{index}].rationale")
        tools = _string_list(phase_raw.get("tools"), f"phases[{index}].tools")
        if name == "recon" and not tools:
            raise PlanValidationError("recon phase must select at least one catalog tool")
        for tool_name in tools:
            entry = catalog_by_name.get(tool_name)
            if entry is None:
                raise PlanValidationError(f"unknown tool: {tool_name!r}")
            if entry.phase != name and not (name == "surface" and entry.phase == "recon"):
                raise PlanValidationError(f"tool {tool_name!r} is not valid in phase {name!r}")
            if context.target_type not in entry.target_types:
                raise PlanValidationError(
                    f"tool {tool_name!r} is not compatible with {context.target_type!r}"
                )
            if tool_name in used_tools:
                raise PlanValidationError(f"tool {tool_name!r} is selected more than once")
            used_tools.add(tool_name)

        profile = _string(phase_raw.get("profile"), f"phases[{index}].profile", required=False)
        if profile is not None and (name != "recon" or profile not in profiles):
            raise PlanValidationError(
                "profile must be an allowlisted recon profile in the recon phase"
            )

        vuln_classes = _string_list(phase_raw.get("vuln_classes"), f"phases[{index}].vuln_classes")
        if vuln_classes and name not in {"insertion-points", "payloads", "verification"}:
            raise PlanValidationError(
                "vulnerability classes are valid only in insertion-points, payloads, "
                "or verification"
            )
        unknown_classes = sorted(set(vuln_classes) - allowed_classes)
        if unknown_classes:
            raise PlanValidationError(
                f"unknown vulnerability classes: {', '.join(unknown_classes)}"
            )

        payload_refs = _string_list(phase_raw.get("payload_refs"), f"phases[{index}].payload_refs")
        if payload_refs and name != "payloads":
            raise PlanValidationError("payload references are valid only in the payloads phase")
        unknown_payloads = sorted(set(payload_refs) - allowed_payloads)
        if unknown_payloads:
            raise PlanValidationError(f"unknown payload references: {', '.join(unknown_payloads)}")

        phases.append(
            PlanPhase(
                name=name,
                rationale=phase_rationale,
                tools=tools,
                profile=profile,
                vuln_classes=vuln_classes,
                payload_refs=payload_refs,
            )
        )

    required_phases = {"recon", "surface", "insertion-points", "payloads", "report"}
    selected_phases = {phase.name for phase in phases}
    missing_phases = sorted(required_phases - selected_phases)
    if missing_phases:
        raise PlanValidationError(f"plan is missing required phases: {', '.join(missing_phases)}")
    if len(used_tools) > tool_budget:
        raise PlanValidationError("selected tools exceed tool_budget")
    return ExecutionPlan(
        rationale=rationale,
        request_budget=request_budget,
        tool_budget=tool_budget,
        phases=tuple(phases),
    )


def plan_execution(
    context: PlanningContext,
    client: PlannerClient,
    *,
    catalog: Sequence[ToolCatalogEntry] | None = None,
) -> ExecutionPlan:
    """Plan with a validation-fixer loop.

    First attempt uses the plain planning prompt. On validation failure, the
    validator's error and the rejected JSON go back to the model with a fixer
    instruction maximal-correction discipline: minimal correction, same intent, schema-conformant
    output only. Provider
    and network failures still propagate immediately - only validation errors
    are fixable.
    """
    entries = tuple(catalog or build_tool_catalog())
    raw = client.propose_json(planning_prompt(context, entries), max_tokens=4096)
    last_error: PlanValidationError | None = None
    for _attempt in range(3):
        try:
            return validate_execution_plan(raw, context, catalog=entries)
        except PlanValidationError as exc:
            last_error = exc
            fix_prompt = (
                "Your previous plan JSON was rejected by strict validation.\n"
                f"VALIDATION ERROR: {exc}\n\n"
                f"YOUR PREVIOUS (REJECTED) JSON:\n{json.dumps(raw)[:4000]}\n\n\n"
                "Fix it with MINIMAL changes preserving your original intent. "
                "Same rules as before: only catalog tool names, only allowlisted "
                "phase/class/profile/payload values. Return ONE corrected JSON object only."
            )
            raw = client.propose_json(fix_prompt, max_tokens=4096)
    if last_error is not None:
        raise last_error
    raise PlanValidationError("planning failed without a validator error")
