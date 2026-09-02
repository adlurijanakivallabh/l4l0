"""Read-only HTML/JavaScript surface extraction.

The parser is deliberately facts-only: it turns observed forms, links, and
browser/API call literals into :class:`EndpointSpec` records. It never submits
a form, evaluates JavaScript, or emits a candidate/finding. All limits are
bounded so an unusually large page cannot flood the planner context.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from html.parser import HTMLParser
from urllib.parse import parse_qsl, urljoin, urlsplit

from reachagent.graph.nodes import Protocol
from reachagent.recon.mapper import EndpointSpec, ParameterSpec

_READ_ONLY = frozenset({"GET", "HEAD", "OPTIONS"})
_MAX_FORM_CONTROLS = 100
_MAX_FORMS = 50
_MAX_LINKS = 100
_MAX_SCRIPTS = 40
_MAX_SCRIPT_CHARS = 200_000
_MAX_ENDPOINTS = 200
_MAX_PARAMETERS = 500
_URL_RE = re.compile(r"(?P<quote>['\"])(?P<url>(?:https?://|/)[^'\"\s]{1,500})(?P=quote)")
_FETCH_RE = re.compile(
    r"\bfetch\s*\(\s*(?P<quote>['\"])(?P<url>[^'\"]{1,500})(?P=quote)(?P<tail>[^;]{0,1600})",
    re.IGNORECASE | re.DOTALL,
)
_AXIOS_RE = re.compile(
    r"\baxios\s*\.\s*(?P<method>get|post|put|patch|delete|head|options)\s*\(\s*"
    r"(?P<quote>['\"])(?P<url>[^'\"]{1,500})(?P=quote)(?P<tail>[^;]{0,1600})",
    re.IGNORECASE | re.DOTALL,
)
_XHR_RE = re.compile(
    r"\.open\s*\(\s*(?P<quote>['\"])(?P<method>GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)"
    r"(?P=quote)\s*,\s*(?P<urlquote>['\"])(?P<url>[^'\"]{1,500})(?P=urlquote)",
    re.IGNORECASE,
)
_METHOD_RE = re.compile(r"\bmethod\s*:\s*['\"](?P<method>[A-Za-z]+)['\"]", re.IGNORECASE)
_CONTENT_TYPE_RE = re.compile(
    r"(?:content-type|Content-Type)\s*['\"]?\s*[:=]\s*['\"](?P<value>[^'\"]+)['\"]",
    re.IGNORECASE,
)
_OBJECT_KEY_RE = re.compile(r"(?:^|[,\{])\s*['\"]?(?P<name>[A-Za-z_$][\w$.-]*)['\"]?\s*:")
_GRAPHQL_FIELD_RE = re.compile(r"\b(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*(?=\(|\{|$)")
_GRAPHQL_ARG_RE = re.compile(r"\b(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*:")


@dataclass(frozen=True)
class ParsedSurface:
    """Bounded parser output before graph materialization."""

    endpoints: tuple[EndpointSpec, ...] = ()
    links: tuple[str, ...] = ()
    scripts: tuple[str, ...] = ()


def evidence_ref(source: str, detail: str) -> str:
    """Create a stable, secret-free evidence handle for one observed fact."""
    digest = hashlib.sha256(f"{source}\n{detail}".encode()).hexdigest()[:16]
    return f"surface:{digest}"


def _path_and_query(raw_url: str, base_url: str) -> tuple[str, str] | None:
    absolute = urljoin(base_url, raw_url)
    parts = urlsplit(absolute)
    if parts.scheme not in {"http", "https"} or not parts.netloc:
        return None
    # An absolute link to a DIFFERENT host (a footer "powered by" link to the
    # project's own GitHub repo, a CDN asset, a social-share URL, ...) must never
    # be treated as a same-site path — urljoin() resolving it fine and it having a
    # real scheme+netloc says nothing about it being ON the scanned site. Silently
    # keeping only its path (dropping the real host) previously fabricated a
    # phantom same-host endpoint from any such link — caught live (DVWA linking to
    # github.com/digininja/DVWA materialized as if `/digininja/DVWA` existed on
    # the scanned target). ScopeGuard would still refuse firing at it later, but
    # by then it's already wasted a probe and shown up in the graph/report as if
    # it were real target surface.
    if parts.netloc.lower() != urlsplit(base_url).netloc.lower():
        return None
    return parts.path or "/", parts.query


def _query_parameters(query: str, source: str, detail: str) -> list[ParameterSpec]:
    return [
        ParameterSpec(
            name=name,
            location="query",
            serialization="application/x-www-form-urlencoded",
            example=value or None,
            source=source,
            confidence=0.9,
            evidence_ref=evidence_ref(source, detail),
        )
        for name, value in parse_qsl(query, keep_blank_values=True)
        if name and len(name) <= 128
    ]


class _HTMLSurfaceParser(HTMLParser):
    def __init__(self, page_url: str) -> None:
        super().__init__(convert_charrefs=True)
        self.page_url = page_url
        self.forms: list[dict[str, object]] = []
        self.links: list[str] = []
        self.scripts: list[str] = []
        self._form: dict[str, object] | None = None
        self._select: dict[str, object] | None = None
        self._textarea: dict[str, object] | None = None

    @staticmethod
    def _attrs(attrs: list[tuple[str, str | None]]) -> dict[str, str]:
        return {key.lower(): value or "" for key, value in attrs}

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = self._attrs(attrs)
        tag = tag.lower()
        if tag == "form":
            if self._form is not None:
                self.forms.append(self._form)
            self._form = {
                "action": urljoin(self.page_url, values.get("action") or self.page_url),
                "method": (values.get("method") or "GET").upper(),
                "enctype": (values.get("enctype") or "application/x-www-form-urlencoded").lower(),
                "controls": [],
            }
            return
        if tag == "a" and values.get("href") and len(self.links) < _MAX_LINKS:
            self.links.append(urljoin(self.page_url, values["href"]))
            return
        if tag == "script" and values.get("src") and len(self.scripts) < _MAX_SCRIPTS:
            self.scripts.append(urljoin(self.page_url, values["src"]))
            return
        if tag == "option" and self._select is not None:
            selected = "selected" in values or not self._select.get("value")
            if selected:
                self._select["value"] = values.get("value", "")
            return
        if self._form is None:
            return
        if tag in {"input", "textarea", "select"}:
            controls = self._form["controls"]
            if not isinstance(controls, list) or len(controls) >= _MAX_FORM_CONTROLS:
                return
            control: dict[str, object] = {
                "name": values.get("name", ""),
                "type": values.get("type", "text").lower(),
                "value": values.get("value", ""),
                "required": "required" in values,
            }
            controls.append(control)
            if tag == "select":
                self._select = control
            elif tag == "textarea":
                self._textarea = control
        elif tag in {"button"} and values.get("name"):
            controls = self._form["controls"]
            if isinstance(controls, list) and len(controls) < _MAX_FORM_CONTROLS:
                controls.append(
                    {
                        "name": values["name"],
                        "type": values.get("type", "submit").lower(),
                        "value": values.get("value", ""),
                        "required": "required" in values,
                    }
                )

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.handle_starttag(tag, attrs)

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        if tag == "form" and self._form is not None:
            self.forms.append(self._form)
            self._form = None
        elif tag == "select":
            self._select = None
        elif tag == "textarea":
            self._textarea = None

    def handle_data(self, data: str) -> None:
        if self._textarea is not None:
            current = str(self._textarea.get("value", ""))
            self._textarea["value"] = current + data


def _form_endpoint(form: Mapping[str, object], source: str, index: int) -> EndpointSpec | None:
    action = str(form.get("action") or "")
    path_info = _path_and_query(action, source)
    if path_info is None:
        return None
    path, query = path_info
    method = str(form.get("method") or "GET").upper()
    enctype = str(form.get("enctype") or "application/x-www-form-urlencoded").lower()
    location = "multipart" if enctype == "multipart/form-data" else "form"
    if method in {"GET", "HEAD", "OPTIONS"}:
        location = "query"
    if enctype == "application/json":
        location = "json"
    params: list[ParameterSpec] = _query_parameters(query, source, f"form:{index}:query")
    controls = form.get("controls")
    if isinstance(controls, list):
        for control in controls:
            if not isinstance(control, Mapping):
                continue
            name = str(control.get("name") or "").strip()
            if not name:
                continue
            params.append(
                ParameterSpec(
                    name=name,
                    location=location,
                    serialization=enctype,
                    required=bool(control.get("required", False)),
                    example=(str(control["value"]) if control.get("value") else None),
                    source=source,
                    confidence=0.98,
                    evidence_ref=evidence_ref(source, f"form:{index}:{name}"),
                )
            )
    return EndpointSpec(
        method=method,
        path=path,
        content_type=enctype,
        state_changing=method not in _READ_ONLY,
        parameters=tuple(params),
        source=action,
        confidence=0.98,
        evidence_ref=evidence_ref(source, f"form:{index}:{method}:{path}"),
    )


def parse_html_surface(html: str, page_url: str) -> ParsedSurface:
    """Extract links, script sources, and form insertion points from HTML."""
    parser = _HTMLSurfaceParser(page_url)
    parser.feed(html[:_MAX_SCRIPT_CHARS])
    if parser._form is not None:
        parser.forms.append(parser._form)
    endpoints: list[EndpointSpec] = []
    for index, form in enumerate(parser.forms[:_MAX_FORMS]):
        endpoint = _form_endpoint(form, page_url, index)
        if endpoint is not None:
            endpoints.append(endpoint)
    # A link is a real GET route; query keys are separate insertion points.
    for index, link in enumerate(parser.links[:_MAX_LINKS]):
        path_info = _path_and_query(link, page_url)
        if path_info is None:
            continue
        path, query = path_info
        endpoints.append(
            EndpointSpec(
                method="GET",
                path=path,
                parameters=tuple(_query_parameters(query, page_url, f"link:{index}")),
                source=link,
                confidence=0.82,
                evidence_ref=evidence_ref(page_url, f"link:{link}"),
            )
        )
    return _dedupe_surface(
        ParsedSurface(tuple(endpoints), tuple(parser.links), tuple(parser.scripts))
    )


def _body_parameters(tail: str, source: str, detail: str, location: str) -> list[ParameterSpec]:
    match = re.search(
        r"JSON\.stringify\s*\(\s*\{(?P<body>[^{}]{0,800})\}\s*\)",
        tail,
        re.DOTALL,
    )
    if match is None:
        match = re.search(r"\bbody\s*:\s*\{(?P<body>[^{}]{0,800})\}", tail, re.DOTALL)
    if not match:
        return []
    return [
        ParameterSpec(
            name=key.group("name"),
            location=location,
            serialization="application/json"
            if location == "json"
            else "application/x-www-form-urlencoded",
            source=source,
            confidence=0.7,
            evidence_ref=evidence_ref(source, f"{detail}:{key.group('name')}"),
        )
        for key in _OBJECT_KEY_RE.finditer(match.group("body"))
    ][:_MAX_PARAMETERS]


def _js_endpoint(
    raw_url: str,
    source: str,
    method: str,
    tail: str = "",
    index: int = 0,
) -> EndpointSpec | None:
    path_info = _path_and_query(raw_url, source)
    if path_info is None:
        return None
    path, query = path_info
    method = method.upper()
    content_match = _CONTENT_TYPE_RE.search(tail)
    content_type = content_match.group("value").strip() if content_match else None
    is_graphql = "graphql" in path.lower() or bool(
        re.search(r"\b(?:query|mutation)\s+[A-Za-z_]", tail)
    )
    location = "graphql" if is_graphql else "json" if content_type == "application/json" else "form"
    params = _query_parameters(query, source, f"js:{index}:query")
    params.extend(_body_parameters(tail, source, f"js:{index}:body", location))
    body_params = [param for param in params if param.location == location]
    request_body = (
        json.dumps(
            {param.name: param.example or "reachagent-probe" for param in body_params},
            sort_keys=True,
        )
        if body_params and location in {"json", "form"}
        else None
    )
    graphql_operation_type = None
    if is_graphql:
        operation = re.search(r"\b(query|mutation|subscription)\b", tail, re.IGNORECASE)
        graphql_operation_type = operation.group(1).lower() if operation else "query"
        for match in _GRAPHQL_FIELD_RE.finditer(tail):
            name = match.group("name")
            if name in {"query", "mutation", "subscription", "variables"}:
                continue
            params.append(
                ParameterSpec(
                    name=name,
                    location="graphql",
                    serialization="application/json",
                    source=source,
                    confidence=0.65,
                    evidence_ref=evidence_ref(source, f"js:{index}:graphql:{name}"),
                )
            )
            after = tail[match.end() :]
            if after.startswith("("):
                argument_text = after[1:].split(")", 1)[0]
                for argument in _GRAPHQL_ARG_RE.findall(argument_text):
                    params.append(
                        ParameterSpec(
                            name=f"{name}.{argument}",
                            location="graphql",
                            serialization="application/json",
                            source=source,
                            confidence=0.65,
                            evidence_ref=evidence_ref(
                                source, f"js:{index}:graphql:{name}:{argument}"
                            ),
                        )
                    )
    return EndpointSpec(
        method=method,
        path=path,
        content_type=content_type,
        state_changing=method not in _READ_ONLY,
        protocol=Protocol.GRAPHQL if is_graphql else Protocol.REST,
        graphql_operation_type=graphql_operation_type,
        parameters=tuple(params[:_MAX_PARAMETERS]),
        source=source,
        confidence=0.72,
        evidence_ref=evidence_ref(source, f"js:{index}:{method}:{raw_url}"),
        request_headers=((("Content-Type", content_type),) if content_type is not None else ()),
        request_body=request_body,
    )


def parse_javascript_surface(script: str, source_url: str) -> ParsedSurface:
    """Recover bounded fetch/XHR/axios routes and their obvious fields."""
    text = script[:_MAX_SCRIPT_CHARS]
    endpoints: list[EndpointSpec] = []
    index = 0
    for match in _FETCH_RE.finditer(text):
        method_match = _METHOD_RE.search(match.group("tail"))
        endpoint = _js_endpoint(
            match.group("url"),
            source_url,
            method_match.group("method") if method_match else "GET",
            match.group("tail"),
            index,
        )
        if endpoint is not None:
            endpoints.append(endpoint)
            index += 1
    for match in _AXIOS_RE.finditer(text):
        endpoint = _js_endpoint(
            match.group("url"), source_url, match.group("method"), match.group("tail"), index
        )
        if endpoint is not None:
            endpoints.append(endpoint)
            index += 1
    for match in _XHR_RE.finditer(text):
        endpoint = _js_endpoint(match.group("url"), source_url, match.group("method"), "", index)
        if endpoint is not None:
            endpoints.append(endpoint)
            index += 1
    # Some bundles hide the call in a helper; retain only URL-looking literals
    # as low-confidence GET routes rather than treating every string as a route.
    if not endpoints:
        for match in _URL_RE.finditer(text):
            endpoint = _js_endpoint(match.group("url"), source_url, "GET", "", index)
            if endpoint is not None:
                endpoints.append(endpoint)
                index += 1
            if index >= _MAX_ENDPOINTS:
                break
    return _dedupe_surface(ParsedSurface(tuple(endpoints)))


def _dedupe_surface(surface: ParsedSurface) -> ParsedSurface:
    by_key: dict[tuple[str, str, Protocol], EndpointSpec] = {}
    for endpoint in surface.endpoints:
        key = (endpoint.method.upper(), endpoint.path, endpoint.protocol)
        existing = by_key.get(key)
        if existing is None:
            by_key[key] = endpoint
            continue
        params: dict[tuple[str, str], ParameterSpec] = {
            (p.name, p.location): p for p in existing.parameters
        }
        params.update({(p.name, p.location): p for p in endpoint.parameters})
        by_key[key] = EndpointSpec(
            method=existing.method,
            path=existing.path,
            content_type=existing.content_type or endpoint.content_type,
            state_changing=existing.state_changing or endpoint.state_changing,
            parameters=tuple(params.values()),
            protocol=existing.protocol,
            graphql_operation_type=existing.graphql_operation_type
            or endpoint.graphql_operation_type,
            source=existing.source or endpoint.source,
            confidence=max(existing.confidence or 0.0, endpoint.confidence or 0.0),
            evidence_ref=existing.evidence_ref or endpoint.evidence_ref,
            request_headers=existing.request_headers or endpoint.request_headers,
            request_body=existing.request_body or endpoint.request_body,
        )
    return ParsedSurface(
        endpoints=tuple(list(by_key.values())[:_MAX_ENDPOINTS]),
        links=tuple(dict.fromkeys(surface.links))[:_MAX_LINKS],
        scripts=tuple(dict.fromkeys(surface.scripts))[:_MAX_SCRIPTS],
    )


def json_example(value: object) -> str | None:
    """Serialize a JSON example without leaking an unserializable object."""
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    except (TypeError, ValueError):
        return None


__all__ = [
    "ParsedSurface",
    "evidence_ref",
    "json_example",
    "parse_html_surface",
    "parse_javascript_surface",
]
