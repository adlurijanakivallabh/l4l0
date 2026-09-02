"""Browser taint-tracking shim — DOM XSS source→sink discovery (§7, §9; Task 5).

Installs a JavaScript shim via ``addInitScript`` that hooks common DOM XSS sinks
(``innerHTML``, ``outerHTML``, ``insertAdjacentHTML``, ``document.write``,
``eval``, string-argument ``setTimeout``/``setInterval``, ``location``
assignments) and sources (``location.hash``, ``postMessage``) to discover
candidate source→sink flows systematically, without relying on reflection in
HTTP responses.

**EXECUTION_CONFIRMATION oracle is deferred to Task 6 (#24).** This module
discovers candidates and tags them ``EXECUTION_CONFIRMATION``; the oracle that
confirms actual execution stays ``UnknownOracleError`` until #24 builds it. The
candidate→oracle→finding gate is preserved: no finding is written here.

**No real browser in unit tests.** The ``BrowserDriver`` Protocol is the seam:
tests supply in-memory fakes; the live path supplies a Playwright-backed
implementation. The shim JS string is the same in both cases — it is injected
into the fake driver's ``init_scripts`` list so tests can assert it was installed.

**MCP boundary.** ``fire_browser`` is registered as an Explorer MCP tool (§13),
so the full taint-discovery path reaches the oracle through ``mcp.call_tool``,
not a direct Playwright Python call. The same role-boundary invariant applies:
``fire_browser`` is Explorer-only, unreachable from Coordinator/Validator.

**Execution marker (observable-execution layer).** A tainted value reaching a
sink (innerHTML etc.) records a *flow* — but a benign canary reaching innerHTML
injects inert text; nothing proves a script actually ran. The DOM probe therefore
uses the payload convention
``<img src=x onerror="window.__reachagent_exec=1">``: when innerHTML parses it, the
broken-image ``onerror`` fires and sets ``window.__reachagent_exec = 1`` —
observable **only if the browser actually executed injected JS**. The shim resets
``window.__reachagent_exec = 0`` at install (so a stale marker never leaks across
pages); the driver reads ``window.__reachagent_exec === 1`` after flow collection
and surfaces it as :attr:`BrowserFireResult.executed`. The marker is *read*, never
hooked — the sink hook list is unchanged.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from dataclasses import field as dataclass_field
from typing import Protocol, runtime_checkable

# ---------------------------------------------------------------------------
# Taint-tracking shim JavaScript
# ---------------------------------------------------------------------------

# Installed via addInitScript before page load. Hooks the common
# DOM XSS sinks and two sources; records each source→sink flow as a JSON
# object on window.__reachagent_flows so the Python driver can read it back.
TAINT_SHIM_JS = r"""
(function() {
  if (window.__reachagent_shim_installed) return;
  window.__reachagent_shim_installed = true;
  window.__reachagent_flows = [];
  window.__reachagent_taint_values = [];
  window.__reachagent_exec = 0;

  function addTaint(value) {
    if (value) window.__reachagent_taint_values.push(String(value));
  }

  function record(source, sink, value) {
    var v = String(value).slice(0, 200);
    var taints = window.__reachagent_taint_values || [];
    if (!taints.some(function(t) { return t && String(value).indexOf(t) !== -1; })) return;
    window.__reachagent_flows.push({source: source, sink: sink, value: v});
  }

  // --- Sink hooks ---
  var _origInnerHTML = Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML');
  Object.defineProperty(Element.prototype, 'innerHTML', {
    set: function(v) {
      var ts = window.__reachagent_taint_source;
      if (ts) record(ts, 'innerHTML', v);
      _origInnerHTML.set.call(this, v);
    },
    get: _origInnerHTML.get
  });

  var _origWrite = document.write.bind(document);
  document.write = function(v) {
    var ts = window.__reachagent_taint_source;
    if (ts) record(ts, 'document.write', v);
    return _origWrite(v);
  };

  var _origEval = window.eval;
  window.eval = function(v) {
    if (window.__reachagent_taint_source) record(window.__reachagent_taint_source, 'eval', v);
    return _origEval(v);
  };

  var _origOuterHTML = Object.getOwnPropertyDescriptor(Element.prototype, 'outerHTML');
  Object.defineProperty(Element.prototype, 'outerHTML', {
    set: function(v) {
      var ts = window.__reachagent_taint_source;
      if (ts) record(ts, 'outerHTML', v);
      _origOuterHTML.set.call(this, v);
    },
    get: _origOuterHTML.get
  });

  var _origInsertAdjacentHTML = Element.prototype.insertAdjacentHTML;
  Element.prototype.insertAdjacentHTML = function(position, v) {
    var ts = window.__reachagent_taint_source;
    if (ts) record(ts, 'insertAdjacentHTML', v);
    return _origInsertAdjacentHTML.call(this, position, v);
  };

  // setTimeout/setInterval with a string handler implicitly eval it — the
  // function-handler form (the vast majority of real call sites) is untouched.
  ['setTimeout', 'setInterval'].forEach(function(name) {
    var orig = window[name];
    window[name] = function(handler) {
      var ts = window.__reachagent_taint_source;
      if (ts && typeof handler === 'string') record(ts, name, handler);
      return orig.apply(window, arguments);
    };
  });

  var _locDesc = Object.getOwnPropertyDescriptor(window, 'location') ||
                 Object.getOwnPropertyDescriptor(Location.prototype, 'href');
  // location.href assignment — best-effort; browsers restrict full override
  try {
    var _origHref = Object.getOwnPropertyDescriptor(Location.prototype, 'href');
    Object.defineProperty(Location.prototype, 'href', {
      set: function(v) {
        var ts = window.__reachagent_taint_source;
        if (ts) record(ts, 'location.href', v);
        _origHref.set.call(this, v);
      },
      get: _origHref.get
    });
  } catch(e) {}

  // --- Source hooks ---
  // location.hash: mark taint when hash is non-empty on load and on hashchange
  function checkHash() {
    if (location.hash && location.hash.length > 1) {
      var raw = location.hash.slice(1);
      window.__reachagent_taint_source = 'location.hash';
      window.__reachagent_taint_values = [
        decodeURIComponent(raw),
        raw,
      ];
      var queryIndex = raw.indexOf('?');
      if (queryIndex !== -1) {
        try {
          new URLSearchParams(raw.slice(queryIndex + 1)).forEach(function(value) {
            addTaint(value);
          });
        } catch(e) {}
      }
    }
  }
  checkHash();
  window.addEventListener('hashchange', checkHash);

  // postMessage: mark taint when a message arrives
  window.addEventListener('message', function(e) {
    window.__reachagent_taint_source = 'postMessage';
  });
})();
"""

# ---------------------------------------------------------------------------
# General Explorer recon shim (v2 W11) — client-side surface for SPA targets
# ---------------------------------------------------------------------------

# Installed via addInitScript, separate from TAINT_SHIM_JS (a distinct tool,
# independent scope): hooks console output and JS-initiated network calls
# (fetch/XHR) so a single-page app's real API surface — invisible to the
# static HTML parser, which only sees the empty shell `<div id=root>` a JS
# framework renders into — becomes discoverable. Same "hook via init script,
# read via evaluate()" pattern the taint shim already established; no new
# BrowserDriver Protocol method needed.
RECON_SHIM_JS = r"""
(function() {
  if (window.__reachagent_recon_installed) return;
  window.__reachagent_recon_installed = true;
  window.__reachagent_console = [];
  window.__reachagent_network = [];
  var MAX = 200;

  ['log', 'warn', 'error', 'info'].forEach(function(level) {
    var orig = console[level];
    console[level] = function() {
      try {
        if (window.__reachagent_console.length < MAX) {
          var parts = Array.prototype.slice.call(arguments).map(String).join(' ');
          window.__reachagent_console.push((level + ': ' + parts).slice(0, 300));
        }
      } catch (e) {}
      return orig.apply(console, arguments);
    };
  });

  var _origFetch = window.fetch;
  if (_origFetch) {
    window.fetch = function(input, init) {
      try {
        var url = typeof input === 'string' ? input : (input && input.url) || '';
        var method = (init && init.method) || (input && input.method) || 'GET';
        if (window.__reachagent_network.length < MAX) {
          window.__reachagent_network.push(
            String(method).toUpperCase() + ' ' + String(url).slice(0, 300)
          );
        }
      } catch (e) {}
      return _origFetch.apply(window, arguments);
    };
  }

  var _origOpen = XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open = function(method, url) {
    try {
      if (window.__reachagent_network.length < MAX) {
        window.__reachagent_network.push(
          String(method).toUpperCase() + ' ' + String(url).slice(0, 300)
        );
      }
    } catch (e) {}
    return _origOpen.apply(this, arguments);
  };
})();
"""

# Evaluated on demand AFTER navigation (not an init script — this reads
# synchronous DOM/storage state at collection time, once the SPA has had a
# chance to render). Storage KEYS only, never values — the same "secrets
# never leave the browser process" discipline this codebase applies to
# cookies (BrowserFireResult.cookies is repr=False and never persisted to
# the graph); a JWT/session token sitting in localStorage must not leak into
# an event log or the graph any more than a cookie value would.
RECON_COLLECT_JS = r"""
(function() {
  function keys(storage) {
    try {
      var out = [];
      for (var i = 0; i < storage.length; i++) out.push(storage.key(i));
      return out;
    } catch (e) { return []; }
  }
  function forms() {
    try {
      return Array.prototype.slice.call(document.forms).map(function(f) {
        return {
          action: f.action || '',
          method: (f.method || 'get').toUpperCase(),
          inputs: Array.prototype.slice.call(f.elements)
            .map(function(el) { return el.name; })
            .filter(Boolean)
        };
      });
    } catch (e) { return []; }
  }
  function links() {
    try {
      var seen = {};
      var out = [];
      Array.prototype.slice.call(document.querySelectorAll('a[href]')).forEach(function(a) {
        var href = a.getAttribute('href');
        if (href && !seen[href]) { seen[href] = true; out.push(href); }
      });
      return out.slice(0, 200);
    } catch (e) { return []; }
  }
  return {
    local_storage_keys: keys(window.localStorage),
    session_storage_keys: keys(window.sessionStorage),
    forms: forms(),
    links: links(),
    console: window.__reachagent_console || [],
    network: window.__reachagent_network || []
  };
})()
"""


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TaintFlow:
    """One discovered source→sink flow from the shim's runtime recording."""

    source: str  # e.g. "location.hash", "postMessage"
    sink: str  # e.g. "innerHTML", "eval"
    value_snippet: str = ""  # first 200 chars of the tainted value (audit only)
    url: str = ""


@dataclass(frozen=True)
class DiscoveredForm:
    """One `<form>` the recon shim found rendered in the DOM (v2 W11).

    A pure fact, same shape as a Phase-2 static-HTML-mapped form — the caller
    folds this into ``graph.add_endpoint``/``add_parameter``, never a finding.
    """

    action: str
    method: str
    inputs: tuple[str, ...] = ()


@dataclass(frozen=True)
class BrowserReconResult:
    """Outcome of one ``run_browser_recon`` call (v2 W11) — general Explorer
    recon for SPA targets, distinct in scope from the XSS taint shim.

    ``local_storage_keys``/``session_storage_keys`` are KEY NAMES ONLY, never
    values — the same "secrets never leave the browser process" discipline
    already applied to cookies. ``console_messages``/``network_calls`` are
    bounded (200 entries each, 300 chars each) client-side by the shim itself.
    """

    url: str
    local_storage_keys: tuple[str, ...] = ()
    session_storage_keys: tuple[str, ...] = ()
    forms: tuple[DiscoveredForm, ...] = ()
    links: tuple[str, ...] = ()
    console_messages: tuple[str, ...] = dataclass_field(default=(), repr=False)
    network_calls: tuple[str, ...] = dataclass_field(default=(), repr=False)
    status_code: int | None = None
    final_url: str = ""


@dataclass(frozen=True)
class BrowserFireResult:
    """Outcome of one ``fire_browser`` call.

    ``flows`` is the list of source→sink flows the shim recorded. An empty list
    means no injectable sinks were reached — the clean-target case. Each flow is
    a candidate for the EXECUTION_CONFIRMATION oracle (deferred to #24); this
    result is the Explorer's terminal output, never a finding.

    ``executed`` is True when the injected payload's ``onerror`` marker
    (``window.__reachagent_exec = 1``) actually fired — observable proof the
    browser *executed* injected JS, distinct from a mere sink-reached flow.
    """

    url: str
    identity: str
    flows: tuple[TaintFlow, ...] = dataclass_field(default=(), repr=False)
    shim_installed: bool = False
    executed: bool = False
    # Navigation evidence is kept server-side and projected by the MCP layer.
    # Cookie values never leave the identity store; only names are safe to expose.
    status_code: int | None = None
    final_url: str = ""
    redirects: tuple[str, ...] = ()
    cookies: tuple[tuple[str, str], ...] = dataclass_field(default=(), repr=False)
    body_length: int = 0
    # Raw page content remains server-side behind ``browser_ref``.  ``repr``
    # hides it so accidental logs cannot expose response data.
    body: bytes = dataclass_field(default=b"", repr=False)
    headers: tuple[tuple[str, str], ...] = dataclass_field(default=(), repr=False)
    title: str = ""


@dataclass(frozen=True)
class BrowserNavigation:
    """Bounded navigation evidence returned by a browser driver.

    The browser owns the response and cookie jar.  This projection is the only
    value consumed by :func:`run_taint_shim`; cookie values stay in memory until
    the MCP boundary binds them to the selected identity's ``TokenStore``.
    """

    status_code: int | None = None
    final_url: str = ""
    redirects: tuple[str, ...] = ()
    cookies: tuple[tuple[str, str], ...] = ()
    headers: tuple[tuple[str, str], ...] = ()


# ---------------------------------------------------------------------------
# BrowserDriver Protocol — the seam between tests and Playwright
# ---------------------------------------------------------------------------


@runtime_checkable
class BrowserDriver(Protocol):
    """Minimal browser automation surface the shim needs (§13).

    The live implementation wraps a Playwright ``Page``; tests supply an
    in-memory fake. The contract is narrow by design: only what the shim
    installation and flow-collection path actually needs.
    """

    def add_init_script(self, script: str) -> None:
        """Install ``script`` via addInitScript before the next page load."""
        ...

    def navigate(self, url: str) -> object:
        """Navigate to ``url`` and wait for load."""
        ...

    def evaluate(self, expression: str) -> object:
        """Evaluate ``expression`` in the page context and return the result."""
        ...


@runtime_checkable
class AsyncBrowserDriver(Protocol):
    """Async browser surface used by the MCP Playwright path."""

    async def add_init_script(self, script: str) -> None: ...

    async def navigate(self, url: str) -> object: ...

    async def evaluate(self, expression: str) -> object: ...


def _read_attr(value: object, name: str, default: object = None) -> object:
    """Read a sync Playwright-style attribute without trusting arbitrary objects."""
    try:
        item = getattr(value, name, default)
        return item() if callable(item) else item
    except Exception:  # noqa: BLE001 - browser metadata is best effort
        return default


def _redirect_urls(response: object) -> tuple[str, ...]:
    """Collect redirected-from URLs in oldest-to-newest order."""
    chain: list[str] = []
    request = _read_attr(response, "request")
    seen: set[int] = set()
    while request is not None and id(request) not in seen:
        seen.add(id(request))
        previous = _read_attr(request, "redirected_from")
        if previous is None:
            break
        previous_url = _read_attr(previous, "url", "")
        if previous_url:
            chain.append(str(previous_url))
        request = previous
    return tuple(reversed(chain))


def _navigation(raw: object, requested_url: str, cookies: object = ()) -> BrowserNavigation:
    """Normalize Playwright response/fake values to a stable, bounded record."""
    status_raw = _read_attr(raw, "status") if raw is not None else None
    status: int | None
    try:
        status = int(str(status_raw)) if status_raw is not None else None
    except (TypeError, ValueError):
        status = None
    final = _read_attr(raw, "url", "") if raw is not None else ""
    final_url = str(final or requested_url)
    cookie_pairs: list[tuple[str, str]] = []
    if isinstance(cookies, list | tuple):
        for item in cookies:
            if isinstance(item, dict) and item.get("name"):
                cookie_pairs.append((str(item["name"]), str(item.get("value", ""))))
            elif isinstance(item, tuple) and len(item) == 2:
                cookie_pairs.append((str(item[0]), str(item[1])))
    header_pairs: list[tuple[str, str]] = []
    raw_headers = _read_attr(raw, "headers", {}) if raw is not None else {}
    if isinstance(raw_headers, dict):
        header_pairs = [(str(key).lower(), str(value)) for key, value in raw_headers.items()]
    return BrowserNavigation(
        status_code=status,
        final_url=final_url,
        redirects=_redirect_urls(raw) if raw is not None else (),
        cookies=tuple(cookie_pairs),
        headers=tuple(header_pairs),
    )


_BROWSER_BODY_MAX_BYTES = 2_000_000


async def run_taint_shim_async(
    driver: AsyncBrowserDriver,
    identity: str,
    url: str,
    *,
    inject_shim: bool = True,
) -> BrowserFireResult:
    """Async equivalent used by MCP's Playwright async API path."""
    if inject_shim:
        await driver.add_init_script(TAINT_SHIM_JS)
    navigation_raw = await driver.navigate(url)
    await asyncio.sleep(0.5)
    cookies: object = ()
    get_cookies = getattr(driver, "get_cookies", None)
    if callable(get_cookies):
        try:
            cookies = await get_cookies()
        except Exception:  # noqa: BLE001 - cookie capture is best effort
            cookies = ()
    navigation = _navigation(navigation_raw, url, cookies)
    all_headers = getattr(navigation_raw, "all_headers", None)
    if callable(all_headers):
        try:
            raw_headers = await all_headers()
            if isinstance(raw_headers, dict):
                navigation = BrowserNavigation(
                    status_code=navigation.status_code,
                    final_url=navigation.final_url,
                    redirects=navigation.redirects,
                    cookies=navigation.cookies,
                    headers=tuple(
                        (str(key).lower(), str(value)) for key, value in raw_headers.items()
                    ),
                )
        except Exception:  # noqa: BLE001,S110 - optional response projection
            pass
    raw_flows: list[object] = []
    if inject_shim:
        result = await driver.evaluate("window.__reachagent_flows || []")
        if isinstance(result, list):
            raw_flows = result
    flows = tuple(
        TaintFlow(
            source=str(f.get("source", "")) if isinstance(f, dict) else "",
            sink=str(f.get("sink", "")) if isinstance(f, dict) else "",
            value_snippet=str(f.get("value", "")) if isinstance(f, dict) else "",
            url=url,
        )
        for f in raw_flows
        if isinstance(f, dict)
    )
    executed = False
    if inject_shim:
        exec_result = await driver.evaluate("window.__reachagent_exec === 1")
        executed = bool(exec_result)
    body = b""
    body_length = 0
    try:
        raw_body = await driver.evaluate("document.documentElement?.outerHTML || ''")
        if isinstance(raw_body, str):
            encoded = raw_body.encode("utf-8", errors="replace")
            body_length = len(encoded)
            body = encoded[:_BROWSER_BODY_MAX_BYTES]
        else:
            body_length = int(str(raw_body))
    except Exception:  # noqa: BLE001 - optional projection
        body_length = 0
    return BrowserFireResult(
        url=url,
        identity=identity,
        flows=flows,
        shim_installed=inject_shim,
        executed=executed,
        status_code=navigation.status_code,
        final_url=navigation.final_url,
        redirects=navigation.redirects,
        cookies=navigation.cookies,
        body_length=body_length,
        body=body,
        headers=navigation.headers,
    )


def run_taint_shim(
    driver: BrowserDriver,
    identity: str,
    url: str,
    *,
    inject_shim: bool = True,
) -> BrowserFireResult:
    """Install shim, navigate, and collect source-to-sink flows synchronously."""
    if inject_shim:
        driver.add_init_script(TAINT_SHIM_JS)
    navigation_raw = driver.navigate(url)
    cookies: object = ()
    get_cookies = getattr(driver, "get_cookies", None)
    if callable(get_cookies):
        try:
            cookies = get_cookies()
        except Exception:  # noqa: BLE001 - cookie capture is best effort
            cookies = ()
    navigation = _navigation(navigation_raw, url, cookies)
    raw_flows: list[object] = []
    if inject_shim:
        result = driver.evaluate("window.__reachagent_flows || []")
        if isinstance(result, list):
            raw_flows = result
    flows = tuple(
        TaintFlow(
            source=str(f.get("source", "")) if isinstance(f, dict) else "",
            sink=str(f.get("sink", "")) if isinstance(f, dict) else "",
            value_snippet=str(f.get("value", "")) if isinstance(f, dict) else "",
            url=url,
        )
        for f in raw_flows
        if isinstance(f, dict)
    )
    executed = False
    if inject_shim:
        exec_result = driver.evaluate("window.__reachagent_exec === 1")
        executed = bool(exec_result)
    body = b""
    body_length = 0
    try:
        raw_body = driver.evaluate("document.documentElement?.outerHTML || ''")
        if isinstance(raw_body, str):
            encoded = raw_body.encode("utf-8", errors="replace")
            body_length = len(encoded)
            body = encoded[:_BROWSER_BODY_MAX_BYTES]
        else:
            body_length = int(str(raw_body))
    except Exception:  # noqa: BLE001 - optional projection
        body_length = 0
    return BrowserFireResult(
        url=url,
        identity=identity,
        flows=flows,
        shim_installed=inject_shim,
        executed=executed,
        status_code=navigation.status_code,
        final_url=navigation.final_url,
        redirects=navigation.redirects,
        cookies=navigation.cookies,
        body_length=body_length,
        body=body,
        headers=navigation.headers,
    )


async def run_browser_recon_async(
    driver: AsyncBrowserDriver,
    url: str,
    *,
    settle_seconds: float = 0.5,
) -> BrowserReconResult:
    """Install the recon shim, navigate, let the SPA settle, and collect general
    Explorer-recon facts (v2 W11) — localStorage/sessionStorage KEY NAMES,
    rendered forms/links, console output, and JS-initiated network calls.

    Independent scope from the XSS taint shim (``run_taint_shim_async``): this
    is a different tool for a different purpose (SPA route/form discovery, not
    execution confirmation), so it installs its own separate init script rather
    than reusing/extending ``TAINT_SHIM_JS``.
    """
    await driver.add_init_script(RECON_SHIM_JS)
    navigation_raw = await driver.navigate(url)
    await asyncio.sleep(settle_seconds)
    navigation = _navigation(navigation_raw, url)
    collected = await driver.evaluate(RECON_COLLECT_JS)
    if not isinstance(collected, dict):
        collected = {}

    def _str_list(value: object, limit: int) -> tuple[str, ...]:
        if not isinstance(value, list):
            return ()
        return tuple(str(item) for item in value[:limit] if item is not None)

    forms: list[DiscoveredForm] = []
    for raw_form in collected.get("forms", []) if isinstance(collected.get("forms"), list) else []:
        if not isinstance(raw_form, dict):
            continue
        inputs = raw_form.get("inputs", [])
        forms.append(
            DiscoveredForm(
                action=str(raw_form.get("action", "")),
                method=str(raw_form.get("method", "GET")).upper(),
                inputs=tuple(str(i) for i in inputs) if isinstance(inputs, list) else (),
            )
        )

    return BrowserReconResult(
        url=url,
        local_storage_keys=_str_list(collected.get("local_storage_keys"), 100),
        session_storage_keys=_str_list(collected.get("session_storage_keys"), 100),
        forms=tuple(forms[:50]),
        links=_str_list(collected.get("links"), 200),
        console_messages=_str_list(collected.get("console"), 200),
        network_calls=_str_list(collected.get("network"), 200),
        status_code=navigation.status_code,
        final_url=navigation.final_url,
    )
