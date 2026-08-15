"""Browser taint-tracking shim — DOM XSS source→sink discovery (§7, §9; Task 5).

Installs a JavaScript shim via ``addInitScript`` that hooks common DOM XSS sinks
(``innerHTML``, ``document.write``, ``eval``, ``location`` assignments) and
sources (``location.hash``, ``postMessage``) to discover candidate source→sink
flows systematically, without relying on reflection in HTTP responses.

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
from typing import Protocol, runtime_checkable

# ---------------------------------------------------------------------------
# Taint-tracking shim JavaScript
# ---------------------------------------------------------------------------

# Installed via addInitScript before page load. Hooks the six most common
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
    flows: tuple[TaintFlow, ...] = ()
    shim_installed: bool = False
    executed: bool = False


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

    def navigate(self, url: str) -> None:
        """Navigate to ``url`` and wait for load."""
        ...

    def evaluate(self, expression: str) -> object:
        """Evaluate ``expression`` in the page context and return the result."""
        ...


@runtime_checkable
class AsyncBrowserDriver(Protocol):
    """Async browser surface used by the MCP Playwright path."""

    async def add_init_script(self, script: str) -> None: ...

    async def navigate(self, url: str) -> None: ...

    async def evaluate(self, expression: str) -> object: ...


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
    await driver.navigate(url)
    await asyncio.sleep(0.5)
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
    return BrowserFireResult(
        url=url,
        identity=identity,
        flows=flows,
        shim_installed=inject_shim,
        executed=executed,
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
    driver.navigate(url)
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
    return BrowserFireResult(
        url=url,
        identity=identity,
        flows=flows,
        shim_installed=inject_shim,
        executed=executed,
    )
