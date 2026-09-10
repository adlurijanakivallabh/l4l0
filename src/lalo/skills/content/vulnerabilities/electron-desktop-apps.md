---
name: electron-desktop-apps
category: vulnerability
description: Electron-specific attack surface — nodeIntegration/contextIsolation misconfiguration, IPC handler trust boundaries, and a per-class proof ladder
keywords: [electron, desktop app, nodeintegration, contextisolation, ipc, preload script]
---

# Electron Desktop Applications

An Electron app's renderer process is a Chromium web page; if it can
reach Node.js APIs directly, any client-side vulnerability that would
normally be confined to the browser sandbox ([[xss]] chief among them)
escalates directly to native code execution on the user's machine.

## Attack Surface

- `nodeIntegration: true` and/or `contextIsolation: false` on any
  `BrowserWindow` that renders content influenced by remote/untrusted
  data (a loaded URL, a rendered Markdown/HTML preview, chat content).
- The preload script's exposed API surface (`contextBridge.exposeInMainWorld`)
  — an overly broad exposed function (e.g. one wrapping raw
  `fs`/`child_process` access with no argument validation) hands the
  renderer a native-code-execution primitive even with
  `contextIsolation: true` correctly enabled.
- IPC handlers (`ipcMain.handle`/`ipcMain.on`) that trust the renderer's
  arguments without validating them the same way a server would validate
  a network request — the renderer is not a trusted process boundary
  just because it's the same application.
- `webSecurity: false`, or a `will-navigate`/`new-window` handler that
  doesn't restrict navigation to expected origins, allowing a loaded
  remote page to navigate to and execute in a more privileged context.

## Recon

- Read the actual `BrowserWindow` construction options for
  `nodeIntegration`/`contextIsolation`/`webSecurity`/`sandbox` — this is
  the single highest-value check, since it determines whether ANY
  renderer-side bug (XSS especially) escalates to RCE at all.
- Read the preload script in full and catalog every function exposed via
  `contextBridge` — for each, identify what native capability it
  ultimately reaches and whether its arguments are validated before use.
- Read every `ipcMain.handle`/`ipcMain.on` registration and check what
  it does with the arguments it receives from the renderer.

## Techniques

1. **XSS-to-RCE escalation check.** If `nodeIntegration: true` or
   `contextIsolation: false` on a window rendering untrusted content, any
   confirmed [[xss]] there escalates directly — demonstrate by having the
   injected script call a Node.js global (`require('child_process')`)
   and execute a benign command, proving native code execution rather
   than just script execution in a sandbox.
2. **Preload-bridge argument-injection probe.** For each exposed
   `contextBridge` function wrapping a native capability, call it from
   the renderer's DevTools/console (or via a confirmed XSS) with
   adversarial arguments (a path-traversal-shaped file path, a command-
   injection-shaped string) and confirm whether the underlying native
   call validates them.
3. **IPC-handler trust-boundary probe.** Send unexpected/adversarial
   arguments to an `ipcMain` handler the same way you would fuzz an API
   endpoint, applying whatever class the handler's actual native
   operation belongs to (path traversal, command injection, SSRF).

## Proof Ladder

- **L1** — a risky configuration identified (`nodeIntegration`/
  `contextIsolation` misconfigured, or a preload function wrapping a
  native capability with no visible validation) but not yet exploited.
- **L2** — the risky configuration confirmed reachable from
  attacker-influenced content (an XSS lands in the affected window; the
  preload function is callable with adversarial arguments) with no
  native-code effect demonstrated yet.
- **L3** — a benign native-code effect demonstrated (a proof file
  written/read, a benign command executed) via the escalation path —
  reportable.
- **L4** — full, reliable native code execution reproducible from a
  remote/untrusted content source with no additional local access
  required.

## Validation and False-Positive Discipline

Apply [[closure-discipline]]. `contextIsolation: true` combined with a
preload script exposing only narrowly-scoped, argument-validated
functions (confirmed by reading the actual preload code, not assumed
from the setting alone) closes the direct-Node-access escalation path
even if the renderer itself is later found vulnerable to XSS.

## Impact

Native code execution on the end user's machine from a renderer-side
vulnerability that would otherwise be sandbox-confined in an ordinary
browser context — full desktop compromise, not merely a web-application-
scoped impact.

## Summary

Always start with the `BrowserWindow` construction options —
`nodeIntegration`/`contextIsolation`/`webSecurity`/`sandbox` determine
whether every other finding in this application escalates to native code
execution or stays browser-sandbox-confined. Then read the preload
script and IPC handlers as their own, separate trust boundary.
