"use strict";
/* ReachAgent chat-first GUI. One conversation == one scan. The chat panel is a
 * thin, deterministic rendering of a scan's own lifecycle (never a separate
 * chat-message store); the right panel streams the same live scan data the
 * backend already exposes (events/findings/surface/audit/report). */

const $ = (id) => document.getElementById(id);
const esc = (s) => String(s == null ? "" : s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");

const TERMINAL_STATES = new Set(["completed", "failed", "blocked", "cancelled"]);
const LIFECYCLE_LABEL = { queued: "Queued", running: "Running", paused: "Paused", cancelling: "Cancelling", blocked: "Blocked", completed: "Completed", failed: "Failed", cancelled: "Cancelled" };
const PHASE_STEP = { plan: "PLAN", recon: "RECON", surface: "SURFACE", endpoints: "ENDPOINTS", "insertion-points": "INSERTION", payloads: "PAYLOADS", verification: "VERIFY", chains: "CHAINS", tools: "TOOLS", report: "REPORT" };
const OUT_CLASS = { fired: "out-fired", refused: "out-refused", error: "out-error", ingested: "out-ingested" };
const _WRITE_METHODS = new Set(["POST", "PUT", "PATCH", "DELETE"]);

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------
const state = {
  scanId: null,
  pendingProposal: null,
  eventsAfter: 0,
  fastTimer: null,
  slowTimer: null,
  fastInFlight: false,
  slowInFlight: false,
  sidebarTimer: null,
  activeTab: "terminal",
  workPaneHidden: false,
  splitRatio: 0.46,
  reportReady: false,
};

function resetPollState() {
  clearTimeout(state.fastTimer);
  clearTimeout(state.slowTimer);
  state.fastTimer = null;
  state.slowTimer = null;
  state.eventsAfter = 0;
}

// ---------------------------------------------------------------------------
// View switching
// ---------------------------------------------------------------------------
function showLanding() {
  state.scanId = null;
  state.pendingProposal = null;
  resetPollState();
  $("landing").hidden = false;
  $("convo-view").hidden = true;
  $("landing-input").value = "";
  $("landing-input").focus();
  renderConvoList();
}

const TERM_IDLE_HTML = $("term-feed").innerHTML;

function resetWorkPane() {
  $("term-feed").innerHTML = TERM_IDLE_HTML;
  $("term-count").textContent = "";
  setTerminalLive(false);
  renderMetrics(null);
  renderFindingsList(null);
  renderSurfaceTree({ available: false, hosts: [], orphan_endpoints: [] });
  renderAuditList(null);
  renderReport("");
  $("report-toolbar").hidden = true;
  state.reportReady = false;
}

function showConversation(scanId) {
  state.scanId = scanId;
  state.pendingProposal = null;
  $("landing").hidden = true;
  $("convo-view").hidden = false;
  $("chat-log").innerHTML = "";
  $("chat-header-title").textContent = "New assessment";
  $("chat-header-lifecycle").hidden = true;
  resetWorkPane();
}

// ---------------------------------------------------------------------------
// Chat bubbles
// ---------------------------------------------------------------------------
function addBubble(role, contentEl, opts) {
  opts = opts || {};
  const wrap = document.createElement("div");
  wrap.className = "msg " + role;
  if (opts.id) wrap.id = opts.id;
  const avatar = document.createElement("span");
  avatar.className = "msg-avatar";
  avatar.textContent = role === "user" ? "U" : "›";
  const bubble = document.createElement("div");
  bubble.className = "msg-bubble";
  bubble.appendChild(contentEl);
  wrap.append(avatar, bubble);
  $("chat-log").appendChild(wrap);
  $("chat-log").scrollTop = $("chat-log").scrollHeight;
  return wrap;
}

function textBubble(role, text) {
  const p = document.createElement("p");
  p.textContent = text;
  return addBubble(role, p);
}

// ---------------------------------------------------------------------------
// New assessment flow: message -> /api/parse-intent -> confirmation card -> /api/scan
// ---------------------------------------------------------------------------
// v2 Phase 6 Stage E2: a specific reason per failure mode instead of one generic
// "I'll need a bit more to go on" for every case — a well-phrased prompt used to
// look identical to a config problem that had nothing to do with its wording.
const INTENT_FAILURE_MESSAGES = {
  no_provider:
    "No LLM provider is configured yet — add one in Settings (gear icon), then try again.",
  provider_error:
    "I couldn't reach the configured LLM provider — check its API key/URL in Settings, then try again.",
  malformed_reply: "The model's reply didn't parse cleanly — try rephrasing, or send it again.",
};

function introMessageFor(proposal) {
  if (proposal.extracted && proposal.target) {
    return (
      "Got it — here's what I'll run against " +
      proposal.target +
      ". Adjust anything below, then confirm to start."
    );
  }
  const reasonNote = INTENT_FAILURE_MESSAGES[proposal.reason];
  return reasonNote
    ? reasonNote + " You can still fill in the target, scope, and credentials manually below."
    : "I'll need a bit more to go on. Fill in the target, scope, and any credentials below to continue.";
}

async function startNewAssessment(message) {
  await handleProposalTurn(message, null);
}

// v3 conversational-confirmation flow (pentagi-style): every turn before a scan
// starts is a normal chat exchange — no big form. The assistant's reply is a
// short text summary of what it understood plus one "Start assessment" button;
// the operator refines by typing more ("also skip ffuf", "the password is
// actually X") rather than editing fields, which /api/parse-intent's `previous`
// refine mode folds onto the existing proposal instead of re-extracting blind.
async function handleProposalTurn(message, previous) {
  message = message.trim();
  if (!message) return;
  if (!previous) showConversation(null); // first turn: clears the log; scanId stays null until confirmed
  textBubble("user", message);

  const thinkingP = document.createElement("div");
  thinkingP.className = "thinking";
  thinkingP.innerHTML = "<span></span><span></span><span></span>";
  const thinkingBubble = addBubble("assistant", thinkingP, { id: "thinking-bubble" });

  let proposal = previous || { target: "", in_scope: "", out_of_scope: "", credentials: [], goal: message, skip_tools: "", extracted: false };
  try {
    const r = await fetch("/api/parse-intent", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(previous ? { message, previous } : { message }),
    });
    if (r.ok) proposal = await r.json();
  } catch (_e) {
    /* degrade to the previous/empty proposal below — the summary bubble still works */
  }
  thinkingBubble.remove();
  textBubble("assistant", introMessageFor(proposal));
  renderProposalSummary(proposal, message);
}

function maskedCredLine(c) {
  const dots = "•".repeat(Math.max(4, (c.password || "").length));
  return c.username + " / " + dots + (c.role && c.role !== "user" ? " (" + c.role + ")" : "");
}

// Any earlier proposal bubble's Start button is disabled once a newer one
// exists — only the latest understanding of the request should be launchable.
function supersedePriorProposals() {
  document.querySelectorAll("#chat-log .proposal-summary:not(.superseded)").forEach((el) => {
    el.classList.add("superseded");
    const btn = el.querySelector(".pp-start");
    if (btn) btn.disabled = true;
  });
}

function renderProposalSummary(proposal, message) {
  supersedePriorProposals();
  state.pendingProposal = proposal;

  const wrap = document.createElement("div");
  wrap.className = "proposal-summary";

  const rows = [
    ["Target", proposal.target],
    ["In-scope", proposal.in_scope],
    ["Out-of-scope", proposal.out_of_scope],
    ["Credentials", (proposal.credentials || []).map(maskedCredLine).join(", ")],
    ["Skipping", proposal.skip_tools],
    ["Objective", proposal.goal || message],
  ].filter(([, v]) => v);
  const fields = document.createElement("div");
  fields.className = "proposal-fields";
  fields.innerHTML = rows
    .map(([k, v]) => '<div class="proposal-row"><span class="proposal-key">' + esc(k) + '</span><span class="proposal-val">' + esc(v) + "</span></div>")
    .join("");
  wrap.appendChild(fields);

  if (!proposal.extracted) {
    const note = document.createElement("div");
    note.className = "confirm-note";
    note.textContent = "I couldn't fully work that out — tell me the target, credentials, or scope and I'll update this.";
    wrap.appendChild(note);
  }

  const actions = document.createElement("div");
  actions.className = "proposal-actions";
  actions.innerHTML =
    '<select class="pp-provider proposal-provider"><option value="">Server default</option></select>' +
    '<button class="pp-start primary-btn" type="button"' + (proposal.target ? "" : " disabled") + '><span>Start assessment</span><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="m5 12 14 0M13 6l6 6-6 6"/></svg></button>';
  wrap.appendChild(actions);
  populateProviderSelect(actions.querySelector(".pp-provider"));

  const hint = document.createElement("div");
  hint.className = "proposal-hint";
  hint.textContent = "Tell me what to change, or start when this looks right.";
  wrap.appendChild(hint);

  const bubble = addBubble("assistant", wrap, { id: "proposal-bubble" });
  actions.querySelector(".pp-start").onclick = () => confirmProposal(wrap, bubble, message);
}

function tuningChip(id, label) {
  return (
    '<label class="tuning-chip"><input id="' + id + '" type="checkbox">' +
    '<span class="box"><svg viewBox="0 0 24 24" fill="none"><path d="M5 13l4 4L19 7"/></svg></span>' + esc(label) + "</label>"
  );
}

async function confirmProposal(wrap, bubble, message) {
  const proposal = state.pendingProposal || {};
  const target = (proposal.target || "").trim();
  if (!target) return;
  const startBtn = wrap.querySelector(".pp-start");
  startBtn.disabled = true;
  startBtn.querySelector("span").textContent = "Starting…";

  const credentials = (proposal.credentials || []).filter((c) => c.username && c.password);
  const inScope = (proposal.in_scope || "").trim() || target;
  const body = Object.assign({}, loadScanDefaults(), {
    target,
    in_scope: inScope,
    out_of_scope: (proposal.out_of_scope || "").trim() || null,
    prompt: (proposal.goal || message || "").trim() || message,
    use_llm: true,
    llm_provider: wrap.querySelector(".pp-provider").value || null,
    identities: credentials.length ? credentials : undefined,
    skip_tools: (proposal.skip_tools || "").trim() || null,
  });

  try {
    const r = await fetch("/api/scan", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
    const j = await r.json();
    if (!r.ok || j.error) throw new Error(j.error || "Could not queue assessment");
    freezeProposalSummary(bubble, target, inScope, credentials.length);
    state.scanId = j.scan_id;
    state.pendingProposal = null;
    beginLiveTracking();
    renderConvoList();
    scheduleSidebarRefresh();
  } catch (err) {
    startBtn.disabled = false;
    startBtn.querySelector("span").textContent = "Start assessment";
    const errNote = document.createElement("div");
    errNote.className = "confirm-note";
    errNote.textContent = String(err.message || err);
    wrap.appendChild(errNote);
  }
}

function freezeProposalSummary(bubble, target, scope, credCount) {
  const frozen = document.createElement("div");
  frozen.className = "cc-frozen";
  frozen.innerHTML =
    "<span>Target: <b>" + esc(target) + "</b></span>" +
    "<span>Scope: <b>" + esc(scope) + "</b></span>" +
    "<span>Credentials: <b>" + credCount + "</b></span>" +
    "<span>Starting assessment…</span>";
  bubble.querySelector(".msg-bubble").replaceChildren(frozen);
}

// v3 V6: the 9 tuning checkboxes + recon-depth/wordlist/max-attempts/repo-path
// live once in Settings ("Scan defaults") instead of being re-asked per scan —
// set once, applied to every /api/scan call from here on.
const SCAN_DEFAULTS_KEY = "reachagent.scanDefaults";
const DEFAULT_SCAN_DEFAULTS = {
  max_attempts: 20,
  recon_depth: "quick",
  wordlist_size: "medium",
  repo_path: null,
  surface_tuning: false,
  signal_tuning: false,
  transport_tuning: false,
  guardian_advisor: false,
  concurrent_specialists: false,
  aggressive: false,
  recon_depth_tuning: false,
  wordlist_depth_tuning: false,
  rate_limit_corroboration: false,
};

function loadScanDefaults() {
  try {
    const raw = localStorage.getItem(SCAN_DEFAULTS_KEY);
    if (!raw) return Object.assign({}, DEFAULT_SCAN_DEFAULTS);
    return Object.assign({}, DEFAULT_SCAN_DEFAULTS, JSON.parse(raw));
  } catch (_e) {
    return Object.assign({}, DEFAULT_SCAN_DEFAULTS);
  }
}

function saveScanDefaults(defaults) {
  try {
    localStorage.setItem(SCAN_DEFAULTS_KEY, JSON.stringify(defaults));
  } catch (_e) {
    /* localStorage unavailable (private mode, quota) — defaults just won't persist */
  }
}

// ---------------------------------------------------------------------------
// Chat input wiring (both landing and in-conversation composer)
// ---------------------------------------------------------------------------
function autoGrow(textarea) {
  textarea.style.height = "auto";
  textarea.style.height = Math.min(textarea.scrollHeight, 160) + "px";
}

function wireComposer(textareaId, sendBtnId, onSend) {
  const textarea = $(textareaId);
  const send = () => {
    const value = textarea.value;
    textarea.value = "";
    autoGrow(textarea);
    onSend(value);
  };
  $(sendBtnId).onclick = send;
  textarea.addEventListener("input", () => autoGrow(textarea));
  textarea.addEventListener("keydown", (e) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      send();
    }
  });
}

wireComposer("landing-input", "landing-send", startNewAssessment);
wireComposer("chat-input", "chat-send", async (message) => {
  message = message.trim();
  if (!message) return;
  if (!state.scanId) {
    // Pre-scan: this composer is the SAME box used for reviewing/refining the
    // proposal before it's launched (state.pendingProposal set) — route there
    // instead of silently swallowing the message.
    await handleProposalTurn(message, state.pendingProposal);
    return;
  }
  textBubble("user", message);
  // Real conversational Q&A (W1): POST /ask returns an actual LLM answer generated from live
  // scan state, and also steers the scan when it's still active. Works after completion too
  // (ask it to explain a finding). A transient "…" bubble stands in while the model replies.
  textBubble("assistant", "…");
  const pending = $("chat-log").lastElementChild;
  const setReply = (txt) => {
    const bubble = pending && pending.querySelector(".msg-bubble");
    if (bubble) bubble.textContent = txt;
    else textBubble("assistant", txt);
    $("chat-log").scrollTop = $("chat-log").scrollHeight;
  };
  try {
    const r = await fetch("/api/scan/" + state.scanId + "/ask", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ message }),
    });
    if (r.ok) {
      const j = await r.json();
      setReply(j.answer || "(no reply)");
    } else {
      setReply("Couldn't reach the agent right now; the scan state is in the tabs on the right.");
    }
  } catch (_e) {
    setReply("Couldn't reach the server to ask that.");
  }
});

document.querySelectorAll(".landing-chip").forEach((chip) => {
  chip.addEventListener("click", () => {
    $("landing-input").value = chip.dataset.fill;
    $("landing-input").focus();
  });
});

function openMobileSidebar() {
  $("sidebar").classList.add("open");
  $("sidebar-backdrop").classList.add("open");
}
function closeMobileSidebar() {
  $("sidebar").classList.remove("open");
  $("sidebar-backdrop").classList.remove("open");
}
$("mobile-menu-btn").onclick = openMobileSidebar;
$("sidebar-backdrop").addEventListener("click", closeMobileSidebar);

$("new-chat").onclick = () => {
  closeMobileSidebar();
  showLanding();
};

// ---------------------------------------------------------------------------
// Live tracking: fast /events poll (terminal) + slower full-scan poll (findings/etc.)
// ---------------------------------------------------------------------------
function beginLiveTracking() {
  resetPollState();
  updateChatHeader({ lifecycle: "queued", target: "" });
  pollEvents();
  pollScanSnapshot();
}

async function pollEvents() {
  if (!state.scanId || state.fastInFlight) return;
  state.fastInFlight = true;
  try {
    const r = await fetch("/api/scan/" + state.scanId + "/events?after=" + state.eventsAfter, { cache: "no-store" });
    if (r.ok) {
      const j = await r.json();
      appendTerminalRows(j.events || []);
      state.eventsAfter = j.next || state.eventsAfter;
      setTerminalLive(j.lifecycle === "running" || j.lifecycle === "queued");
      if (!TERMINAL_STATES.has(j.lifecycle)) {
        state.fastTimer = setTimeout(pollEvents, 900);
      }
    } else {
      state.fastTimer = setTimeout(pollEvents, 2000);
    }
  } catch (_e) {
    state.fastTimer = setTimeout(pollEvents, 2000);
  } finally {
    state.fastInFlight = false;
  }
}

async function pollScanSnapshot() {
  if (!state.scanId || state.slowInFlight) return;
  state.slowInFlight = true;
  try {
    const r = await fetch("/api/scan/" + state.scanId, { cache: "no-store" });
    if (r.ok) {
      const j = await r.json();
      renderScanSnapshot(j);
      if (!TERMINAL_STATES.has(j.lifecycle)) {
        state.slowTimer = setTimeout(pollScanSnapshot, 2500);
      } else {
        onScanFinished(j);
      }
    } else {
      state.slowTimer = setTimeout(pollScanSnapshot, 3000);
    }
  } catch (_e) {
    state.slowTimer = setTimeout(pollScanSnapshot, 3000);
  } finally {
    state.slowInFlight = false;
  }
}

function onScanFinished(j) {
  if ($("finish-bubble-" + j.scan_id)) return; // already rendered once
  renderFinishBubble(j);
  renderConvoList();
  scheduleSidebarRefresh();
}

// ---------------------------------------------------------------------------
// Chat header + status/summary bubbles
// ---------------------------------------------------------------------------
function updateChatHeader(j) {
  $("chat-header-title").textContent = j.target || "New assessment";
  const lifecycle = j.lifecycle || "queued";
  state.lifecycle = lifecycle;
  const pill = $("chat-header-lifecycle");
  pill.hidden = false;
  pill.textContent = LIFECYCLE_LABEL[lifecycle] || lifecycle;
  pill.className = "chat-header-lifecycle " + lifecycle;
  // W3: once cancellation is in flight, keep the button visible but disabled and relabelled
  // so the operator gets clear feedback and a second click can't fire another cancel.
  const cancelling = lifecycle === "cancelling" || j.cancel_requested;
  const cancelBtn = $("cancel-scan");
  cancelBtn.hidden = !j.can_cancel && !cancelling;
  cancelBtn.disabled = cancelling;
  cancelBtn.textContent = cancelling ? "Cancelling…" : "Cancel";
  $("pause-scan").hidden = !j.can_pause || cancelling;
  $("resume-scan").hidden = !j.can_resume || cancelling;
}

function renderScanSnapshot(j) {
  updateChatHeader(j);
  renderMetrics(j.graph);
  renderFindingsList(j.findings, j.suspected);
  renderSurfaceTree(j.graph && j.graph.available ? null : null); // surface fetched separately below
  fetchSurface();
  renderAuditList(j.audit);
  if (j.report_md) {
    state.reportReady = true;
    renderReport(j.report_md);
    renderExportLinks(state.scanId);
  }
}

async function fetchSurface() {
  if (!state.scanId) return;
  try {
    const r = await fetch("/api/scan/" + state.scanId + "/surface", { cache: "no-store" });
    if (r.ok) renderSurfaceTree(await r.json());
  } catch (_e) {
    /* surface stays as last-rendered on a transient failure */
  }
}

function renderFinishBubble(j) {
  const box = document.createElement("div");
  box.className = "status-bubble";
  const dotClass = { completed: "completed", failed: "failed", blocked: "blocked", cancelled: "" }[j.lifecycle] || "";
  const findingCount = (j.findings || []).length;
  const summary = document.createElement("div");
  const headline = document.createElement("p");
  headline.style.margin = "0";
  if (j.lifecycle === "completed") {
    headline.innerHTML = "Assessment complete — <b>" + findingCount + "</b> oracle-confirmed finding" + (findingCount === 1 ? "" : "s") + ".";
  } else if (j.lifecycle === "blocked") {
    headline.textContent = "Blocked: " + (j.error || "authentication required further setup.");
  } else if (j.lifecycle === "cancelled") {
    headline.textContent = "Assessment cancelled by operator.";
  } else {
    headline.textContent = "Assessment failed: " + (j.error || "unknown error.");
  }
  summary.appendChild(headline);
  if (j.lifecycle === "completed" && findingCount) {
    const actions = document.createElement("div");
    actions.className = "summary-actions";
    actions.innerHTML =
      '<a class="dl" href="/api/scan/' + state.scanId + '/export?format=markdown" download>Markdown</a>' +
      '<a class="dl" href="/api/scan/' + state.scanId + '/export?format=html" download>HTML report</a>' +
      '<a class="dl" href="/api/scan/' + state.scanId + '/export?format=pdf" download>PDF</a>' +
      '<a class="dl" href="/api/scan/' + state.scanId + '/export?format=docx" download>DOCX</a>' +
      '<a class="dl" href="/api/scan/' + state.scanId + '/export?format=sarif" download>SARIF</a>';
    summary.appendChild(actions);
  }
  const dot = document.createElement("span");
  dot.className = "status-dot " + dotClass;
  box.append(dot, summary);
  addBubble("assistant", box, { id: "finish-bubble-" + j.scan_id });
}

// ---------------------------------------------------------------------------
// Terminal (live command/event feed)
// ---------------------------------------------------------------------------
function setTerminalLive(live) {
  const el = $("term-live");
  el.classList.toggle("live", live);
  el.lastChild.textContent = live ? " live" : " idle";
}

function appendTerminalRows(events) {
  if (!events.length) return;
  // W1: the agent's own decision rationale (kind "assistant-note") is a conversational turn —
  // route it into the chat log, not the terminal feed, so talking with the agent shows its
  // live reasoning too. Everything else stays in the terminal.
  const terminalEvents = [];
  events.forEach((e) => {
    if (e.kind === "assistant-note" && e.message) textBubble("assistant", e.message);
    else terminalEvents.push(e);
  });
  if (!terminalEvents.length) return;
  const feed = $("term-feed");
  // The scrollable element is the .work-body ancestor (#tab-terminal), not
  // #term-feed itself — #term-feed has no overflow/height of its own, so
  // reading/writing scrollTop on it was always a no-op.
  const scroller = $("tab-terminal");
  const emptyPlaceholder = feed.querySelector(".term-empty");
  if (emptyPlaceholder) emptyPlaceholder.remove();
  const atBottom = scroller.scrollHeight - scroller.scrollTop - scroller.clientHeight < 40;
  terminalEvents.forEach((e) => feed.appendChild(terminalRow(e)));
  $("term-count").textContent = feed.children.length + " events";
  if (atBottom) scroller.scrollTop = scroller.scrollHeight;
}

// Shown inline, always — the operator watches these run live, like a shell.
// Everything else in `details` stays behind the click-to-expand JSON panel.
const _INLINE_DETAIL_KEYS = new Set(["command", "output"]);

function formatEventTime(iso) {
  if (!iso) return "";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "";
  return d.toLocaleTimeString(undefined, { hour12: false });
}

function terminalRow(e) {
  const row = document.createElement("div");
  row.className = "term-row kind-" + (e.kind || "info");
  const time = document.createElement("span");
  time.className = "t-time";
  time.textContent = formatEventTime(e.timestamp);
  const phase = document.createElement("span");
  phase.className = "t-phase";
  phase.textContent = PHASE_STEP[e.phase] || e.phase || "";
  const dot = document.createElement("span");
  dot.className = "t-dot";
  const body = document.createElement("span");
  body.className = "t-msg";
  const msgLine = document.createElement("div");
  msgLine.textContent = e.message || "";
  body.appendChild(msgLine);

  // Recon-tier events put command/output as top-level detail keys; signal-gated
  // events nest the same concept inside a `metadata` sub-object (its own,
  // already-established shape) under `output_preview` instead of `output` —
  // check both rather than forcing one source to change its established shape.
  const details = e.details || {};
  const meta = details.metadata || {};
  const command = details.command || meta.command;
  const output = details.output || meta.output_preview;
  if (command) {
    const cmdLine = document.createElement("div");
    cmdLine.className = "t-cmd";
    cmdLine.textContent = command;
    body.appendChild(cmdLine);
  }
  if (output) {
    const outBlock = document.createElement("pre");
    outBlock.className = "t-output";
    outBlock.textContent = output;
    body.appendChild(outBlock);
  }
  row.append(time, phase, dot, body);

  const extraKeys = Object.keys(details).filter((k) => !_INLINE_DETAIL_KEYS.has(k));
  if (extraKeys.length) {
    const extra = {};
    extraKeys.forEach((k) => (extra[k] = details[k]));
    if (extra.metadata && typeof extra.metadata === "object") {
      const { command: _c, output_preview: _o, ...restMeta } = extra.metadata;
      extra.metadata = restMeta;
    }
    const more = document.createElement("div");
    more.className = "term-more";
    more.textContent = "more detail";
    const detailBox = document.createElement("div");
    detailBox.className = "term-detail";
    detailBox.hidden = true;
    detailBox.textContent = JSON.stringify(extra, null, 2);
    more.addEventListener("click", (evt) => {
      evt.stopPropagation();
      detailBox.hidden = !detailBox.hidden;
    });
    body.append(more, detailBox);
  }
  return row;
}

// ---------------------------------------------------------------------------
// Tabs
// ---------------------------------------------------------------------------
document.querySelectorAll(".work-tab").forEach((tab) => {
  tab.addEventListener("click", () => {
    document.querySelectorAll(".work-tab").forEach((t) => t.classList.remove("active"));
    tab.classList.add("active");
    const target = tab.dataset.tab;
    state.activeTab = target;
    ["terminal", "findings", "surface", "report", "audit"].forEach((name) => {
      $("tab-" + name).hidden = name !== target;
    });
  });
});

$("toggle-work-pane").onclick = () => {
  state.workPaneHidden = !state.workPaneHidden;
  $("split").classList.toggle("solo", state.workPaneHidden);
  document.querySelector(".work-pane").style.display = state.workPaneHidden ? "none" : "";
  $("resize-handle").style.display = state.workPaneHidden ? "none" : "";
  $("toggle-work-pane").textContent = state.workPaneHidden ? "Show live panel" : "Hide live panel";
};

// ---------------------------------------------------------------------------
// Findings / metrics / surface / audit / report rendering (server data, as-is)
// ---------------------------------------------------------------------------
// A short tween from a metric's current displayed value to its new one, instead of an
// instant text swap — cheap (one requestAnimationFrame loop, no library) and makes a
// live-updating dashboard read as "alive" rather than flickering numbers.
function animateMetric(el, target) {
  const from = Number(el.dataset.value || 0);
  if (from === target) return;
  el.dataset.value = target;
  if (window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
    el.textContent = target;
    return;
  }
  const duration = 400;
  const start = performance.now();
  function tick(now) {
    const t = Math.min(1, (now - start) / duration);
    const eased = 1 - (1 - t) * (1 - t);
    el.textContent = Math.round(from + (target - from) * eased);
    if (t < 1) requestAnimationFrame(tick);
    else el.textContent = target;
  }
  requestAnimationFrame(tick);
}

function renderMetrics(g) {
  const available = Boolean(g && g.available);
  const c = (g && g.counts) || {};
  if (!available) {
    ["m-hosts", "m-services", "m-endpoints", "m-params", "m-findings"].forEach((id) => {
      $(id).textContent = "—";
      $(id).dataset.value = 0;
    });
  } else {
    animateMetric($("m-hosts"), c.hosts || 0);
    animateMetric($("m-services"), c.services || 0);
    animateMetric($("m-endpoints"), c.endpoints || 0);
    animateMetric($("m-params"), c.parameters || 0);
    animateMetric($("m-findings"), c.findings || 0);
  }
  const count = $("tab-findings-count");
  if (available && c.findings) {
    count.hidden = false;
    count.textContent = c.findings;
  } else {
    count.hidden = true;
  }
}

function addMetaRow(parent, label, value) {
  const row = document.createElement("div");
  row.className = "fmeta-row";
  const b = document.createElement("b");
  b.textContent = label;
  const v = document.createElement("span");
  v.textContent = value || "—";
  row.append(b, v);
  parent.appendChild(row);
}

function addBadge(parent, text, title) {
  const b = document.createElement("span");
  b.className = "fbadge";
  b.textContent = text;
  if (title) b.title = title;
  parent.appendChild(b);
}

function buildChainRows(chains) {
  const frag = document.createDocumentFragment();
  (chains || []).forEach((ch) => {
    const row = document.createElement("div");
    row.className = "chain";
    ch.nodes.forEach((n, i) => {
      const cn = document.createElement("span");
      cn.className = "cn";
      cn.textContent = n;
      row.appendChild(cn);
      if (i < ch.kinds.length) {
        const edge = document.createElement("span");
        edge.className = "ce " + (ch.kinds[i] === "derived_credential" ? "derived" : "");
        edge.textContent = ch.kinds[i] === "derived_credential" ? "→ credential" : "→ enables";
        row.appendChild(edge);
      }
    });
    frag.appendChild(row);
  });
  return frag;
}

// Expandable <details> card — same disclosure idiom as .surface-host/.surface-endpoint
// elsewhere in this file, so opening a finding for detail is a familiar interaction.
// A short entrance animation plays once, staggered by `index` (--i), the first time a
// card is created; polling never recreates an existing card (see the signature guard in
// renderFindingsList/renderSuspectedInto below), so an operator's expanded card survives
// every subsequent poll instead of snapping shut every ~1s.
// Real captured proof (v2 Phase 6 Stage E1) — a bounded, already secret-scrubbed
// response snippet an oracle captured at decision time, not just the opaque
// evidence_ref handle string. Differential-family findings get a baseline-vs-probe
// pair (closer to what the oracle actually decided on than a single highlight);
// everything else gets one "Response evidence" block.
function evidenceCodeBlock(label, text) {
  const wrap = document.createElement("div");
  wrap.className = "fevidence-block";
  const b = document.createElement("b");
  b.textContent = label;
  const pre = document.createElement("pre");
  pre.className = "fevidence-code";
  pre.textContent = text;
  wrap.append(b, pre);
  return wrap;
}

function buildEvidenceBlock(evidence) {
  const box = document.createElement("div");
  if (!evidence) return box;
  box.className = "fevidence";
  if (evidence.baseline_body_projection || evidence.probe_body_projection) {
    if (evidence.baseline_body_projection) {
      box.appendChild(evidenceCodeBlock("Baseline response", evidence.baseline_body_projection));
    }
    if (evidence.probe_body_projection) {
      box.appendChild(evidenceCodeBlock("Probe response", evidence.probe_body_projection));
    }
  } else if (evidence.body_projection) {
    box.appendChild(evidenceCodeBlock("Response evidence", evidence.body_projection));
  }
  if (evidence.headers && evidence.headers.length) {
    const hdrs = document.createElement("div");
    hdrs.className = "fevidence-headers";
    evidence.headers.forEach(([name, value]) => {
      const row = document.createElement("div");
      row.className = "fevidence-header-row";
      const n = document.createElement("code");
      n.textContent = name;
      const v = document.createElement("span");
      v.textContent = value;
      row.append(n, v);
      hdrs.appendChild(row);
    });
    box.appendChild(hdrs);
  }
  return box;
}

function buildFindingCard(f, index) {
  const card = document.createElement("details");
  card.className = "fcard " + (f.severity || "");
  card.style.setProperty("--i", index);
  const summary = document.createElement("summary");
  summary.className = "fhead";
  const cls = document.createElement("span");
  cls.className = "fclass";
  cls.textContent = f.vuln_class || "finding";
  const sev = document.createElement("span");
  sev.className = "fsev";
  sev.textContent = f.severity || "unknown";
  summary.append(cls, sev);
  card.appendChild(summary);

  const body = document.createElement("div");
  body.className = "fbody";
  if (f.description) {
    const p = document.createElement("p");
    p.className = "fdesc";
    p.textContent = f.description;
    body.appendChild(p);
  }
  const badges = document.createElement("div");
  badges.className = "fbadges";
  if (f.wstg_id) addBadge(badges, f.wstg_id);
  if (f.cwe_id) addBadge(badges, f.cwe_id);
  if (f.cvss) addBadge(badges, "CVSS " + f.cvss, f.cvss_vector || "");
  if (f.likelihood) addBadge(badges, "Likelihood " + f.likelihood);
  if (f.impact) addBadge(badges, "Impact " + f.impact);
  if (badges.childNodes.length) body.appendChild(badges);

  const meta = document.createElement("div");
  meta.className = "fmeta";
  addMetaRow(meta, "Oracle", f.oracle_used);
  addMetaRow(meta, "Evidence", f.evidence_ref);
  addMetaRow(meta, "Status", f.status);
  if (f.chain_precondition) addMetaRow(meta, "Chain", f.chain_precondition);
  body.appendChild(meta);

  body.appendChild(buildEvidenceBlock(f.evidence));

  if (f.remediation) {
    const rem = document.createElement("div");
    rem.className = "fremediation";
    const b = document.createElement("b");
    b.textContent = "Remediation";
    const p = document.createElement("p");
    p.textContent = f.remediation;
    rem.append(b, p);
    body.appendChild(rem);
  }
  body.appendChild(buildChainRows(f.chains));
  card.appendChild(body);
  return card;
}

function buildSuspectedCard(s, index) {
  const card = document.createElement("details");
  card.className = "fcard suspected";
  card.style.setProperty("--i", index);
  const summary = document.createElement("summary");
  summary.className = "fhead";
  const cls = document.createElement("span");
  cls.className = "fclass";
  cls.textContent = s.vuln_class || "suspected";
  const sev = document.createElement("span");
  sev.className = "fsev";
  sev.textContent = "unconfirmed";
  summary.append(cls, sev);
  card.appendChild(summary);

  const body = document.createElement("div");
  body.className = "fbody";
  if (s.description) {
    const p = document.createElement("p");
    p.className = "fdesc";
    p.textContent = s.description;
    body.appendChild(p);
  }
  const meta = document.createElement("div");
  meta.className = "fmeta";
  addMetaRow(meta, "Endpoint", s.endpoint);
  addMetaRow(meta, "Location", s.location);
  addMetaRow(meta, "Source", s.source);
  addMetaRow(meta, "Why unconfirmed", s.reason);
  body.appendChild(meta);
  card.appendChild(body);
  return card;
}

function renderSuspectedInto(box, suspected, startIndex) {
  // W2: the Suspected/Unconfirmed tier, rendered visibly SEPARATE from confirmed findings —
  // leads the oracle didn't prove, for manual review, never counted as confirmed.
  if (!suspected || !suspected.length) return;
  const divider = document.createElement("div");
  divider.className = "suspected-divider";
  divider.textContent = "Suspected / Unconfirmed — " + suspected.length + " (not oracle-verified)";
  box.appendChild(divider);
  suspected.forEach((s, i) => box.appendChild(buildSuspectedCard(s, startIndex + i)));
}

let _findingsSignature = null;

function renderFindingsList(findings, suspected) {
  const box = $("findings-list");
  if (findings === null) {
    _findingsSignature = null;
    box.innerHTML = "";
    return;
  }
  if ((!findings || !findings.length) && (!suspected || !suspected.length)) {
    _findingsSignature = "0:0";
    box.innerHTML = '<div class="empty">No oracle-confirmed findings yet.</div>';
    return;
  }
  // Polling re-fetches the full list every ~1s; findings/suspected leads are add-only
  // and immutable once written, so a count signature is a sufficient, cheap diff — skip
  // the rebuild entirely when nothing changed, so an operator-expanded <details> card
  // (and scroll position) survive the next poll instead of resetting every second.
  const signature = (findings || []).length + ":" + (suspected || []).length;
  if (signature === _findingsSignature) return;
  _findingsSignature = signature;
  box.innerHTML = "";
  if (!findings || !findings.length) {
    const note = document.createElement("div");
    note.className = "empty";
    note.textContent = "No oracle-confirmed findings yet.";
    box.appendChild(note);
  }
  (findings || []).forEach((f, i) => box.appendChild(buildFindingCard(f, i)));
  renderSuspectedInto(box, suspected, (findings || []).length);
}

let _surfaceSignature = null;

function renderSurfaceTree(surface) {
  if (surface === null) return; // caller fetches asynchronously and re-invokes
  const box = $("surface-tree");
  const hosts = (surface && surface.hosts) || [];
  const orphan = (surface && surface.orphan_endpoints) || [];
  if (surface && surface.available === false) {
    // A conversation switch's explicit reset — always force a real rebuild next
    // time, never let a coincidentally-matching signature from a DIFFERENT scan
    // suppress it.
    _surfaceSignature = null;
  } else {
    // The recon-tier surface is add-only within a scan (hosts/endpoints/params
    // are never removed once discovered), so a count-based signature is a cheap,
    // sufficient diff — fetchSurface() re-fetches and rebuilds the WHOLE tree
    // every ~2.5s poll unconditionally, which (after Stage A/E4 added an
    // entrance animation to .surface-host) replayed on every single poll tick —
    // a real, visible "flickering/blinking" regression. Skip the rebuild
    // entirely when nothing actually changed.
    const paramCount = (eps) => (eps || []).reduce((n, ep) => n + (ep.parameters || []).length, 0);
    const endpointCount = hosts.reduce((n, h) => n + (h.endpoints || []).length, 0) + orphan.length;
    const totalParams =
      hosts.reduce((n, h) => n + paramCount(h.endpoints), 0) + paramCount(orphan);
    const signature = [hosts.length, endpointCount, totalParams, orphan.length].join(":");
    if (signature === _surfaceSignature) return;
    _surfaceSignature = signature;
  }
  if (!hosts.length && !orphan.length) {
    box.innerHTML = '<div class="empty">No endpoints discovered yet.</div>';
    return;
  }
  box.innerHTML = "";
  const endpointEl = (ep) => {
    const d = document.createElement("details");
    d.className = "surface-endpoint";
    const s = document.createElement("summary");
    const method = document.createElement("span");
    const m0 = ep.method || "GET";
    method.className = "audit-method " + (_WRITE_METHODS.has(m0) ? "write" : "read");
    method.textContent = m0;
    const path = document.createElement("span");
    path.className = "surface-path";
    path.textContent = ep.path || "";
    s.append(method, path);
    d.appendChild(s);
    const m = document.createElement("div");
    m.className = "node-meta";
    m.textContent = (ep.access_restricted ? "restricted " + ep.access_restricted + " · " : "") + (ep.technology || ep.content_type || "endpoint");
    d.appendChild(m);
    const params = ep.parameters || [];
    if (params.length) {
      const wrap = document.createElement("div");
      wrap.className = "surface-params";
      params.forEach((p) => {
        const pill = document.createElement("span");
        pill.className = "surface-param" + (p.inferred_sink_type ? " sink" : "");
        pill.textContent =
          (p.location || "query") + ":" + (p.name || "") + (p.inferred_sink_type ? " → " + p.inferred_sink_type : "");
        wrap.appendChild(pill);
      });
      d.appendChild(wrap);
    }
    return d;
  };
  hosts.forEach((h) => {
    const d = document.createElement("details");
    d.className = "surface-host";
    d.open = true;
    const s = document.createElement("summary");
    s.textContent = h.address || h.hostname || h.id;
    d.appendChild(s);
    const m = document.createElement("div");
    m.className = "node-meta";
    m.textContent = h.technology || h.source || "host";
    d.appendChild(m);
    (h.services || []).forEach((svc) => {
      const x = document.createElement("div");
      x.className = "node-meta";
      x.textContent = "service " + svc.port + "/" + svc.protocol + (svc.service_name ? " " + svc.service_name : "");
      d.appendChild(x);
    });
    (h.endpoints || []).forEach((ep) => d.appendChild(endpointEl(ep)));
    box.appendChild(d);
  });
  orphan.forEach((ep) => box.appendChild(endpointEl(ep)));
}

function renderAuditList(rows) {
  const box = $("audit-list");
  if (!rows || !rows.length) {
    box.innerHTML = '<div class="empty">Waiting for an assessment.</div>';
    return;
  }
  box.innerHTML = "";
  const head = document.createElement("div");
  head.className = "audit-head";
  ["Time", "Identity", "Method", "Target", "Outcome"].forEach((label) => {
    const cell = document.createElement("span");
    cell.textContent = label;
    head.appendChild(cell);
  });
  box.appendChild(head);
  rows.forEach((r, i) => {
    const row = document.createElement("div");
    row.className = "audit-row";
    row.style.setProperty("--i", Math.min(i, 30));
    const ts = document.createElement("span");
    ts.className = "muted";
    ts.textContent = (r.timestamp || "").slice(11, 19);
    const id = document.createElement("span");
    id.className = "id";
    id.textContent = r.identity || "—";
    const m = document.createElement("span");
    const method = r.method || "—";
    m.className = "audit-method " + (_WRITE_METHODS.has(method) ? "write" : "read");
    m.textContent = method;
    const tgt = document.createElement("span");
    tgt.className = "audit-target";
    tgt.textContent = r.target || "—";
    const key = (r.outcome || "").split(":")[0];
    const out = document.createElement("span");
    out.className = OUT_CLASS[key] || "";
    out.textContent = r.outcome || "—";
    row.append(ts, id, m, tgt, out);
    box.appendChild(row);
  });
}

function mdToHtml(md) {
  const fmt = (t) => esc(t).replace(/\*\*(.+?)\*\*/g, "<b>$1</b>").replace(/`([^`]+)`/g, '<code class="inline-code">$1</code>');
  const lines = md.split("\n");
  const out = [];
  let inTable = false, rows = [], inList = false, inCode = false, codeBuf = [];
  const flushTable = () => {
    if (!rows.length) return;
    out.push("<table>" + rows.map((r, i) => "<tr>" + r.map((c) => "<" + (i ? "td" : "th") + ">" + c + "</" + (i ? "td" : "th") + ">").join("") + "</tr>").join("") + "</table>");
    rows = [];
  };
  const flushList = () => {
    if (!inList) return;
    out.push("</ul>");
    inList = false;
  };
  const flushCode = () => {
    if (!inCode) return;
    out.push("<pre><code>" + esc(codeBuf.join("\n")) + "</code></pre>");
    codeBuf = [];
    inCode = false;
  };
  lines.forEach((line) => {
    if (inCode) {
      if (line.trim().startsWith("```")) flushCode();
      else codeBuf.push(line);
      return;
    }
    if (line.trim().startsWith("```")) {
      flushTable();
      flushList();
      inCode = true;
      codeBuf = [];
      return;
    }
    const t = line.trim();
    if (t.startsWith("|") && t.endsWith("|")) {
      flushList();
      const cells = t.slice(1, -1).split("|").map((c) => fmt(c.trim()));
      if (!inTable) {
        inTable = true;
        rows = [cells];
      } else if (!cells.every((c) => /^:?-{2,}:?$/.test(c))) {
        rows.push(cells);
      }
      return;
    }
    if (inTable) {
      inTable = false;
      flushTable();
    }
    if (/^- /.test(t)) {
      if (!inList) {
        flushTable();
        out.push("<ul>");
        inList = true;
      }
      out.push("<li>" + fmt(t.slice(2)) + "</li>");
      return;
    }
    if (inList) flushList();
    if (/^#{1,4} /.test(t)) {
      flushTable();
      const level = t.indexOf(" ");
      out.push("<h" + level + ">" + fmt(t.replace(/^#+\s*/, "")) + "</h" + level + ">");
    } else if (t === "---") {
      out.push("<hr>");
    } else if (t) {
      out.push("<p>" + fmt(t) + "</p>");
    }
  });
  if (inTable) flushTable();
  flushList();
  flushCode();
  return out.join("\n");
}

function renderReport(md) {
  $("report-body").innerHTML = md ? mdToHtml(String(md)) : '<div class="empty">No report yet — appears once the assessment finishes.</div>';
}

function renderExportLinks(scanId) {
  $("report-toolbar").hidden = false;
  ["md", "json", "sarif", "evidence", "bundle", "html", "pdf", "docx"].forEach((fmt) => {
    const key = fmt === "md" ? "markdown" : fmt;
    $("dl-" + fmt).href = "/api/scan/" + scanId + "/export?format=" + key;
  });
}

$("cancel-scan").onclick = async () => {
  if (!state.scanId) return;
  if (!confirm("Cancel this assessment? This stops the scan and cannot be undone.")) return;
  const btn = $("cancel-scan");
  btn.disabled = true;
  try {
    await fetch("/api/scan/" + state.scanId + "/cancel", { method: "POST" });
  } finally {
    btn.disabled = false;
  }
};

$("pause-scan").onclick = async () => {
  if (!state.scanId) return;
  const btn = $("pause-scan");
  btn.disabled = true;
  try {
    await fetch("/api/scan/" + state.scanId + "/pause", { method: "POST" });
  } finally {
    btn.disabled = false;
  }
};

$("resume-scan").onclick = async () => {
  if (!state.scanId) return;
  const btn = $("resume-scan");
  btn.disabled = true;
  try {
    await fetch("/api/scan/" + state.scanId + "/resume", { method: "POST" });
  } finally {
    btn.disabled = false;
  }
};

// ---------------------------------------------------------------------------
// Sidebar conversation list
// ---------------------------------------------------------------------------
function scheduleSidebarRefresh() {
  clearTimeout(state.sidebarTimer);
  state.sidebarTimer = setTimeout(async () => {
    await renderConvoList();
    state.sidebarTimer = setTimeout(scheduleSidebarRefresh, 4000);
  }, 4000);
}

async function renderConvoList() {
  let scans = [];
  try {
    const r = await fetch("/api/scans?limit=30", { cache: "no-store" });
    if (r.ok) scans = (await r.json()).scans || [];
  } catch (_e) {
    return;
  }
  const box = $("convo-list");
  if (!scans.length) {
    box.innerHTML = '<span class="convo-empty">No assessments yet.</span>';
    return;
  }
  box.innerHTML = "";
  scans.forEach((s) => {
    const row = document.createElement("button");
    row.type = "button";
    row.className = "convo-row" + (s.scan_id === state.scanId ? " active" : "");
    row.onclick = () => openExistingConversation(s.scan_id);
    const title = document.createElement("span");
    title.className = "convo-title";
    title.textContent = s.target || "Untitled assessment";
    const meta = document.createElement("span");
    meta.className = "convo-meta";
    const dot = document.createElement("span");
    dot.className = "convo-dot " + (s.lifecycle || "");
    const label = document.createElement("span");
    label.textContent = LIFECYCLE_LABEL[s.lifecycle] || s.lifecycle || "queued";
    meta.append(dot, label);
    row.append(title, meta);
    box.appendChild(row);
  });
}

async function openExistingConversation(scanId) {
  closeMobileSidebar();
  showConversation(scanId);
  try {
    const r = await fetch("/api/scan/" + scanId, { cache: "no-store" });
    if (!r.ok) throw new Error("not found");
    const j = await r.json();
    if (j.operator_prompt) textBubble("user", j.operator_prompt);
    const summary = document.createElement("div");
    summary.className = "cc-frozen";
    summary.innerHTML = "<span>Target: <b>" + esc(j.target || "") + "</b></span>";
    addBubble("assistant", summary);
    renderScanSnapshot(j);
    state.eventsAfter = 0;
    appendTerminalRows(j.events || []);
    if (TERMINAL_STATES.has(j.lifecycle)) {
      onScanFinished(j);
      setTerminalLive(false);
    } else {
      state.eventsAfter = j.events ? j.events.length : 0;
      pollEvents();
      pollScanSnapshot();
    }
  } catch (_e) {
    textBubble("assistant", "Could not load this assessment — it may have been cleared from server memory.");
  }
  renderConvoList();
}

// ---------------------------------------------------------------------------
// Settings modal (LLM providers) — same CRUD flow as before, in a dialog
// ---------------------------------------------------------------------------
let provEditing = null;

function populateProviderSelect(select) {
  fetch("/api/providers")
    .then((r) => r.json())
    .then((j) => {
      select.innerHTML = '<option value="">Server default</option>';
      (j.providers || []).forEach((p) => {
        const o = document.createElement("option");
        o.value = "named:" + p.id;
        o.textContent = p.name;
        select.appendChild(o);
      });
      if (!(j.default || {}).has_key && (j.providers || []).length === 1) {
        select.value = "named:" + j.providers[0].id;
      }
    })
    .catch(() => {});
}

async function loadProviders() {
  try {
    const r = await fetch("/api/providers");
    const j = await r.json();
    renderProviderList(j);
  } catch (_e) {
    $("prov-list").innerHTML = '<div class="empty">Failed to load providers.</div>';
  }
}

function renderProviderList(j) {
  const box = $("prov-list");
  box.innerHTML = "";
  const d = j.default || {};
  const defaultRow = document.createElement("div");
  defaultRow.className = "provider-row";
  defaultRow.innerHTML =
    '<div class="provider-row-main"><div class="provider-row-name">Server default</div><div class="provider-row-meta">' +
    esc(d.provider || "unset") + (d.model ? " · " + esc(d.model) : "") + "</div></div>" +
    '<span class="fsev" style="background:var(--field)">' + (d.has_key ? "key set" : "no key") + "</span>";
  box.appendChild(defaultRow);
  (j.providers || []).forEach((p) => {
    const row = document.createElement("div");
    row.className = "provider-row";
    const main = document.createElement("div");
    main.className = "provider-row-main";
    main.innerHTML = '<div class="provider-row-name">' + esc(p.name) + '</div><div class="provider-row-meta">' + esc(p.provider) + " · " + esc(p.model || p.base_url || "") + "</div>";
    const actions = document.createElement("div");
    actions.className = "provider-row-actions";
    const testBtn = document.createElement("button");
    testBtn.className = "header-btn";
    testBtn.type = "button";
    testBtn.textContent = "Test";
    testBtn.onclick = async () => {
      testBtn.textContent = "…";
      try {
        const tr = await fetch("/api/providers/" + p.id + "/test", { method: "POST" });
        const tj = await tr.json();
        testBtn.textContent = tj.ok ? "✓ ok" : "✗ fail";
      } catch (_e) {
        testBtn.textContent = "✗";
      }
      setTimeout(() => (testBtn.textContent = "Test"), 2500);
    };
    const editBtn = document.createElement("button");
    editBtn.className = "header-btn";
    editBtn.type = "button";
    editBtn.textContent = "Edit";
    editBtn.onclick = () => openProviderForm(p);
    const delBtn = document.createElement("button");
    delBtn.className = "header-btn danger";
    delBtn.type = "button";
    delBtn.textContent = "Delete";
    delBtn.onclick = async () => {
      if (!confirm("Delete " + p.name + "?")) return;
      await fetch("/api/providers/" + p.id, { method: "DELETE" });
      loadProviders();
    };
    actions.append(testBtn, editBtn, delBtn);
    row.append(main, actions);
    box.appendChild(row);
  });
}

function openProviderForm(p) {
  provEditing = p ? p.id : null;
  $("pf-name").value = p ? p.name : "";
  $("pf-provider").value = p ? p.provider : "openai-compatible";
  $("pf-base-url").value = p ? p.base_url || "" : "";
  $("pf-model").value = p ? p.model || "" : "";
  $("pf-api-style").value = p ? p.api_style || "chat_completions" : "chat_completions";
  $("pf-grunt-model").value = p ? p.grunt_model || "" : "";
  $("pf-api-key").value = "";
  $("prov-form-error").textContent = "";
  $("provider-form").hidden = false;
}

$("prov-new").onclick = () => openProviderForm(null);
$("prov-save").onclick = async () => {
  const body = {
    id: provEditing,
    name: $("pf-name").value.trim(),
    provider: $("pf-provider").value,
    base_url: $("pf-base-url").value.trim(),
    model: $("pf-model").value.trim(),
    api_style: $("pf-api-style").value,
    grunt_model: $("pf-grunt-model").value.trim(),
    api_key: $("pf-api-key").value.trim(),
  };
  try {
    const r = await fetch("/api/providers", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
    const j = await r.json();
    if (j.error) {
      $("prov-form-error").textContent = j.error;
      return;
    }
    $("provider-form").hidden = true;
    loadProviders();
  } catch (e) {
    $("prov-form-error").textContent = String(e);
  }
};
$("prov-test").onclick = async () => {
  $("prov-form-error").textContent = "testing…";
  const body = {
    name: $("pf-name").value.trim() || "test",
    provider: $("pf-provider").value,
    base_url: $("pf-base-url").value.trim(),
    model: $("pf-model").value.trim(),
    api_style: $("pf-api-style").value,
    api_key: $("pf-api-key").value.trim(),
  };
  try {
    if (!provEditing) {
      const sr = await fetch("/api/providers", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
      const sj = await sr.json();
      if (sj.error) {
        $("prov-form-error").textContent = sj.error;
        return;
      }
      provEditing = sj.id;
    }
    const r = await fetch("/api/providers/" + provEditing + "/test", { method: "POST" });
    const j = await r.json();
    $("prov-form-error").textContent = j.ok ? "ok — reply: " + (j.reply || "") : j.error;
  } catch (e) {
    $("prov-form-error").textContent = String(e);
  }
};

// v3 V6: "Scan defaults" section of the Settings modal — the recon-tuning
// checkboxes + max-attempts/recon-depth/wordlist/repo-path settings that used
// to be re-asked in every scan's confirmation form now live here, set once.
function populateScanDefaultsForm() {
  const d = loadScanDefaults();
  $("sd-max-attempts").value = d.max_attempts;
  $("sd-recon-depth").value = d.recon_depth;
  $("sd-wordlist-size").value = d.wordlist_size;
  $("sd-repo-path").value = d.repo_path || "";
  $("sd-tune-surface").checked = !!d.surface_tuning;
  $("sd-tune-signal").checked = !!d.signal_tuning;
  $("sd-tune-transport").checked = !!d.transport_tuning;
  $("sd-tune-guardian").checked = !!d.guardian_advisor;
  $("sd-tune-concurrent").checked = !!d.concurrent_specialists;
  $("sd-tune-aggressive").checked = !!d.aggressive;
  $("sd-tune-depth").checked = !!d.recon_depth_tuning;
  $("sd-tune-wordlist-depth").checked = !!d.wordlist_depth_tuning;
  $("sd-tune-ratelimit").checked = !!d.rate_limit_corroboration;
}

function persistScanDefaultsForm() {
  saveScanDefaults({
    max_attempts: parseInt($("sd-max-attempts").value, 10) || 20,
    recon_depth: $("sd-recon-depth").value,
    wordlist_size: $("sd-wordlist-size").value,
    repo_path: $("sd-repo-path").value.trim() || null,
    surface_tuning: $("sd-tune-surface").checked,
    signal_tuning: $("sd-tune-signal").checked,
    transport_tuning: $("sd-tune-transport").checked,
    guardian_advisor: $("sd-tune-guardian").checked,
    concurrent_specialists: $("sd-tune-concurrent").checked,
    aggressive: $("sd-tune-aggressive").checked,
    recon_depth_tuning: $("sd-tune-depth").checked,
    wordlist_depth_tuning: $("sd-tune-wordlist-depth").checked,
    rate_limit_corroboration: $("sd-tune-ratelimit").checked,
  });
}

document.querySelectorAll("#scan-defaults-form input, #scan-defaults-form select").forEach((el) => {
  el.addEventListener("change", persistScanDefaultsForm);
});

$("open-settings").onclick = () => {
  $("settings-overlay").hidden = false;
  loadProviders();
  populateScanDefaultsForm();
};
$("settings-close").onclick = () => {
  $("settings-overlay").hidden = true;
};
$("settings-overlay").addEventListener("click", (e) => {
  if (e.target.id === "settings-overlay") $("settings-overlay").hidden = true;
});

// ---------------------------------------------------------------------------
// Resizable split
// ---------------------------------------------------------------------------
(function wireResize() {
  const handle = $("resize-handle");
  const split = $("split");
  let dragging = false;
  handle.addEventListener("mousedown", () => {
    dragging = true;
    handle.classList.add("dragging");
    document.body.style.userSelect = "none";
  });
  window.addEventListener("mousemove", (e) => {
    if (!dragging) return;
    const rect = split.getBoundingClientRect();
    const ratio = Math.min(0.78, Math.max(0.22, (e.clientX - rect.left) / rect.width));
    state.splitRatio = ratio;
    split.style.gridTemplateColumns = ratio * 100 + "% 5px " + (100 - ratio * 100) + "%";
  });
  window.addEventListener("mouseup", () => {
    if (!dragging) return;
    dragging = false;
    handle.classList.remove("dragging");
    document.body.style.userSelect = "";
  });
})();

// ---------------------------------------------------------------------------
// Theme
// ---------------------------------------------------------------------------
$("theme-toggle").onclick = () => {
  const next = document.documentElement.dataset.theme === "dark" ? "light" : "dark";
  document.documentElement.dataset.theme = next;
  localStorage.setItem("reachagent-theme", next);
};
const savedTheme = localStorage.getItem("reachagent-theme");
if (savedTheme) document.documentElement.dataset.theme = savedTheme;

// ---------------------------------------------------------------------------
// Boot
// ---------------------------------------------------------------------------
renderConvoList();
scheduleSidebarRefresh();
