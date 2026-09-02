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

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------
const state = {
  scanId: null,
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
async function startNewAssessment(message) {
  message = message.trim();
  if (!message) return;
  showConversation(null); // clears the log; scanId stays null until confirmed
  textBubble("user", message);

  const thinkingP = document.createElement("div");
  thinkingP.className = "thinking";
  thinkingP.innerHTML = "<span></span><span></span><span></span>";
  const thinkingBubble = addBubble("assistant", thinkingP, { id: "thinking-bubble" });

  let proposal = { target: "", in_scope: "", out_of_scope: "", credentials: [], goal: message, extracted: false };
  try {
    const r = await fetch("/api/parse-intent", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ message }),
    });
    if (r.ok) proposal = await r.json();
  } catch (_e) {
    /* degrade to the empty proposal below — the confirmation card still works */
  }
  thinkingBubble.remove();
  textBubble(
    "assistant",
    proposal.extracted && proposal.target
      ? "Got it — here's what I'll run against " + proposal.target + ". Adjust anything below, then confirm to start."
      : "I'll need a bit more to go on. Fill in the target, scope, and any credentials below to continue."
  );
  renderConfirmationCard(proposal, message);
}

function credRow(cred) {
  cred = cred || { username: "", password: "", role: "user" };
  const row = document.createElement("div");
  row.className = "cred-row";
  row.innerHTML =
    '<input class="cred-username" type="text" placeholder="username" value="' + esc(cred.username) + '">' +
    '<input class="cred-password" type="text" placeholder="password" value="' + esc(cred.password) + '">' +
    '<select class="cred-role"><option value="user">user</option><option value="admin">admin</option></select>' +
    '<button class="cred-remove" type="button" aria-label="Remove">✕</button>';
  row.querySelector(".cred-role").value = cred.role === "admin" ? "admin" : "user";
  row.querySelector(".cred-remove").onclick = () => row.remove();
  return row;
}

function renderConfirmationCard(proposal, originalMessage) {
  const card = document.createElement("div");
  card.className = "confirm-card";

  const title = document.createElement("div");
  title.className = "cc-title";
  title.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 12l2 2 4-4"/><circle cx="12" cy="12" r="9"/></svg>Review before I start';
  card.appendChild(title);

  if (!proposal.extracted) {
    const note = document.createElement("div");
    note.className = "confirm-note";
    note.textContent = "I couldn't auto-detect scope from that message — fill in the target below to continue.";
    card.appendChild(note);
  }

  const grid = document.createElement("div");
  grid.className = "cc-grid";
  grid.innerHTML =
    '<div class="cc-field span-2"><label>Target URL</label><input id="cc-target" type="text" placeholder="https://authorized-target.example" value="' + esc(proposal.target) + '"></div>' +
    '<div class="cc-field"><label>In-scope hosts</label><input id="cc-scope" type="text" placeholder="same as target" value="' + esc(proposal.in_scope) + '"></div>' +
    '<div class="cc-field"><label>Out-of-scope (optional)</label><input id="cc-outscope" type="text" placeholder="admin.example" value="' + esc(proposal.out_of_scope || "") + '"></div>' +
    '<div class="cc-field span-2"><label>Objective</label><textarea id="cc-goal" rows="2">' + esc(proposal.goal || originalMessage) + '</textarea></div>' +
    '<div class="cc-field span-2 cc-creds"><label>Credentials</label><div id="cc-cred-rows"></div><button id="cc-cred-add" class="cred-add" type="button">+ Add credential</button></div>';
  card.appendChild(grid);

  const credBox = grid.querySelector("#cc-cred-rows");
  (proposal.credentials || []).forEach((c) => credBox.appendChild(credRow(c)));
  grid.querySelector("#cc-cred-add").onclick = () => credBox.appendChild(credRow());

  const advanced = document.createElement("details");
  advanced.className = "cc-advanced";
  advanced.innerHTML =
    '<summary>Advanced</summary>' +
    '<div class="cc-advanced-body">' +
    '<div class="cc-grid">' +
    '<div class="cc-field"><label>LLM provider</label><select id="cc-provider"><option value="">Server default</option></select></div>' +
    '<div class="cc-field"><label>Max attempts</label><input id="cc-attempts" type="number" value="20" min="5" max="200"></div>' +
    '<div class="cc-field"><label>Repo path (white-box, optional)</label><input id="cc-repo-path" type="text" placeholder="/path/to/local/repo"></div>' +
    '</div>' +
    '<div><label style="display:block;margin:0 0 7px;color:var(--muted);font-size:10px;font-weight:650">Recon tuning (opt-in)</label>' +
    '<div class="tuning-grid">' +
    tuningChip("cc-tune-surface", "Surface priority") +
    tuningChip("cc-tune-signal", "Signal-tool") +
    tuningChip("cc-tune-transport", "Transport") +
    tuningChip("cc-tune-guardian", "Guardian advisor") +
    tuningChip("cc-tune-concurrent", "Concurrent specialists") +
    tuningChip("cc-tune-aggressive", "Aggressive mode") +
    '</div></div></div>';
  card.appendChild(advanced);
  populateProviderSelect(advanced.querySelector("#cc-provider"));

  const footer = document.createElement("div");
  footer.className = "cc-footer";
  footer.innerHTML =
    '<span class="cc-hint">Credentials are sent only to launch this assessment — never written to disk.</span>' +
    '<button id="cc-start" class="primary-btn" type="button"><span>Start assessment</span><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="m5 12 14 0M13 6l6 6-6 6"/></svg></button>';
  card.appendChild(footer);

  const bubble = addBubble("assistant", card, { id: "confirm-card-bubble" });
  footer.querySelector("#cc-start").onclick = () => confirmAndStart(card, bubble, originalMessage);
}

function tuningChip(id, label) {
  return (
    '<label class="tuning-chip"><input id="' + id + '" type="checkbox">' +
    '<span class="box"><svg viewBox="0 0 24 24" fill="none"><path d="M5 13l4 4L19 7"/></svg></span>' + esc(label) + "</label>"
  );
}

async function confirmAndStart(card, bubble, originalMessage) {
  const target = card.querySelector("#cc-target").value.trim();
  if (!target) {
    card.querySelector("#cc-target").focus();
    return;
  }
  const startBtn = card.querySelector("#cc-start");
  startBtn.disabled = true;
  startBtn.querySelector("span").textContent = "Starting…";

  const credentials = Array.from(card.querySelectorAll(".cred-row"))
    .map((row) => ({
      username: row.querySelector(".cred-username").value.trim(),
      password: row.querySelector(".cred-password").value.trim(),
      role: row.querySelector(".cred-role").value,
    }))
    .filter((c) => c.username && c.password);

  const body = {
    target,
    in_scope: card.querySelector("#cc-scope").value.trim() || target,
    out_of_scope: card.querySelector("#cc-outscope").value.trim() || null,
    prompt: card.querySelector("#cc-goal").value.trim() || originalMessage,
    max_attempts: parseInt(card.querySelector("#cc-attempts").value, 10) || 20,
    use_llm: true,
    llm_provider: card.querySelector("#cc-provider").value || null,
    identities: credentials.length ? credentials : undefined,
    surface_tuning: card.querySelector("#cc-tune-surface").checked,
    signal_tuning: card.querySelector("#cc-tune-signal").checked,
    transport_tuning: card.querySelector("#cc-tune-transport").checked,
    guardian_advisor: card.querySelector("#cc-tune-guardian").checked,
    concurrent_specialists: card.querySelector("#cc-tune-concurrent").checked,
    aggressive: card.querySelector("#cc-tune-aggressive").checked,
    repo_path: card.querySelector("#cc-repo-path").value.trim() || null,
  };

  try {
    const r = await fetch("/api/scan", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
    const j = await r.json();
    if (!r.ok || j.error) throw new Error(j.error || "Could not queue assessment");
    freezeConfirmationCard(bubble, target, body.in_scope, credentials.length);
    state.scanId = j.scan_id;
    beginLiveTracking();
    renderConvoList();
    scheduleSidebarRefresh();
  } catch (err) {
    startBtn.disabled = false;
    startBtn.querySelector("span").textContent = "Start assessment";
    const errNote = document.createElement("div");
    errNote.className = "confirm-note";
    errNote.textContent = String(err.message || err);
    card.appendChild(errNote);
  }
}

function freezeConfirmationCard(bubble, target, scope, credCount) {
  const frozen = document.createElement("div");
  frozen.className = "cc-frozen";
  frozen.innerHTML =
    "<span>Target: <b>" + esc(target) + "</b></span>" +
    "<span>Scope: <b>" + esc(scope) + "</b></span>" +
    "<span>Credentials: <b>" + credCount + "</b></span>" +
    "<span>Starting assessment…</span>";
  bubble.querySelector(".msg-bubble").replaceChildren(frozen);
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
  textBubble("user", message);
  if (!state.scanId) return;
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

function terminalRow(e) {
  const row = document.createElement("div");
  row.className = "term-row kind-" + (e.kind || "info");
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
  row.append(phase, dot, body);

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
function renderMetrics(g) {
  const available = Boolean(g && g.available);
  const c = (g && g.counts) || {};
  $("m-hosts").textContent = available ? c.hosts || 0 : "—";
  $("m-services").textContent = available ? c.services || 0 : "—";
  $("m-endpoints").textContent = available ? c.endpoints || 0 : "—";
  $("m-params").textContent = available ? c.parameters || 0 : "—";
  $("m-findings").textContent = available ? c.findings || 0 : "—";
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

function renderSuspectedInto(box, suspected) {
  // W2: the Suspected/Unconfirmed tier, rendered visibly SEPARATE from confirmed findings —
  // leads the oracle didn't prove, for manual review, never counted as confirmed.
  if (!suspected || !suspected.length) return;
  const divider = document.createElement("div");
  divider.className = "suspected-divider";
  divider.textContent = "Suspected / Unconfirmed — " + suspected.length + " (not oracle-verified)";
  box.appendChild(divider);
  suspected.forEach((s) => {
    const card = document.createElement("div");
    card.className = "fcard suspected";
    const head = document.createElement("div");
    head.className = "fhead";
    const cls = document.createElement("span");
    cls.className = "fclass";
    cls.textContent = s.vuln_class || "suspected";
    const sev = document.createElement("span");
    sev.className = "fsev";
    sev.textContent = "unconfirmed";
    head.append(cls, sev);
    card.appendChild(head);
    const meta = document.createElement("div");
    meta.className = "fmeta";
    addMetaRow(meta, "Endpoint", s.endpoint);
    addMetaRow(meta, "Location", s.location);
    addMetaRow(meta, "Source", s.source);
    addMetaRow(meta, "Why unconfirmed", s.reason);
    card.appendChild(meta);
    box.appendChild(card);
  });
}

function renderFindingsList(findings, suspected) {
  const box = $("findings-list");
  if ((!findings || !findings.length) && (!suspected || !suspected.length)) {
    box.innerHTML = '<div class="empty">No oracle-confirmed findings yet.</div>';
    return;
  }
  box.innerHTML = "";
  if (!findings || !findings.length) {
    const note = document.createElement("div");
    note.className = "empty";
    note.textContent = "No oracle-confirmed findings yet.";
    box.appendChild(note);
  }
  (findings || []).forEach((f) => {
    const card = document.createElement("div");
    card.className = "fcard " + (f.severity || "");
    const head = document.createElement("div");
    head.className = "fhead";
    const cls = document.createElement("span");
    cls.className = "fclass";
    cls.textContent = f.vuln_class || "finding";
    const sev = document.createElement("span");
    sev.className = "fsev";
    sev.textContent = f.severity || "unknown";
    head.append(cls, sev);
    card.appendChild(head);
    const meta = document.createElement("div");
    meta.className = "fmeta";
    addMetaRow(meta, "Oracle", f.oracle_used);
    addMetaRow(meta, "Evidence", f.evidence_ref);
    addMetaRow(meta, "Status", f.status);
    if (f.chain_precondition) addMetaRow(meta, "Chain", f.chain_precondition);
    card.appendChild(meta);
    (f.chains || []).forEach((ch) => {
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
      card.appendChild(row);
    });
    box.appendChild(card);
  });
  renderSuspectedInto(box, suspected);
}

function renderSurfaceTree(surface) {
  if (surface === null) return; // caller fetches asynchronously and re-invokes
  const box = $("surface-tree");
  const hosts = (surface && surface.hosts) || [];
  const orphan = (surface && surface.orphan_endpoints) || [];
  if (!hosts.length && !orphan.length) {
    box.innerHTML = '<div class="empty">No endpoints discovered yet.</div>';
    return;
  }
  box.innerHTML = "";
  const endpointEl = (ep) => {
    const d = document.createElement("details");
    d.className = "surface-endpoint";
    const s = document.createElement("summary");
    s.textContent = (ep.method || "GET") + " " + (ep.path || "");
    d.appendChild(s);
    const m = document.createElement("div");
    m.className = "node-meta";
    m.textContent = (ep.access_restricted ? "restricted " + ep.access_restricted + " · " : "") + (ep.technology || ep.content_type || "endpoint");
    d.appendChild(m);
    const ul = document.createElement("ul");
    (ep.parameters || []).forEach((p) => {
      const li = document.createElement("li");
      li.textContent = (p.location || "query") + " " + (p.name || "") + (p.inferred_sink_type ? " → " + p.inferred_sink_type : "");
      ul.appendChild(li);
    });
    if (ul.children.length) d.appendChild(ul);
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
  rows.forEach((r) => {
    const row = document.createElement("div");
    row.className = "audit-row";
    const ts = document.createElement("span");
    ts.className = "muted";
    ts.textContent = (r.timestamp || "").slice(11, 19);
    const id = document.createElement("span");
    id.className = "id";
    id.textContent = r.identity || "—";
    const m = document.createElement("span");
    m.className = "muted";
    m.textContent = r.method || "—";
    const tgt = document.createElement("span");
    tgt.className = "muted";
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
  ["md", "json", "sarif", "evidence", "bundle", "html"].forEach((fmt) => {
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

$("open-settings").onclick = () => {
  $("settings-overlay").hidden = false;
  loadProviders();
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
