// L4L0 live-scan console. No build step, no framework - plain DOM updates
// driven by the cursor-resumable WebSocket protocol served by app.py.
//
// Rendered as a single conversation thread (agent narration, findings,
// chains, and log output all appear as messages from "L4L0"; the
// operator's own messages are interleaved as their own turns) - not a
// dashboard of separate panels, and not a form sitting above one either.
// One composer box does double duty: before a scan is running, submitting
// it parses a target (URL/IP) out of the typed text and launches a scan
// with the whole message as the mission; once a scan is active, the same
// box sends read-only steering instead. Every dynamic value still reaches
// the DOM via textContent/template cloning, never innerHTML or string
// concatenation - a target- or agent-influenced string is never parsed as
// markup.
(() => {
  "use strict";

  const statusEl = document.getElementById("conn-status");
  const threadEl = document.getElementById("thread");
  const statAgentsEl = document.getElementById("stat-agents");
  const statFindingsEl = document.getElementById("stat-findings");
  const statChainsEl = document.getElementById("stat-chains");
  const statElapsedEl = document.getElementById("stat-elapsed");
  const jumpLatestBtn = document.getElementById("jump-latest");
  const composerForm = document.getElementById("composer-form");
  const composerInput = document.getElementById("composer-input");
  const composerSendBtn = composerForm.querySelector(".btn-send");
  const stopScanBtn = document.getElementById("stop-scan");
  const bulkImportTextarea = document.getElementById("bulk-import-textarea");
  const bulkImportAddBtn = document.getElementById("bulk-import-add-btn");

  const runHistoryListEl = document.getElementById("run-history-list");
  const refreshRunsBtn = document.getElementById("refresh-runs");
  const historyBanner = document.getElementById("history-banner");
  const historyBannerText = document.getElementById("history-banner-text");
  const historyBackToLiveBtn = document.getElementById("history-back-to-live");

  const openSettingsBtn = document.getElementById("open-settings");
  const closeSettingsBtn = document.getElementById("close-settings");
  const themeToggleBtn = document.getElementById("theme-toggle");
  const settingsDrawer = document.getElementById("settings-drawer");
  const providerListEl = document.getElementById("provider-list");
  const providerSelectEl = document.getElementById("provider-select");
  const providerForm = document.getElementById("provider-form");
  const providerKeyInput = document.getElementById("provider-key-input");
  const providerFormStatus = document.getElementById("provider-form-status");

  const tplMsgAgent = document.getElementById("tpl-msg-agent");
  const tplMsgUser = document.getElementById("tpl-msg-user");
  const tplAgentStatus = document.getElementById("tpl-agent-status");
  const tplFindingCard = document.getElementById("tpl-finding-card");
  const tplChainCard = document.getElementById("tpl-chain-card");
  const tplRunItem = document.getElementById("tpl-run-item");

  const SCAN_STATUS_EVENTS = new Set(["scan_started", "scan_completed", "scan_failed"]);
  const KNOWN_SEVERITIES = new Set(["critical", "high", "medium", "low", "info"]);

  const agents = new Map();
  const findingCards = new Map(); // finding_id -> the .finding-card element, for in-place updates
  const shellBlocks = new Map(); // command_id -> the .shell-block element
  const shellOutputListEl = document.getElementById("shell-output-list");
  let findingCount = 0;
  let chainCount = 0;
  let openLogBlock = null; // the currently-growing <pre>, or null if the last thread entry isn't a log run
  let lastCursor = null;
  let socket = null;
  let reconnectDelayMs = 500;
  let viewingRunId = null; // null = live; otherwise the run_id currently displayed
  // Non-null only when the WS socket itself is scoped to a NON-primary run's
  // live feed (a second concurrently-running scan opened from the rail) -
  // distinct from viewingRunId, which is also set for a completed run's
  // static replay (where the socket stays on the primary feed, unscoped).
  let liveWatchRunId = null;
  let pendingLiveCount = 0;

  function isNearBottom() {
    return threadEl.scrollHeight - threadEl.scrollTop - threadEl.clientHeight < 80;
  }

  // Shared by every append site: scroll along only if the operator was
  // already at the bottom (real chat UX never yanks a reader's scroll
  // position), otherwise surface the jump-to-latest pill instead of
  // silently growing the thread off-screen.
  function afterAppend(wasNear) {
    if (wasNear) {
      threadEl.scrollTop = threadEl.scrollHeight;
    } else {
      jumpLatestBtn.hidden = false;
    }
  }

  function scrollToBottomIfNear() {
    afterAppend(isNearBottom());
  }

  function setStatus(connected) {
    statusEl.textContent = connected ? "connected" : "reconnecting...";
    statusEl.className = connected ? "conn-pill connected" : "conn-pill disconnected";
  }

  // Every new "L4L0" turn (a status line, a finding, a chain) closes any
  // currently-open log block, so raw output and narration never interleave
  // inside the same growing element.
  function newAgentTurn() {
    const wasNear = isNearBottom();
    const node = tplMsgAgent.content.cloneNode(true);
    const msg = node.querySelector(".msg-agent");
    threadEl.appendChild(node);
    msg.classList.add("entering");
    openLogBlock = null;
    afterAppend(wasNear);
    return msg.querySelector(".msg-body");
  }

  // Curated one-liners for the known "log"/"status" event shapes emitted by
  // scan.py/loop.py - falls back to a raw JSON dump for anything not
  // recognized, since EventCategory's own payload shapes are an open set
  // (a future event kind must still render as *something*, not vanish).
  function formatLogPayload(payload) {
    switch (payload.event) {
      case "tool_call":
        return `→ ${payload.tool}(${JSON.stringify(payload.args ?? {})})`;
      case "tool_result":
        return `${payload.ok ? "✓" : "✗"} ${payload.tool}`;
      default:
        return payload.text || JSON.stringify(payload);
    }
  }

  function formatFailure(payload) {
    let text = `scan failed: ${payload.error || "unknown error"}`;
    if (payload.failures && payload.failures.length) {
      const segments = payload.failures.map((f) => `${f.provider}: ${f.reason}`).join("; ");
      text += ` (role=${payload.role || "?"}; tried: ${segments})`;
    }
    return text;
  }

  function formatStatusPayload(payload) {
    switch (payload.event) {
      case "resumed":
        return `resumed from step ${payload.replayed_steps}`;
      case "budget_exhausted":
        return `budget exhausted at step ${payload.step}`;
      case "provider_failed":
        return `provider failed at step ${payload.step}`;
      case "finished":
        return payload.reserved_turn
          ? `finished (reserved turn, step ${payload.step})`
          : `finished at step ${payload.step}`;
      case "repeating_tool_call_aborted":
        return `repeating tool call aborted: ${payload.tool}`;
      case "scan_started":
        return `scan started — targets: ${(payload.targets || []).join(", ") || "(none)"}`;
      case "scan_completed":
        return `scan completed — status: ${payload.status}`;
      case "scan_failed":
        return formatFailure(payload);
      default:
        return JSON.stringify(payload);
    }
  }

  function appendScrollback(text) {
    if (!openLogBlock) {
      const body = newAgentTurn();
      openLogBlock = document.createElement("pre");
      openLogBlock.className = "log-block";
      body.appendChild(openLogBlock);
    }
    const line = document.createElement("span");
    line.className = "line-fresh";
    line.textContent = text + "\n";
    openLogBlock.appendChild(line);
    openLogBlock.scrollTop = openLogBlock.scrollHeight;
    scrollToBottomIfNear();
  }

  function renderAgentLine(agent) {
    const body = newAgentTurn();
    const node = tplAgentStatus.content.cloneNode(true);
    node.querySelector(".agent-name").textContent = agent.name || agent.agent_id || "?";
    node.querySelector(".agent-status").textContent = agent.status || "unknown";
    const taskEl = node.querySelector(".agent-task");
    if (agent.task) {
      taskEl.textContent = agent.task;
    } else {
      taskEl.remove();
    }
    body.appendChild(node);
    statAgentsEl.textContent = String(agents.size);
  }

  function buildFindingCard(finding, findingId) {
    const node = tplFindingCard.content.cloneNode(true);
    const card = node.querySelector(".finding-card");
    card.dataset.findingId = findingId;
    const severityWord = String(finding.severity || "unknown").toLowerCase();
    const plateClass = KNOWN_SEVERITIES.has(severityWord) ? severityWord : "unknown";
    const pill = card.querySelector(".severity-pill");
    pill.className = `severity-pill sev-${plateClass}`;
    // Severity is never color alone: the pill's own text is the primary
    // signal, the color is reinforcement.
    pill.textContent = severityWord.toUpperCase().slice(0, 4);
    card.querySelector(".finding-confidence").textContent = `${finding.confidence ?? "?"}/100`;
    card.querySelector(".finding-title").textContent = finding.title || finding.finding_id || "";
    return card;
  }

  function renderFinding(findingId, finding) {
    const existing = findingCards.get(findingId);
    if (existing) {
      // An update to an already-shown finding (e.g. a revised confidence
      // score) replaces that finding's own card in place - it does not
      // reopen the conversation as a second, duplicate finding turn.
      const replacement = buildFindingCard(finding, findingId);
      existing.replaceWith(replacement);
      findingCards.set(findingId, replacement);
      return;
    }
    const body = newAgentTurn();
    const card = buildFindingCard(finding, findingId);
    body.appendChild(card);
    card.classList.add("entering");
    findingCards.set(findingId, card);
    findingCount += 1;
    statFindingsEl.textContent = String(findingCount);
  }

  function renderChain(chain) {
    const body = newAgentTurn();
    const node = tplChainCard.content.cloneNode(true);
    const card = node.querySelector(".chain-card");
    const nodeIds = chain.node_ids || [];
    nodeIds.forEach((nodeId, index) => {
      if (index > 0) {
        const link = document.createElement("span");
        link.className = "chain-link";
        link.textContent = "→";
        card.appendChild(link);
      }
      card.appendChild(document.createTextNode(nodeId));
    });
    body.appendChild(card);
    card.classList.add("entering");
    chainCount += 1;
    statChainsEl.textContent = String(chainCount);
  }

  // Live shell panel: one growing .shell-block per command_id, independent
  // of the conversation thread - a command's start/chunk/end events arrive
  // as their own "shell" category rather than interleaving into the
  // narration log, so run_command output gets a dedicated always-visible
  // readout instead of competing with agent turns for thread space.
  function applyShellEvent(payload) {
    const commandId = payload.command_id;
    if (payload.event === "start") {
      const block = document.createElement("pre");
      block.className = "shell-block";
      const header = document.createElement("div");
      header.className = "shell-block-header";
      header.textContent = `$ ${payload.command}`;
      const body = document.createElement("div");
      body.className = "shell-block-body";
      block.appendChild(header);
      block.appendChild(body);
      shellOutputListEl.appendChild(block);
      block.classList.add("entering");
      shellBlocks.set(commandId, block);
      block.scrollIntoView({ block: "end" });
    } else if (payload.event === "chunk") {
      const block = shellBlocks.get(commandId);
      if (!block) return;
      const line = document.createElement("span");
      line.className = payload.stream === "stderr" ? "shell-line-stderr" : "shell-line-stdout";
      line.textContent = payload.text;
      block.querySelector(".shell-block-body").appendChild(line);
      shellOutputListEl.scrollTop = shellOutputListEl.scrollHeight;
    } else if (payload.event === "end") {
      const block = shellBlocks.get(commandId);
      if (!block) return;
      const badge = document.createElement("span");
      badge.className = payload.exit_code === 0 ? "shell-exit-ok" : "shell-exit-fail";
      badge.textContent =
        payload.exit_code === null || payload.exit_code === undefined
          ? "exit —"
          : `exit ${payload.exit_code}`;
      block.querySelector(".shell-block-header").appendChild(badge);
    }
  }

  // Preference order, not alphabetical: pdf (best presentation) first, then
  // the always-present canonical markdown, then whatever else exists - a
  // narrow rail item links to exactly one format rather than cluttering
  // itself with one link per available export.
  const REPORT_LINK_PREFERENCE = ["pdf", "md", "json", "sarif", "docx"];

  function preferredReportFormat(formats) {
    return REPORT_LINK_PREFERENCE.find((fmt) => formats.includes(fmt)) || null;
  }

  function formatRunTimestamp(epochSeconds) {
    if (!epochSeconds) return "";
    return new Date(epochSeconds * 1000).toLocaleString(undefined, {
      month: "short",
      day: "numeric",
      hour: "numeric",
      minute: "2-digit",
    });
  }

  function buildRunItem(run) {
    const node = tplRunItem.content.cloneNode(true);
    const item = node.querySelector(".run-item");
    if (run.running) item.classList.add("running");
    item.querySelector(".run-mission").textContent = run.mission || "(no mission recorded)";
    const parts = [run.running ? "running" : "completed", formatRunTimestamp(run.modified_at)];
    item.querySelector(".run-meta").textContent = parts.filter(Boolean).join(" · ");
    item.dataset.runId = run.run_id;
    item.dataset.missionText = run.mission || "(no mission recorded)";
    item.dataset.running = run.running ? "true" : "false";
    const link = item.querySelector(".run-report-link");
    const fmt = preferredReportFormat(run.report_formats || []);
    if (fmt) {
      link.href = `/runs/${encodeURIComponent(run.run_id)}/report/${fmt}`;
      link.hidden = false;
    }
    // Separate from the "best report" link above - not another format in
    // that rotation, but a categorically different artifact (a plaintext,
    // per-agent-attributed operational transcript, not a polished report).
    const narrativeLink = item.querySelector(".run-narrative-link");
    if ((run.report_formats || []).includes("narrative")) {
      narrativeLink.href = `/runs/${encodeURIComponent(run.run_id)}/report/narrative`;
      narrativeLink.hidden = false;
    }
    if (!run.running) {
      const resumeBtn = item.querySelector(".run-resume-btn");
      resumeBtn.hidden = false;
      resumeBtn.dataset.runId = run.run_id;
      // Never hidden or disabled for a run with a valid report - resuming
      // one is a cheap, harmless no-op (the backend adopts the existing
      // report instead of redoing anything), and CLAUDE.md's own maximum-
      // agent-freedom stance rules out ever blocking the action outright.
      // This is purely informational: it stops the button from silently
      // implying more work remains when none does.
      if (run.report_valid) {
        resumeBtn.textContent = "Resume (already finished)";
        resumeBtn.title = "This run already has a verified final report - resuming will not redo it.";
      } else {
        resumeBtn.textContent = "Resume";
        resumeBtn.title = "";
      }
    }
    return item;
  }

  function renderRunHistory(runs) {
    runHistoryListEl.replaceChildren();
    if (!runs.length) {
      const empty = document.createElement("li");
      empty.className = "run-history-empty";
      empty.textContent = "No runs yet.";
      runHistoryListEl.appendChild(empty);
      return;
    }
    for (const run of runs) {
      runHistoryListEl.appendChild(buildRunItem(run));
    }
  }

  async function loadRunHistory() {
    try {
      const response = await fetch("/runs");
      if (!response.ok) return; // best-effort - must never block the live console
      const body = await response.json();
      renderRunHistory(body.runs || []);
    } catch {
      // network hiccup fetching history - the live scan itself is unaffected
    }
  }

  function _resetThreadForNewView() {
    threadEl.replaceChildren();
    agents.clear();
    findingCards.clear();
    shellOutputListEl.replaceChildren();
    shellBlocks.clear();
    findingCount = 0;
    chainCount = 0;
    statFindingsEl.textContent = "0";
    statChainsEl.textContent = "0";
    statAgentsEl.textContent = "0";
    openLogBlock = null;
  }

  async function openRun(runId, missionText, isRunning) {
    _resetThreadForNewView();
    viewingRunId = runId;
    pendingLiveCount = 0;
    historyBannerText.textContent = isRunning
      ? `Watching live: ${missionText || runId}`
      : `Viewing: ${missionText || runId}`;
    historyBanner.hidden = false;
    composerInput.placeholder = isRunning ? "Message this run…" : "Continue this run…";

    if (isRunning) {
      // Reconnect the socket scoped to this specific run's own live feed -
      // its own "send a full snapshot on connect" behavior replays history
      // AND keeps receiving further live updates, for a genuinely
      // concurrently-running scan the operator wasn't already watching.
      liveWatchRunId = runId;
      lastCursor = null;
      socket.close();
      return;
    }
    try {
      const response = await fetch(`/runs/${encodeURIComponent(runId)}/events`);
      if (!response.ok) return;
      const body = await response.json();
      for (const event of body.events || []) {
        applyEvent(event);
      }
    } catch {
      // best-effort - the completed-run static replay is unaffected by a
      // failed history fetch; the thread was already reset above
    }
  }

  function returnToLive() {
    viewingRunId = null;
    liveWatchRunId = null;
    pendingLiveCount = 0;
    historyBanner.hidden = true;
    composerInput.placeholder = scanActive ? "Message this run…" : "Tell me what to test…";
    _resetThreadForNewView();
    lastCursor = null;
    socket.close(); // reconnects to the primary (no run_id) feed
  }

  historyBackToLiveBtn.addEventListener("click", returnToLive);

  // ---------- settings drawer (providers) ----------

  async function loadProviderSettings() {
    try {
      const response = await fetch("/settings/providers");
      if (!response.ok) return;
      const body = await response.json();
      providerListEl.replaceChildren();
      providerSelectEl.replaceChildren();
      for (const p of body.providers) {
        const li = document.createElement("li");
        li.textContent = `${p.id} — ${p.configured ? "configured" : "not configured"}`;
        providerListEl.appendChild(li);
        const opt = document.createElement("option");
        opt.value = p.id;
        opt.textContent = p.id;
        providerSelectEl.appendChild(opt);
      }
    } catch {
      // best-effort - settings drawer content, never blocks the live console
    }
  }

  openSettingsBtn.addEventListener("click", () => {
    settingsDrawer.hidden = false;
    loadProviderSettings();
  });
  closeSettingsBtn.addEventListener("click", () => {
    settingsDrawer.hidden = true;
  });

  // ---------- theme toggle ----------

  function applyStoredTheme() {
    let stored = null;
    try {
      stored = localStorage.getItem("lalo-theme");
    } catch {
      // localStorage unavailable (private mode, blocked) - default theme stands
    }
    if (stored === "light" || stored === "dark") {
      document.documentElement.setAttribute("data-theme", stored);
    }
  }

  themeToggleBtn.addEventListener("click", () => {
    const current = document.documentElement.getAttribute("data-theme") === "light" ? "light" : "dark";
    const next = current === "light" ? "dark" : "light";
    document.documentElement.setAttribute("data-theme", next);
    try {
      localStorage.setItem("lalo-theme", next);
    } catch {
      // best-effort persistence only - the toggle still works for this page view
    }
  });

  applyStoredTheme();

  providerForm.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const providerId = providerSelectEl.value;
    const apiKey = providerKeyInput.value.trim();
    if (!apiKey) return;
    providerFormStatus.textContent = "Verifying…";
    try {
      const response = await fetch("/settings/providers", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ provider_id: providerId, api_key: apiKey, extra: {} }),
      });
      const body = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(body.error || `request failed (${response.status})`);
      providerFormStatus.textContent = `${providerId} verified and saved.`;
      providerKeyInput.value = "";
      loadProviderSettings();
    } catch (err) {
      providerFormStatus.textContent = `Failed: ${err.message}`;
    }
  });

  function appendUserMessage(text, { error = false } = {}) {
    const wasNear = isNearBottom();
    const node = tplMsgUser.content.cloneNode(true);
    const msg = node.querySelector(".msg-user");
    if (error) msg.classList.add("msg-error");
    msg.querySelector(".bubble").textContent = text;
    threadEl.appendChild(node);
    msg.classList.add("entering");
    openLogBlock = null;
    afterAppend(wasNear);
  }

  function appendAgentText(text) {
    const body = newAgentTurn();
    const p = document.createElement("p");
    p.className = "agent-line";
    p.textContent = text;
    body.appendChild(p);
  }

  function formatElapsed(ms) {
    const totalSeconds = Math.max(0, Math.floor(ms / 1000));
    const m = Math.floor(totalSeconds / 60);
    const s = totalSeconds % 60;
    return `${String(m).padStart(2, "0")}:${String(s).padStart(2, "0")}`;
  }

  let elapsedTimer = null;

  function startElapsedClock() {
    // ponytail: restarts from 00:00 on every reconnect rather than showing
    // the scan's true elapsed time, since the status event carries no
    // server-side timestamp yet - add one to Event if a reconnect mid-scan
    // showing the real elapsed time ever matters.
    const startMs = Date.now();
    statElapsedEl.textContent = "00:00";
    clearInterval(elapsedTimer);
    elapsedTimer = setInterval(() => {
      statElapsedEl.textContent = formatElapsed(Date.now() - startMs);
    }, 1000);
  }

  function stopElapsedClock() {
    clearInterval(elapsedTimer);
    elapsedTimer = null;
  }

  let scanActive = false;

  function onScanStarted() {
    scanActive = true;
    stopScanBtn.hidden = false;
    composerInput.placeholder = "Message this run…";
    startElapsedClock();
    loadRunHistory();
  }

  function onScanEnded(payload) {
    scanActive = false;
    stopScanBtn.hidden = true;
    composerInput.placeholder = "Tell me what to test…";
    stopElapsedClock();
    loadRunHistory();
    if (payload && payload.event === "scan_failed") {
      appendAgentText(formatFailure(payload));
      return;
    }
    let text = "Scan finished — send another target and objective anytime.";
    if (payload && payload.usage_delta) {
      const u = payload.usage_delta;
      const reqWord = u.requests === 1 ? "request" : "requests";
      text += ` Tokens this run: ${u.input_tokens} in / ${u.output_tokens} out (${u.requests} ${reqWord}).`;
    }
    if (payload && payload.report_paths) {
      const paths = Object.entries(payload.report_paths)
        .map(([fmt, p]) => `${fmt}: ${p}`)
        .join(", ");
      text += ` Report: ${paths}`;
    }
    appendAgentText(text);
  }

  function applyEvent(event) {
    switch (event.category) {
      case "status":
        appendScrollback(`[status] ${formatStatusPayload(event.payload)}`);
        if (SCAN_STATUS_EVENTS.has(event.payload.event)) {
          if (event.payload.event === "scan_started") {
            if (!scanActive) onScanStarted();
          } else if (scanActive) {
            onScanEnded(event.payload);
          }
        }
        break;
      case "log":
        appendScrollback(formatLogPayload(event.payload));
        break;
      case "agent":
        {
          // Key by the domain id in the payload, not the event's own id: a
          // caller may reasonably append() a fresh event for every status
          // change of the SAME agent rather than tracking and update()-ing
          // the original event id - each such change becomes its own
          // narration line in the thread, using the fully merged agent state.
          const key = event.payload.agent_id || event.id;
          const merged = { ...agents.get(key), ...event.payload };
          agents.set(key, merged);
          renderAgentLine(merged);
        }
        break;
      case "finding":
        {
          const key = event.payload.finding_id || event.id;
          renderFinding(key, event.payload);
        }
        break;
      case "steering":
        appendUserMessage(event.payload.text || "");
        break;
      case "chain":
        renderChain(event.payload);
        break;
      case "shell":
        applyShellEvent(event.payload);
        break;
      default:
      // EventCategory (events.py) is a closed set - an unrecognized
      // category here means a client/server version mismatch, not a
      // condition to silently render something for.
    }
  }

  function connect() {
    const url = new URL("/ws", window.location.href);
    url.protocol = url.protocol === "https:" ? "wss:" : "ws:";
    if (liveWatchRunId !== null) {
      url.searchParams.set("run_id", liveWatchRunId);
    }
    if (lastCursor !== null) {
      url.searchParams.set("cursor", String(lastCursor));
    }
    socket = new WebSocket(url.toString());

    socket.addEventListener("open", () => {
      setStatus(true);
      reconnectDelayMs = 500;
    });

    socket.addEventListener("message", (ev) => {
      const data = JSON.parse(ev.data);
      lastCursor = data.cursor;
      const events = data.events || [];
      // Suppress only when looking at something OTHER than what this socket
      // is actually streaming right now (a completed run's static replay,
      // where the socket stays on the primary/default feed unscoped).
      if (viewingRunId !== null && viewingRunId !== liveWatchRunId) {
        pendingLiveCount += events.length;
        if (pendingLiveCount > 0) {
          historyBannerText.textContent = `${pendingLiveCount} new live event(s) — `;
        }
        return;
      }
      for (const event of events) {
        applyEvent(event);
      }
    });

    socket.addEventListener("close", (ev) => {
      if (ev.code === 4400) {
        // The cursor this client remembered is stale/out of range (e.g. the
        // server's event log was reset) - repeating the same cursor will
        // only fail the same way forever. Fall back to a fresh full
        // snapshot on the next attempt instead.
        lastCursor = null;
      }
      setStatus(false);
      setTimeout(connect, reconnectDelayMs);
      reconnectDelayMs = Math.min(reconnectDelayMs * 2, 10_000);
    });

    socket.addEventListener("error", () => socket.close());
  }

  async function launchFromPrompt(text) {
    composerSendBtn.disabled = true;
    composerInput.disabled = true;
    try {
      const maxSteps = document.getElementById("opt-max-steps").value;
      const spawnMaxDepth = document.getElementById("opt-spawn-max-depth").value;
      const budgetCeiling = document.getElementById("opt-budget-ceiling").value;
      const costLimit = document.getElementById("opt-cost-limit").value;
      const maxDuration = document.getElementById("opt-max-duration").value;
      const egressLock = document.getElementById("opt-egress-lock").checked;
      const redactFindings = document.getElementById("opt-redact-findings").checked;
      const failOnUnreachable = document.getElementById("opt-fail-on-unreachable").checked;
      const secondOpinion = document.getElementById("opt-second-opinion").checked;
      const response = await fetch("/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          mission: text,
          ...(maxSteps ? { max_steps: Number(maxSteps) } : {}),
          ...(spawnMaxDepth ? { spawn_max_depth: Number(spawnMaxDepth) } : {}),
          ...(budgetCeiling ? { budget_ceiling: Number(budgetCeiling) } : {}),
          ...(costLimit ? { cost_limit_usd: Number(costLimit) } : {}),
          ...(maxDuration ? { max_duration_s: Number(maxDuration) } : {}),
          egress_lock: egressLock,
          redact_findings: redactFindings,
          fail_on_unreachable_targets: failOnUnreachable,
          enable_second_opinion_review: secondOpinion,
        }),
      });
      const body = await response.json().catch(() => ({}));
      if (!response.ok) {
        throw new Error(body.error || `request failed (${response.status})`);
      }
      // A fresh launch always becomes the thread's new focus, live - the
      // very first scan of the process happens to be the backend's
      // "primary" (see gui/app.py's own primary_run_id), but every launch
      // after that must be explicitly watched or its progress would only
      // ever surface by clicking into Past Runs.
      _resetThreadForNewView();
      liveWatchRunId = body.run_id;
      lastCursor = null;
      appendUserMessage(text);
      const parts = [`Understood — target(s): ${body.resolved_targets.join(", ")}`];
      if (body.resolved_exclude_targets && body.resolved_exclude_targets.length) {
        parts.push(`excluding: ${body.resolved_exclude_targets.join(", ")}`);
      }
      if (body.resolved_rules_of_engagement) {
        parts.push(`rules of engagement: ${body.resolved_rules_of_engagement}`);
      }
      appendAgentText(parts.join(" · "));
      composerInput.value = "";
      socket.close(); // reconnects scoped to body.run_id
      onScanStarted();
    } catch (err) {
      appendUserMessage(`[scan not started: ${err.message}] ${text}`, { error: true });
    } finally {
      composerSendBtn.disabled = false;
      composerInput.disabled = false;
      composerInput.focus();
    }
  }

  async function launchResume(runId) {
    const response = await fetch("/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ resume_run_id: runId }),
    });
    const body = await response.json().catch(() => ({}));
    if (!response.ok) {
      throw new Error(body.error || `request failed (${response.status})`);
    }
  }

  async function resumeRun(runId, button) {
    button.disabled = true;
    try {
      await launchResume(runId);
      appendAgentText(`Resuming run ${runId}…`);
      onScanStarted();
    } catch (err) {
      appendAgentText(`[resume failed: ${err.message}]`);
      button.disabled = false;
    }
  }

  async function continueViewedRun(text) {
    const runId = viewingRunId;
    composerSendBtn.disabled = true;
    composerInput.disabled = true;
    try {
      if (!scanActive) {
        await launchResume(runId);
      }
      viewingRunId = null;
      historyBanner.hidden = true;
      onScanStarted();
      await sendSteering(text);
    } catch (err) {
      appendAgentText(`[continue failed: ${err.message}]`);
    } finally {
      composerSendBtn.disabled = false;
      composerInput.disabled = false;
      composerInput.focus();
    }
  }

  async function sendSteering(text) {
    composerSendBtn.disabled = true;
    composerInput.disabled = true;
    try {
      const url = liveWatchRunId !== null
        ? `/steer?run_id=${encodeURIComponent(liveWatchRunId)}`
        : "/steer";
      const response = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ text }),
      });
      if (!response.ok) {
        const body = await response.json().catch(() => ({}));
        throw new Error(body.error || `request failed (${response.status})`);
      }
      // only cleared on confirmed delivery - the operator can otherwise
      // still see and retry what they typed
      composerInput.value = "";
    } catch (err) {
      appendUserMessage(`[not delivered: ${err.message}] ${text}`, { error: true });
    } finally {
      composerSendBtn.disabled = false;
      composerInput.disabled = false;
      composerInput.focus();
    }
  }

  composerForm.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const text = composerInput.value.trim();
    if (!text) return;
    if (viewingRunId !== null) {
      composerInput.value = "";
      await continueViewedRun(text);
    } else if (scanActive) {
      await sendSteering(text);
    } else {
      await launchFromPrompt(text);
    }
  });

  stopScanBtn.addEventListener("click", async () => {
    stopScanBtn.disabled = true;
    try {
      const url = liveWatchRunId !== null
        ? `/scan/stop?run_id=${encodeURIComponent(liveWatchRunId)}`
        : "/scan/stop";
      const response = await fetch(url, {
        method: "POST",
      });
      const body = await response.json().catch(() => ({}));
      if (!response.ok) {
        throw new Error(body.error || `request failed (${response.status})`);
      }
      appendUserMessage("Stop requested.");
    } catch (err) {
      appendUserMessage(`[stop failed: ${err.message}]`, { error: true });
    } finally {
      stopScanBtn.disabled = false;
    }
  });

  jumpLatestBtn.addEventListener("click", () => {
    threadEl.scrollTop = threadEl.scrollHeight;
    jumpLatestBtn.hidden = true;
  });

  threadEl.addEventListener("scroll", () => {
    if (isNearBottom()) jumpLatestBtn.hidden = true;
  });

  threadEl.addEventListener("click", async (ev) => {
    const btn = ev.target.closest(".finding-copy");
    if (!btn) return;
    const card = btn.closest(".finding-card");
    const parts = [".severity-pill", ".finding-confidence", ".finding-title"]
      .map((sel) => card.querySelector(sel)?.textContent.trim())
      .filter(Boolean);
    try {
      await navigator.clipboard.writeText(parts.join(" · "));
      btn.classList.add("copied");
      setTimeout(() => btn.classList.remove("copied"), 1200);
    } catch {
      // clipboard permission denied/unavailable - the finding text is still
      // visible and selectable manually, nothing else to do here
    }
  });

  refreshRunsBtn.addEventListener("click", () => loadRunHistory());

  runHistoryListEl.addEventListener("click", (ev) => {
    const btn = ev.target.closest(".run-resume-btn");
    if (!btn) return;
    resumeRun(btn.dataset.runId, btn);
  });

  runHistoryListEl.addEventListener("click", (ev) => {
    if (
      ev.target.closest(".run-resume-btn") ||
      ev.target.closest(".run-report-link") ||
      ev.target.closest(".run-narrative-link") ||
      ev.target.closest(".run-duplicate-btn")
    ) {
      return;
    }
    const item = ev.target.closest(".run-item");
    if (!item) return;
    document.querySelectorAll(".run-item.viewing").forEach((el) => el.classList.remove("viewing"));
    item.classList.add("viewing");
    openRun(item.dataset.runId, item.dataset.missionText, item.dataset.running === "true");
  });

  // Duplicate: pre-fill the composer with a past run's original mission text
  // (untruncated - buildRunItem stashes the full string in dataset.missionText)
  // and stop there. It never auto-launches - the operator edits/resubmits
  // through the exact same launchFromPrompt path every fresh scan already
  // uses, so this needs zero backend changes.
  runHistoryListEl.addEventListener("click", (ev) => {
    const btn = ev.target.closest(".run-duplicate-btn");
    if (!btn) return;
    const item = btn.closest(".run-item");
    composerInput.value = item.dataset.missionText || "";
    composerInput.focus();
  });

  // Bulk target import: pasted lines just become more text in the same
  // composer box a normal scan launch already understands via the
  // backend's LLM intake parse, so no backend/endpoint change is needed
  // here either.
  bulkImportAddBtn.addEventListener("click", () => {
    const lines = bulkImportTextarea.value
      .split("\n")
      .map((l) => l.trim())
      .filter(Boolean);
    if (!lines.length) return;
    composerInput.value = [composerInput.value.trim(), ...lines].filter(Boolean).join(" ");
    bulkImportTextarea.value = "";
    composerInput.focus();
  });

  connect();
  loadRunHistory();
})();
