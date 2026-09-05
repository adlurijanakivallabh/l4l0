// L4L0 live-scan console. No build step, no framework - plain DOM updates
// driven by the cursor-resumable WebSocket protocol served by app.py.
(() => {
  "use strict";

  const token = new URLSearchParams(window.location.search).get("token") || "";
  const statusEl = document.getElementById("conn-status");
  const agentListEl = document.getElementById("agent-list");
  const findingListEl = document.getElementById("finding-list");
  const chainListEl = document.getElementById("chain-list");
  const scrollbackEl = document.getElementById("scrollback");
  const steerLogEl = document.getElementById("steer-log");
  const steerForm = document.getElementById("steer-form");
  const steerInput = document.getElementById("steer-input");

  const agents = new Map();
  const findings = new Map();
  const chains = new Map();
  let lastCursor = null;
  let socket = null;
  let reconnectDelayMs = 500;

  function setStatus(connected) {
    statusEl.textContent = connected ? "connected" : "reconnecting...";
    statusEl.className = connected ? "connected" : "disconnected";
  }

  function appendScrollback(text) {
    scrollbackEl.textContent += text + "\n";
    scrollbackEl.scrollTop = scrollbackEl.scrollHeight;
  }

  function renderAgents() {
    agentListEl.replaceChildren();
    for (const agent of agents.values()) {
      const li = document.createElement("li");
      li.textContent = `[${agent.status || "unknown"}] ${agent.name || agent.agent_id} - ${agent.task || ""}`;
      agentListEl.appendChild(li);
    }
  }

  function renderFindings() {
    const sorted = [...findings.values()].sort(
      (a, b) => (b.confidence || 0) - (a.confidence || 0)
    );
    findingListEl.replaceChildren();
    for (const finding of sorted) {
      const li = document.createElement("li");
      li.textContent = `[${finding.severity || "?"}] (${finding.confidence ?? "?"}/100) ${finding.title || finding.finding_id}`;
      findingListEl.appendChild(li);
    }
  }

  function renderChains() {
    chainListEl.replaceChildren();
    for (const chain of chains.values()) {
      const li = document.createElement("li");
      li.textContent = (chain.node_ids || []).join(" -> ");
      chainListEl.appendChild(li);
    }
  }

  function applyEvent(event) {
    switch (event.category) {
      case "status":
        appendScrollback(`[status] ${JSON.stringify(event.payload)}`);
        break;
      case "log":
        appendScrollback(event.payload.text || JSON.stringify(event.payload));
        break;
      case "agent":
        {
          // Key by the domain id in the payload, not the event's own id: a
          // caller may reasonably append() a fresh event for every status
          // change of the SAME agent rather than tracking and update()-ing
          // the original event id - the dashboard must still consolidate
          // those into one row per agent, not one row per event.
          const key = event.payload.agent_id || event.id;
          agents.set(key, { ...agents.get(key), ...event.payload });
          renderAgents();
        }
        break;
      case "finding":
        {
          const key = event.payload.finding_id || event.id;
          findings.set(key, { ...findings.get(key), ...event.payload });
          renderFindings();
        }
        break;
      case "steering":
        {
          const div = document.createElement("div");
          div.textContent = event.payload.text || "";
          steerLogEl.appendChild(div);
        }
        break;
      default:
        if (event.payload && event.payload.node_ids) {
          chains.set(event.id, event.payload);
          renderChains();
        }
    }
  }

  function connect() {
    const url = new URL("/ws", window.location.href);
    url.protocol = url.protocol === "https:" ? "wss:" : "ws:";
    url.searchParams.set("token", token);
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
      for (const event of data.events || []) {
        applyEvent(event);
      }
    });

    socket.addEventListener("close", () => {
      setStatus(false);
      setTimeout(connect, reconnectDelayMs);
      reconnectDelayMs = Math.min(reconnectDelayMs * 2, 10_000);
    });

    socket.addEventListener("error", () => socket.close());
  }

  steerForm.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const text = steerInput.value.trim();
    if (!text) return;
    steerInput.value = "";
    await fetch(`/steer?token=${encodeURIComponent(token)}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ text }),
    });
  });

  connect();
})();
