/* ReachAgent console — vanilla JS, no build step. */
const $ = (id) => document.getElementById(id);
let scanId = null, timer = null;

const PHASE_LABEL = {
  plan: "00 · PLAN", recon: "01 · RECON", endpoints: "02 · ENDPOINTS",
  "insertion-points": "02 · INSERTION", surface: "02 · SURFACE",
  payloads: "03 · PAYLOADS", verification: "04 · VERIFY",
  chains: "05 · CHAINS", report: "06 · REPORT", tools: "TOOLS",
};

function setView(hash) {
  document.querySelectorAll(".views").forEach((v) => (v.style.display = "none"));
  const el = document.querySelector(hash);
  if (el) el.style.display = "block";
  document.querySelectorAll(".nav a").forEach((a) =>
    a.classList.toggle("on", a.getAttribute("href") === hash)
  );
}
document.querySelectorAll(".nav a").forEach((a) =>
  a.addEventListener("click", () => setView(a.getAttribute("href")))
);

function mdToHtml(md) {
  const esc = (s) => String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  const inline = (t) => esc(t)
    .replace(/\*\*(.+?)\*\*/g, "<b>$1</b>")
    .replace(/`([^`]+)`/g, "<code>$1</code>");
  const lines = String(md || "").split("\n");
  let out = [], inCode = false, buf = [], listOpen = false;
  const closeList = () => { if (listOpen) { out.push("</ul>"); listOpen = false; } };
  const flushCode = () => { if (inCode) { out.push("<pre><code>" + esc(buf.join("\n")) + "</code></pre>"); buf = []; inCode = false; } };
  for (const line of lines) {
    if (line.trim().startsWith("```")) { flushCode(); inCode = !inCode ? true : inCode; if (!inCode) continue; continue; }
    if (inCode) { buf.push(line); continue; }
    const t = line.trim();
    if (/^- /.test(t)) { if (!listOpen) { out.push("<ul>"); listOpen = true; } out.push("<li>" + inline(t.slice(2)) + "</li>"); continue; }
    closeList();
    if (/^#{1,4} /.test(t)) { const lvl = t.indexOf(" "); out.push("<h" + lvl + ">" + inline(t.replace(/^#+\s*/, "")) + "</h" + lvl + ">"); }
    else if (t === "---") out.push("<hr>");
    else if (t) out.push("<p>" + inline(t) + "</p>");
  }
  flushCode(); closeList();
  return out.join("\n");
}

function renderReasoning(events) {
  const box = $("reasoning");
  const rows = events.filter(
    (e) => e.kind === "plan" || e.kind === "step" || /LLM|decision/i.test(e.message || "")
  );
  if (!rows.length) { box.innerHTML = '<p class="empty">Start an assessment to see the reasoning loop.</p>'; return; }
  box.innerHTML = rows.map((e) => {
    const cls = e.kind === "plan" ? "plan" : /decision/i.test(e.message || "") ? "decision" : "";
    const d = e.details || {};
    const hint = d.hint || d.selected || d.ranked_ids
      ? Object.entries({ hint: d.hint, selected: d.selected, ranked: d.ranked_ids })
          .filter(([, v]) => v != null && v !== "").map(([k, v]) => k + ": " + JSON.stringify(v)).join(" · ")
      : "";
    return `<div class="r-row ${cls}"><span class="r-ph">${PHASE_LABEL[e.phase] || e.phase}</span><span class="r-dot"></span><span><div class="r-msg">${(e.message || "").replace(/</g, "&lt;")}</div>${hint ? `<div class="r-hint">${hint.replace(/</g, "&lt;")}</div>` : ""}</span></div>`;
  }).join("");
  box.scrollTop = box.scrollHeight;
}

function renderTools(events) {
  const rows = events.filter((e) => e.phase === "tools");
  const box = $("tools");
  if (!rows.length) { box.innerHTML = '<p class="empty">No tools dispatched.</p>'; return; }
  const cls = { ingested: "ok", errored: "bad", refused_out_of_scope: "warn", no_fixture: "" };
  box.innerHTML = rows.map((e) => {
    const d = e.details || {};
    const outcome = d.outcome || e.kind;
    return `<div class="t-row"><span class="t-name">${d.tool || "?"}</span><span style="color:var(--mut)">${d.detail || ""} ${d.nodes ? "· " + d.nodes + " nodes" : ""}</span><span class="t-out ${cls[outcome] || ""}">${String(outcome).replace(/_/g, " ")}</span></div>`;
  }).join("");
  box.scrollTop = box.scrollHeight;
}

function renderTimeline(events) {
  const box = $("timeline");
  if (!events.length) { box.innerHTML = '<p class="empty">—</p>'; return; }
  const skipMark = (m) => /skip/i.test(m);
  box.innerHTML = events.map((e) => {
    const cls = e.kind === "finding" ? "finding" : e.kind === "error" ? "error" : skipMark(e.message) ? "skipped" : "";
    return `<div class="tl ${cls}"><span class="ph">${PHASE_LABEL[e.phase] || e.phase}</span><span class="dot2"></span><span class="m">${(e.message || "").replace(/</g, "&lt;")}</span></div>`;
  }).join("");
  box.scrollTop = box.scrollHeight;
}

function renderCounts(g) {
  const c = (g && g.counts) || {};
  $("c-hosts").textContent = c.hosts ?? 0;
  $("c-eps").textContent = c.endpoints ?? 0;
  $("c-par").textContent = c.parameters ?? 0;
  $("c-fin").textContent = c.findings ?? 0;
}

function renderSurface(surface) {
  const hosts = (surface && surface.hosts) || [];
  const orphan = (surface && surface.orphan_endpoints) || [];
  const box = $("surface");
  if (!hosts.length && !orphan.length) { box.innerHTML = '<p class="empty">No surface mapped yet.</p>'; return; }
  const epHtml = (ep) =>
    `<div class="ep"><span class="mth">${ep.method || "GET"}</span> ${ep.path}${ep.access_restricted ? ` <span class="res">restricted ${ep.access_restricted}</span>` : ""}${(ep.parameters || []).length ? " · " + ep.parameters.map((p) => p.name + "(" + p.location + ")" + (p.inferred_sink_type ? ` <span class="sink">→${p.inferred_sink_type}</span>` : "")).join(", ") : ""}</div>`;
  box.innerHTML =
    hosts.map((h) => {
      const svcs = (h.services || []).map((s) => `<div class="sv">${s.port}/${s.protocol} ${s.service_name || ""} ${s.banner || ""}</div>`).join("");
      const eps = (h.endpoints || []).map(epHtml).join("");
      return `<details class="surf" open><summary>${h.address || h.hostname} <span class="h-tech">${h.technology || h.source || ""}</span></summary>${svcs}${eps}</details>`;
    }).join("") + orphan.map(epHtml).join("");
}

function renderAudit(rows) {
  const box = $("audit");
  if (!rows || !rows.length) { box.innerHTML = '<span class="empty">—</span>'; return; }
  const cls = (o) => (o.startsWith("fired") ? "o-fired" : o.startsWith("refused") ? "o-refused" : o.startsWith("errored") ? "o-errored" : o.startsWith("ingested") ? "o-ingested" : "");
  box.innerHTML = rows.map((r) =>
    `<div class="arow"><span>${(r.timestamp || "").slice(11, 19)}</span><span class="id">${r.identity || "—"}</span><span>${r.method || "—"}</span><span>${(r.target || "—").slice(0, 60)}</span><span class="${cls(r.outcome)}">${r.outcome.split(":")[0]}</span></div>`
  ).join("");
  box.scrollTop = box.scrollHeight;
}

function renderFindings(findings) {
  const box = $("findings");
  if (!findings.length) { box.innerHTML = '<p class="empty">No confirmed findings yet.</p>'; return; }
  box.innerHTML = findings.map((f) => {
    const chain = (f.chains || []).map((ch) =>
      ch.nodes.map((n, i) => {
        const edge = i < ch.kinds.length ? `<span class="edge ${ch.kinds[i] === "derived_credential" ? "cred" : ""}">${ch.kinds[i] === "derived_credential" ? "→ credential" : "→ enables"}</span>` : "";
        return `<span class="node">${n}</span>` + edge;
      }).join("")
    ).join("<br>");
    return `<div class="find ${f.severity || ""}"><div class="find-head"><span class="find-class">${f.vuln_class || "finding"}</span><span class="sev">${f.severity || "?"}</span></div>
      <div class="kv"><b>Oracle</b><span>${f.oracle_used || "—"}</span><b>Evidence</b><span>${f.evidence_ref || "—"}</span><b>Status</b><span>${f.status || "—"}</span></div>
      ${chain ? `<div class="chain">${chain}</div>` : ""}</div>`;
  }).join("");
}

async function poll() {
  if (!scanId) return;
  try {
    const j = await (await fetch("/api/scan/" + scanId)).json();
    $("phase").textContent = PHASE_LABEL[j.phase] || j.phase || "—";
    renderReasoning(j.events || []);
    renderTimeline(j.events || []);
    renderTools(j.events || []);
    renderCounts(j.graph);
    renderAudit(j.audit);
    renderFindings(j.findings || []);
    try { renderSurface(await (await fetch(`/api/scan/${scanId}/surface`)).json()); } catch (_) {}
    const pill = $("pill");
    if (j.status === "running") { pill.textContent = "running"; pill.className = "pill run"; }
    else { pill.textContent = j.status || "done"; pill.className = "pill"; }
    $("state").textContent = j.status || "—";
    $("dot").className = "dot " + (j.status === "running" ? "live" : j.status === "error" ? "err" : "done");
    if (j.report_md) { $("report").innerHTML = mdToHtml(j.report_md); $("exports").hidden = false;
      $("dl-md").href = `/api/scan/${scanId}/export?format=markdown`;
      $("dl-json").href = `/api/scan/${scanId}/export?format=json`;
      $("dl-html").href = `/api/scan/${scanId}/export?format=html`; }
    if (j.status !== "running") { clearInterval(timer); timer = null; $("go").disabled = false; }
  } catch (err) { clearInterval(timer); timer = null; $("go").disabled = false; }
}

$("go").onclick = async () => {
  const target = $("target").value.trim();
  if (!target) { $("target").focus(); return; }
  $("go").disabled = true;
  $("tgt").textContent = target;
  ["reasoning", "timeline", "tools", "surface", "audit"].forEach((id) => ($(id).innerHTML = ""));
  $("report").innerHTML = ""; $("exports").hidden = true;
  const body = {
    target,
    in_scope: $("scope").value.trim() || target,
    out_of_scope: $("outscope").value.trim() || null,
    prompt: $("prompt").value.trim() || null,
    max_attempts: parseInt($("att").value, 10) || 20,
    use_llm: true,
    llm_provider: $("prov").value.startsWith("named:") ? $("prov").value : null,
  };
  try {
    const r = await fetch("/api/scan", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
    const j = await r.json();
    if (j.error) throw new Error(j.error);
    scanId = j.scan_id;
    timer = setInterval(poll, 1000); poll();
  } catch (err) { alert(String(err)); $("go").disabled = false; }
};

/* providers */
async function loadProviders() {
  const j = await (await fetch("/api/providers")).json();
  const sel = $("prov");
  const cur = sel.value;
  sel.innerHTML = '<option value="">Server default</option>';
  (j.providers || []).forEach((p) => {
    const o = document.createElement("option");
    o.value = "named:" + p.id; o.textContent = p.name; sel.appendChild(o);
  });
  ["deepseek", "openai"].forEach(([v, t]) => {}); // legacy aliases covered by named configs
  [["deepseek","DeepSeek"],["openai","OpenAI"]].forEach(([v,t])=>{
    const o=document.createElement("option");o.value=v;o.textContent=t+" (env default)";sel.appendChild(o);});
  if (cur) sel.value = cur;
  const box = $("provs");
  const d = j.default || {};
  box.innerHTML = `<div class="prov"><span><b>Server default (env)</b><span class="m">${d.provider || "unset"} · ${d.model || ""}</span></span><span class="tag">${d.has_key ? "key set" : "no key"}</span></div>`;
  (j.providers || []).forEach((p) => {
    const row = document.createElement("div");
    row.className = "prov";
    row.innerHTML = `<span><b>${p.name}</b><span class="m">${p.provider} · ${p.model || p.base_url} · ${p.api_style}</span></span>`;
    const act = document.createElement("span");
    const test = document.createElement("button"); test.className = "mini"; test.textContent = "test";
    test.onclick = async () => { test.textContent = "…"; const tj = await (await fetch(`/api/providers/${p.id}/test`, { method: "POST" })).json(); test.textContent = tj.ok ? "✓" : "✗"; setTimeout(() => (test.textContent = "test"), 2500); };
    const edit = document.createElement("button"); edit.className = "mini"; edit.textContent = "edit";
    edit.onclick = () => openForm(p);
    const del = document.createElement("button"); del.className = "mini danger"; del.textContent = "del";
    del.onclick = async () => { await fetch("/api/providers/" + p.id, { method: "DELETE" }); loadProviders(); };
    act.append(test, edit, del);
    row.appendChild(act); box.appendChild(row);
  });
}
let editingId = null;
function openForm(p) {
  editingId = p ? p.id : null;
  $("pf-title").textContent = p ? "Edit provider" : "New provider";
  $("pf-name").value = p?.name || ""; $("pf-type").value = p?.provider || "openai-compatible";
  $("pf-base").value = p?.base_url || ""; $("pf-model").value = p?.model || "";
  $("pf-shape").value = p?.api_style || "chat_completions"; $("pf-key").value = "";
  $("pf-msg").textContent = ""; $("prov-form").hidden = false;
}
$("prov-new").onclick = () => openForm(null);
$("pf-save").onclick = async () => {
  const body = { id: editingId, name: $("pf-name").value.trim(), provider: $("pf-type").value, base_url: $("pf-base").value.trim(), model: $("pf-model").value.trim(), api_style: $("pf-shape").value, api_key: $("pf-key").value.trim() };
  const r = await fetch("/api/providers", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
  const j = await r.json();
  if (j.error) { $("pf-msg").textContent = j.error; return; }
  $("prov-form").hidden = true; editingId = null; loadProviders();
};

setView("#view-run");
loadProviders();
