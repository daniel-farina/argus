const { invoke } = window.__TAURI__.core;
const { listen } = window.__TAURI__.event;
const { open } = window.__TAURI__.dialog;

const $ = (id) => document.getElementById(id);
const qsa = (sel) => document.querySelectorAll(sel);

const state = {
  folders: [],
  detections: [],
  quarantine: [],
  activity: [],
  stats: null,
  sys: null,
  cpuHistory: [],
};

const ROUTE_META = {
  overview: { title: "Overview", sub: "Protection status and recent activity" },
  folders: { title: "Monitored folders", sub: "Folders scanned in real time" },
  detections: { title: "Detections", sub: "Rule matches on files in monitored trees" },
  quarantine: { title: "Quarantine", sub: "Files isolated from disk" },
  activity: { title: "Live activity", sub: "Every file event the scanner has seen" },
  processes: { title: "Processes", sub: "Dev tools running inside monitored folders" },
  network: { title: "Network", sub: "Outbound TCP traffic from your machine" },
  settings: { title: "Settings", sub: "Protection mode and system info" },
};

/* ============== utils ============== */

function sevName(s) {
  if (!s) return "INFO";
  return (typeof s === "string" ? s : String(s)).toUpperCase();
}
function esc(s) {
  if (s == null) return "";
  return String(s)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}
function fmtBytes(n) {
  if (!n) return "0";
  const u = ["B", "KB", "MB", "GB", "TB"];
  let i = 0;
  let v = Number(n);
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
  return (i === 0 ? v : v.toFixed(v < 10 ? 2 : 1)) + " " + u[i];
}
function fmtUptime(startedAt) {
  if (!startedAt) return "-";
  const ms = Date.now() - new Date(startedAt).getTime();
  if (ms < 0) return "-";
  const s = Math.floor(ms / 1000);
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  const sec = s % 60;
  if (h) return `${h}h ${m}m`;
  if (m) return `${m}m ${sec}s`;
  return `${sec}s`;
}
function fmtSecs(s) {
  if (!s) return "-";
  const d = Math.floor(s / 86400);
  const h = Math.floor((s % 86400) / 3600);
  const m = Math.floor((s % 3600) / 60);
  if (d) return `${d}d ${h}h`;
  if (h) return `${h}h ${m}m`;
  return `${m}m`;
}
function fmtTime(ts) {
  if (!ts) return "";
  try { return new Date(ts).toLocaleTimeString([], { hour12: false }); } catch { return ts; }
}
function shortPath(p, max = 70) {
  if (!p) return "";
  if (p.length <= max) return p;
  return "..." + p.slice(p.length - (max - 1));
}
function risk(score) {
  if (score >= 3) return "critical";
  if (score >= 2) return "high";
  if (score >= 1) return "medium";
  return "low";
}

/* ============== router ============== */

function currentRoute() {
  const hash = location.hash.replace(/^#\//, "").split("?")[0];
  return hash in ROUTE_META ? hash : "overview";
}
function setRoute() {
  const r = currentRoute();
  qsa(".route").forEach((el) => el.classList.toggle("active", el.dataset.route === r));
  qsa(".side-nav a").forEach((a) => a.classList.toggle("active", a.dataset.route === r));
  const meta = ROUTE_META[r];
  $("routeTitle").textContent = meta.title;
  $("routeSub").textContent = meta.sub;
  renderAll();
}

/* ============== renderers ============== */

function renderFolders() {
  const ul = $("folderList");
  ul.innerHTML = "";
  $("navFolders").textContent = state.folders.length || "";
  if (!state.folders.length) {
    $("folderEmpty").style.display = "block";
    return;
  }
  $("folderEmpty").style.display = "none";
  for (const f of state.folders) {
    const li = document.createElement("li");
    li.dataset.testid = "folder-row";
    li.innerHTML = `<span class="folder-path">${esc(f)}</span>`;
    const actions = document.createElement("div");
    actions.className = "btn-row";
    actions.style.marginTop = "0";

    const scanBtn = document.createElement("button");
    scanBtn.className = "btn";
    scanBtn.textContent = "Scan";
    scanBtn.onclick = async () => {
      const orig = scanBtn.textContent;
      scanBtn.textContent = "queued";
      try { await invoke("scan_folder_now", { path: f }); }
      catch (e) { alert("Scan failed: " + e); }
      setTimeout(() => (scanBtn.textContent = orig), 1200);
    };
    actions.appendChild(scanBtn);

    const rm = document.createElement("button");
    rm.className = "remove";
    rm.textContent = "Remove";
    rm.onclick = async () => {
      await invoke("remove_folder", { path: f });
      await refresh();
    };
    actions.appendChild(rm);
    li.appendChild(actions);
    ul.appendChild(li);
  }
}

function renderHit(h) {
  const locBits = [];
  if (h.line) locBits.push(`line ${h.line}${h.column ? ":" + h.column : ""}`);
  if (h.byte_offset != null) locBits.push(`byte ${h.byte_offset}`);
  const loc = locBits.length ? `<span class="muted"> (${locBits.join(" · ")})</span>` : "";
  const matched = h.matched ? `<div class="code matched">${esc(h.matched)}</div>` : "";
  const context = h.context ? `<div class="code context">${esc(h.context)}</div>` : "";
  return `
    <div class="hit">
      <div class="hit-head">
        <span class="rid">${esc(h.rule_id)}</span>
        <span class="sev ${sevName(h.severity)}">${sevName(h.severity)}</span>
        <span class="title">${esc(h.title)}</span>${loc}
      </div>
      ${matched}${context}
    </div>`;
}

function detectionItem(d, quarantined) {
  const isQ = quarantined.has(d.path) || (d.action || "").includes("quarantined");
  const hits = (d.hits || []).map(renderHit).join("");
  const rc = (d.hits || []).length;
  const ur = new Set((d.hits || []).map((h) => h.rule_id)).size;
  const firstHit = (d.hits && d.hits[0]) || {};
  const line = firstHit.line || 1;
  const ruleId = firstHit.rule_id || "";
  const ruleTitle = (firstHit.title || "").replace(/"/g, "&quot;");
  const claudeBtn = state.claudeAvailable
    ? `<button class="btn" data-action="ask-claude" data-line="${line}" data-rule="${esc(ruleId)}" data-title="${ruleTitle}">Ask Claude</button>`
    : "";
  return `
    <div class="item" data-testid="detection-row" data-path="${esc(d.path)}" data-line="${line}">
      <div class="row">
        <div class="path">${esc(d.path)}</div>
        <div class="btn-row" style="margin-top:0">
          <span class="sev ${sevName(d.top_severity)}">${sevName(d.top_severity)}</span>
          <button class="btn" data-action="view" data-line="${line}">View source</button>
          <button class="btn" data-action="copy">Copy</button>
          ${claudeBtn}
          ${isQ
            ? `<span class="badge quarantined">quarantined</span>`
            : `<button class="btn danger" data-action="quarantine">Quarantine</button>
               <button class="btn" data-action="reveal">Reveal</button>`}
        </div>
      </div>
      <div class="meta">
        ${esc(fmtTime(d.timestamp))} · ${esc(d.action)} · ${d.size.toLocaleString()} bytes ·
        ${rc} match${rc === 1 ? "" : "es"} / ${ur} rule${ur === 1 ? "" : "s"} ·
        sha256 ${esc((d.sha256 || "").slice(0, 12))}
      </div>
      <div class="hits">${hits}</div>
    </div>`;
}

function wireDetectionActions(root) {
  root.querySelectorAll("[data-action=quarantine]").forEach((btn) => {
    btn.onclick = async () => {
      const row = btn.closest(".item");
      const path = row && row.dataset.path;
      if (!path) return;
      if (!confirm(`Move this file to quarantine?\n\n${path}`)) return;
      btn.disabled = true;
      try { await invoke("quarantine_path", { path }); }
      catch (e) { alert("Quarantine failed: " + e); }
      await refresh();
    };
  });
  root.querySelectorAll("[data-action=reveal]").forEach((btn) => {
    btn.onclick = async () => {
      const row = btn.closest(".item");
      const path = row && row.dataset.path;
      if (!path) return;
      try {
        const { Command } = window.__TAURI__.shell;
        await new Command("open", ["-R", path]).execute();
      } catch { alert(path); }
    };
  });
  root.querySelectorAll("[data-action=view]").forEach((btn) => {
    btn.onclick = async () => {
      const row = btn.closest(".item");
      const path = row && row.dataset.path;
      const line = Number(btn.dataset.line || row.dataset.line || 1);
      await openSourceModal(path, line);
    };
  });
  root.querySelectorAll("[data-action=copy]").forEach((btn) => {
    btn.onclick = async () => {
      const row = btn.closest(".item");
      const path = row && row.dataset.path;
      const line = Number(row.dataset.line || 1);
      try {
        const win = await invoke("read_file_context", { path, line, contextLines: 25 });
        const payload = `// ${path} (lines ${win.start_line}-${win.end_line}, match line ${line})\n${win.excerpt}`;
        await navigator.clipboard.writeText(payload);
        btn.textContent = "Copied!";
        setTimeout(() => (btn.textContent = "Copy"), 1200);
      } catch (e) {
        alert("Copy failed: " + e);
      }
    };
  });
  root.querySelectorAll("[data-action=ask-claude]").forEach((btn) => {
    btn.onclick = async () => {
      const row = btn.closest(".item");
      const path = row && row.dataset.path;
      const line = Number(btn.dataset.line || row.dataset.line || 1);
      const ruleId = btn.dataset.rule || "";
      const ruleTitle = btn.dataset.title || "";
      await openSourceModal(path, line, { askClaude: { ruleId, ruleTitle } });
    };
  });
}

// ======= Source-code modal =======
let modalCurrent = null;
function renderModalCode(win) {
  const lines = win.excerpt.split("\n");
  return lines
    .map((l, i) => {
      const lineNo = win.start_line + i;
      const mark = lineNo === win.highlight_line ? ' class="hl"' : "";
      return `<span${mark}>${String(lineNo).padStart(5)}  ${esc(l)}</span>`;
    })
    .join("\n");
}
async function openSourceModal(path, line, opts = {}) {
  const overlay = $("modalOverlay");
  const title = $("modalTitle");
  const sub = $("modalSub");
  const code = $("modalCode");
  const claudeWrap = $("modalClaude");
  const claudeBody = $("modalClaudeBody");
  claudeWrap.hidden = true;
  claudeBody.textContent = "";
  title.textContent = path;
  sub.textContent = "loading...";
  code.innerHTML = "";
  overlay.hidden = false;
  modalCurrent = { path, line };

  try {
    const win = await invoke("read_file_context", { path, line, contextLines: 25 });
    sub.textContent = `Lines ${win.start_line}-${win.end_line} of ${win.total_lines}` +
      (win.highlight_line ? ` · match at ${win.highlight_line}` : "") +
      (win.truncated ? " · truncated" : "");
    code.innerHTML = renderModalCode(win);
    modalCurrent = { path, line, win };
  } catch (e) {
    sub.textContent = "Error";
    code.textContent = "Could not read file: " + e;
  }

  if (opts.askClaude) {
    await askClaude(opts.askClaude.ruleId, opts.askClaude.ruleTitle);
  }
}
async function askClaude(ruleId = "", ruleTitle = "") {
  if (!modalCurrent) return;
  const { path, line } = modalCurrent;
  const wrap = $("modalClaude");
  const body = $("modalClaudeBody");
  wrap.hidden = false;
  body.textContent = "claude --print ... (this can take up to a minute)";
  try {
    const out = await invoke("analyze_with_claude", {
      path, line, ruleId, ruleTitle,
    });
    body.textContent = out;
  } catch (e) {
    body.textContent = "Claude failed: " + e;
  }
}
function closeModal() {
  $("modalOverlay").hidden = true;
  modalCurrent = null;
}

// ======= Panic button =======
async function refreshPanicButton() {
  try {
    const { paused } = await invoke("panic_status");
    const btn = $("panicBtn");
    const label = $("panicLabel");
    if (paused) {
      btn.classList.add("active");
      label.textContent = "Resume network";
    } else {
      btn.classList.remove("active");
      label.textContent = "Panic: pause network";
    }
  } catch {}
}

function renderDetections() {
  const root = $("detections");
  $("detCount").textContent = state.detections.length;
  $("navDetections").textContent = state.detections.length || "";
  if (!state.detections.length) {
    root.innerHTML = `<div class="muted">Nothing detected yet.</div>`;
    return;
  }
  const quarantined = new Set((state.quarantine || []).map((q) => q.original_path));
  root.innerHTML = state.detections.map((d) => detectionItem(d, quarantined)).join("");
  wireDetectionActions(root);
}

function renderOverview() {
  const s = state.stats || {};
  $("ovFiles").textContent = (s.files_scanned || 0).toLocaleString();
  $("ovDet").textContent = state.detections.length;
  $("ovQ").textContent = state.quarantine.length;
  $("ovFolders").textContent = state.folders.length;
  $("ovFilesFoot").textContent = `${fmtBytes(s.bytes_scanned || 0)} scanned`;
  $("ovDetFoot").textContent = `${(s.detections_count || 0)} since launch`;
  $("ovQFoot").textContent = `${(s.quarantined_count || 0)} moved this session`;
  $("ovFoldersFoot").textContent = `${s.watched_count || 0} watchers live`;

  const cur = s.current_scan;
  const el = $("ovCurrent");
  if (cur) { el.textContent = cur; el.classList.add("scanning"); }
  else if (s.last_path) {
    el.textContent = `last ${s.last_kind || "scanned"}: ${s.last_path}`;
    el.classList.remove("scanning");
  } else {
    el.textContent = "idle - waiting for file events";
    el.classList.remove("scanning");
  }

  const acts = state.activity.slice(0, 8);
  $("ovActivity").innerHTML = acts.length
    ? acts.map(activityRow).join("")
    : `<div class="muted">Waiting for events...</div>`;

  const recent = state.detections.slice(0, 3);
  const qset = new Set((state.quarantine || []).map((q) => q.original_path));
  const ovDets = $("ovDetections");
  ovDets.innerHTML = recent.length
    ? recent.map((d) => detectionItem(d, qset)).join("")
    : `<div class="muted">Nothing detected yet.</div>`;
  wireDetectionActions(ovDets);
}

function activityRow(e) {
  const note = e.note ? ` - ${esc(e.note)}` : "";
  const dur = e.duration_ms ? ` (${e.duration_ms} ms)` : "";
  return `
    <div class="item" data-testid="activity-row">
      <div class="row">
        <div class="path">
          <span class="t">${esc(fmtTime(e.timestamp))}</span>
          <span class="badge ${esc(e.kind)}">${esc(e.kind)}</span>
          <span>${esc(shortPath(e.path))}</span>
        </div>
        <div class="muted">${fmtBytes(e.size)}${dur}</div>
      </div>
      ${note ? `<div class="meta">${note}</div>` : ""}
    </div>`;
}
function renderActivity() {
  const root = $("activity");
  $("actCount").textContent = state.activity.length;
  root.innerHTML = state.activity.length
    ? state.activity.map(activityRow).join("")
    : `<div class="muted">Waiting for file events...</div>`;
}

function renderQuarantine() {
  const root = $("quarantine");
  $("qCount").textContent = state.quarantine.length;
  $("navQuarantine").textContent = state.quarantine.length || "";
  if (!state.quarantine.length) {
    root.innerHTML = `<div class="muted">Quarantine is empty.</div>`;
    return;
  }
  root.innerHTML = "";
  for (const q of state.quarantine) {
    const el = document.createElement("div");
    el.className = "item";
    el.dataset.testid = "quarantine-row";
    el.innerHTML = `
      <div class="row">
        <div class="path">${esc(q.original_path)}</div>
        <div class="btn-row" style="margin-top:0">
          <button class="btn" data-action="restore">Restore</button>
          <button class="btn danger" data-action="delete">Delete</button>
        </div>
      </div>
      <div class="meta">${esc(fmtTime(q.timestamp))} · sha256 ${esc(q.sha256.slice(0,16))} · quarantine ${esc(q.quarantine_path)}</div>`;
    el.querySelector('[data-action=restore]').onclick = async () => {
      await invoke("restore_quarantine", { id: q.id });
      await refresh();
    };
    el.querySelector('[data-action=delete]').onclick = async () => {
      if (!confirm("Permanently delete this quarantined file?")) return;
      await invoke("delete_quarantine", { id: q.id });
      await refresh();
    };
    root.appendChild(el);
  }
}

/* processes - grouped by name, severity from backend */
function renderProcesses(procs) {
  const root = $("procList");
  if (!procs || !procs.length) {
    root.innerHTML = `<div class="muted">No dev tools currently running inside monitored folders.</div>`;
    return;
  }
  const groups = {};
  for (const p of procs) {
    const key = p.name || "unknown";
    (groups[key] = groups[key] || { name: key, rows: [], top: "INFO" });
    groups[key].rows.push(p);
    const s = sevName(p.severity);
    if (sevRank[s] > sevRank[groups[key].top]) groups[key].top = s;
  }
  const sorted = Object.values(groups).sort((a, b) => sevRank[b.top] - sevRank[a.top]);
  root.innerHTML = sorted
    .map((g) => {
      const rows = g.rows
        .sort((a, b) => sevRank[sevName(b.severity)] - sevRank[sevName(a.severity)])
        .map(
          (p) => {
            const s = sevName(p.severity);
            return `<div class="hit">
              <div class="hit-head">
                <span class="rid">pid ${p.pid}</span>
                <span class="sev ${s}">${s}</span>
                <span class="title">${esc(p.reason)}</span>
              </div>
              <div class="code context">${esc(p.cmd || "")}</div>
              ${p.exe ? `<div class="muted" style="margin-top:4px">exe: ${esc(p.exe)}</div>` : ""}
            </div>`;
          }
        )
        .join("");
      return `<div class="item" data-testid="proc-row">
        <div class="row">
          <div class="path"><b>${esc(g.name)}</b> <span class="muted">(${g.rows.length})</span></div>
          <div><span class="sev ${g.top}">${g.top}</span></div>
        </div>
        <div class="hits">${rows}</div>
      </div>`;
    })
    .join("");
}

/* network - severity comes from backend; highlight new connections */
const sevRank = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0 };
const seenConns = new Set(); // key: pid+remote+path - markers for "new"

function connKey(c) {
  return `${c.pid}|${c.remote}|${c.path || ""}`;
}

function renderNetwork(conns) {
  const root = $("netList");
  if (!conns || !conns.length) {
    root.innerHTML = `<div class="muted">No established outbound connections.</div>`;
    return;
  }

  // Mark new connections based on what we've seen in this session.
  for (const c of conns) {
    const k = connKey(c);
    c._new = !seenConns.has(k);
    seenConns.add(k);
  }

  const groups = {};
  for (const c of conns) {
    const key = c.command || "unknown";
    (groups[key] = groups[key] || {
      name: key,
      pids: new Set(),
      rows: [],
      top: "INFO",
      bytes_in: 0,
      bytes_out: 0,
      newCount: 0,
    });
    groups[key].pids.add(c.pid);
    groups[key].rows.push(c);
    const s = sevName(c.severity);
    if (sevRank[s] > sevRank[groups[key].top]) groups[key].top = s;
    groups[key].bytes_in += Number(c.bytes_in || 0);
    groups[key].bytes_out += Number(c.bytes_out || 0);
    if (c._new) groups[key].newCount += 1;
  }

  const sorted = Object.values(groups).sort((a, b) => {
    const diff = sevRank[b.top] - sevRank[a.top];
    if (diff !== 0) return diff;
    if (b.newCount !== a.newCount) return b.newCount - a.newCount;
    return (b.bytes_in + b.bytes_out) - (a.bytes_in + a.bytes_out);
  });

  root.innerHTML = sorted
    .map((g) => {
      const rows = g.rows
        .sort((a, b) => sevRank[sevName(b.severity)] - sevRank[sevName(a.severity)])
        .map((c) => {
          const s = sevName(c.severity);
          const bi = fmtBytes(c.bytes_in || 0);
          const bo = fmtBytes(c.bytes_out || 0);
          const newBadge = c._new ? `<span class="badge new">new</span>` : "";
          return `<div class="hit">
            <div class="hit-head">
              <span class="rid">pid ${c.pid}</span>
              <span class="sev ${s}">${s}</span>
              ${newBadge}
              <span class="title">${esc(c.remote)}</span>
              <span class="muted">↓ ${bi} · ↑ ${bo}</span>
            </div>
            ${c.path ? `<div class="code context">${esc(c.path)}</div>` : ""}
            ${c.reason ? `<div class="muted" style="margin-top:4px">${esc(c.reason)}</div>` : ""}
          </div>`;
        })
        .join("");
      const newLabel = g.newCount ? ` · <b style="color:#60a5fa">${g.newCount} new</b>` : "";
      return `
        <div class="item" data-testid="net-row">
          <div class="row">
            <div class="path"><b>${esc(g.name)}</b> <span class="muted">${g.pids.size} pid${g.pids.size === 1 ? "" : "s"} · ${g.rows.length} conn${g.rows.length === 1 ? "" : "s"}${newLabel}</span></div>
            <div><span class="sev ${g.top}">${g.top}</span></div>
          </div>
          <div class="meta">↓ total ${fmtBytes(g.bytes_in)} · ↑ total ${fmtBytes(g.bytes_out)}</div>
          <div class="hits">${rows}</div>
        </div>`;
    })
    .join("");
}

/* bottombar + system */
function renderBottombar() {
  const sys = state.sys;
  const stats = state.stats || {};
  const cpu = sys && sys.cpu_global != null ? Math.min(100, Math.round(sys.cpu_global)) : 0;
  const memPct = sys && sys.mem_total ? Math.round((sys.mem_used / sys.mem_total) * 100) : 0;
  const mainDisk = sys && sys.disks && sys.disks.find((d) => d.mount === "/") || (sys && sys.disks && sys.disks[0]);
  const diskPct = mainDisk ? Math.round((mainDisk.used / mainDisk.total) * 100) : 0;

  const cpuFill = $("bbCpuFill");
  const memFill = $("bbMemFill");
  const diskFill = $("bbDiskFill");
  const setBar = (el, v) => {
    if (!el) return;
    el.style.width = v + "%";
    el.classList.toggle("crit", v >= 90);
    el.classList.toggle("warn", v >= 70 && v < 90);
  };
  setBar(cpuFill, cpu);
  setBar(memFill, memPct);
  setBar(diskFill, diskPct);

  $("bbCpu").textContent = sys ? cpu + "%" : "-";
  $("bbMem").textContent = sys
    ? `${fmtBytes(sys.mem_used)} / ${fmtBytes(sys.mem_total)}`
    : "-";
  $("bbDisk").textContent = mainDisk
    ? `${fmtBytes(mainDisk.used)} / ${fmtBytes(mainDisk.total)}`
    : "-";
  $("bbLoad").textContent = sys
    ? `${sys.load_avg_1m.toFixed(2)} / ${sys.load_avg_5m.toFixed(2)} / ${sys.load_avg_15m.toFixed(2)}`
    : "-";
  $("bbUptime").textContent = fmtUptime(stats.started_at);
  $("bbWatched").textContent = stats.watched_count || 0;
  $("bbScans").textContent = (stats.files_scanned || 0).toLocaleString();

  const pulse = $("bbPulse");
  if (stats.current_scan) pulse.classList.remove("idle");
  else pulse.classList.add("idle");
}

function renderSettings() {
  const sys = state.sys;
  const stats = state.stats || {};
  const mode = $("settingsMode");
  const s = state.statusSummary || {};
  const label = !s.protection_enabled
    ? "paused"
    : s.auto_quarantine || s.auto_kill_processes
      ? "active blocking"
      : "detect only";
  mode.textContent = label;

  const meta = $("sysMeta");
  const rows = [];
  if (sys) {
    rows.push(["Hostname", sys.hostname || "-"]);
    rows.push(["OS", sys.os || "-"]);
    rows.push(["CPU", `${sys.cpu_cores.length} cores - ${sys.cpu_global.toFixed(1)}%`]);
    rows.push(["Memory", `${fmtBytes(sys.mem_used)} / ${fmtBytes(sys.mem_total)}`]);
    rows.push(["Swap", `${fmtBytes(sys.swap_used)} / ${fmtBytes(sys.swap_total)}`]);
    rows.push(["System uptime", fmtSecs(sys.uptime_secs)]);
    for (const d of (sys.disks || []).slice(0, 4)) {
      rows.push([`Disk ${d.mount}`, `${fmtBytes(d.used)} / ${fmtBytes(d.total)} (${d.fs})`]);
    }
  }
  rows.push(["App uptime", fmtUptime(stats.started_at)]);
  rows.push(["Files scanned", (stats.files_scanned || 0).toLocaleString()]);
  rows.push(["Bytes scanned", fmtBytes(stats.bytes_scanned || 0)]);
  meta.innerHTML = rows.map(([k, v]) => `<div class="k">${esc(k)}</div><div class="v">${esc(v)}</div>`).join("");
}

function renderAll() {
  renderFolders();
  renderDetections();
  renderQuarantine();
  renderActivity();
  renderOverview();
  renderBottombar();
  renderSettings();
}

/* ============== data ============== */

async function refresh() {
  const s = await invoke("get_status");
  state.statusSummary = s;
  state.folders = s.folders;
  const protOn = s.protection_enabled;
  $("statusPill").classList.toggle("on", protOn);
  $("statusPill").classList.toggle("off", !protOn);
  $("statusText").textContent = protOn ? "Protection active" : "Protection paused";
  $("tglProtection").checked = s.protection_enabled;
  $("tglQuarantine").checked = s.auto_quarantine;
  $("tglKill").checked = s.auto_kill_processes;
  const mode = !s.protection_enabled ? "paused" :
    s.auto_quarantine || s.auto_kill_processes ? "active blocking" : "detect only";
  $("modePill").textContent = mode;
  state.detections = await invoke("list_detections");
  state.quarantine = await invoke("list_quarantine");
  state.activity = await invoke("list_activity", { limit: 80 });
  state.stats = await invoke("get_activity_stats");
  renderAll();
}

async function pollSystem() {
  try {
    state.sys = await invoke("get_system_stats");
    renderBottombar();
    if (currentRoute() === "settings") renderSettings();
  } catch {}
}

/* ============== bootstrap ============== */

async function bootstrap() {
  try { $("versionTag").textContent = `v${await invoke("app_version")}`; }
  catch { $("versionTag").textContent = "error"; }

  // sidebar links
  qsa(".side-nav a").forEach((a) => {
    a.addEventListener("click", (e) => {
      e.preventDefault();
      location.hash = "#/" + a.dataset.route;
    });
  });
  window.addEventListener("hashchange", setRoute);

  // actions
  $("addFolderBtn").onclick = async () => {
    const picked = await open({ directory: true, multiple: false });
    if (picked) {
      try { await invoke("add_folder", { path: picked }); }
      catch (e) { alert("Could not add folder: " + e); }
      await refresh();
    }
  };
  $("scanAllBtn").onclick = async () => {
    const btn = $("scanAllBtn");
    const orig = btn.textContent;
    btn.textContent = "Scanning...";
    try { await invoke("scan_all_folders"); }
    catch (e) { alert("Scan failed: " + e); }
    setTimeout(() => (btn.textContent = orig), 1500);
  };
  const clearBtn = $("clearDetBtn");
  if (clearBtn) {
    clearBtn.onclick = async () => {
      if (!confirm("Clear all detections and activity? Quarantine is kept.")) return;
      await invoke("clear_detections");
      await refresh();
    };
  }

  // Panic button
  const panicBtn = $("panicBtn");
  panicBtn.onclick = async () => {
    panicBtn.classList.add("busy");
    const { paused } = await invoke("panic_status").catch(() => ({ paused: false }));
    try {
      if (paused) {
        await invoke("panic_resume");
      } else {
        if (!confirm("Drop all outbound TCP via pfctl?\n\nYou'll get a macOS admin prompt. Use this if you think your machine is actively compromised.")) {
          panicBtn.classList.remove("busy");
          return;
        }
        await invoke("panic_pause");
      }
    } catch (e) {
      alert("Panic toggle failed: " + e);
    }
    panicBtn.classList.remove("busy");
    await refreshPanicButton();
  };

  // Modal wiring
  $("modalCloseBtn").onclick = closeModal;
  $("modalOverlay").addEventListener("click", (e) => {
    if (e.target === $("modalOverlay")) closeModal();
  });
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") closeModal();
  });
  $("modalCopyBtn").onclick = async () => {
    if (!modalCurrent || !modalCurrent.win) return;
    const w = modalCurrent.win;
    await navigator.clipboard.writeText(
      `// ${w.path} (lines ${w.start_line}-${w.end_line})\n${w.excerpt}`
    );
    $("modalCopyBtn").textContent = "Copied!";
    setTimeout(() => ($("modalCopyBtn").textContent = "Copy"), 1200);
  };
  $("modalAskBtn").onclick = () => askClaude();

  // Check if claude CLI is available once up front
  try { state.claudeAvailable = await invoke("claude_available"); } catch {}
  if (!state.claudeAvailable) {
    $("modalAskBtn").disabled = true;
    $("modalAskBtn").title = "claude CLI not found on PATH";
    $("modalAskBtn").textContent = "Ask Claude (unavailable)";
  }
  const runProcScan = async () => {
    try { renderProcesses(await invoke("scan_processes")); } catch {}
  };
  const runNetScan = async () => {
    try { renderNetwork(await invoke("scan_network")); } catch {}
  };
  $("scanProcsBtn").onclick = runProcScan;
  $("scanNetBtn").onclick = runNetScan;

  // Live-refresh toggles - persist in localStorage so they survive reloads.
  const liveProcs = $("liveProcs");
  const liveNet = $("liveNet");
  let procTimer = null;
  let netTimer = null;
  const setLive = (kind, on) => {
    const key = `live_${kind}`;
    localStorage.setItem(key, on ? "1" : "0");
    if (kind === "procs") {
      if (procTimer) { clearInterval(procTimer); procTimer = null; }
      if (on) { runProcScan(); procTimer = setInterval(runProcScan, 10000); }
    } else {
      if (netTimer) { clearInterval(netTimer); netTimer = null; }
      if (on) { runNetScan(); netTimer = setInterval(runNetScan, 15000); }
    }
  };
  liveProcs.checked = localStorage.getItem("live_procs") === "1";
  liveNet.checked = localStorage.getItem("live_net") === "1";
  liveProcs.onchange = (e) => setLive("procs", e.target.checked);
  liveNet.onchange = (e) => setLive("net", e.target.checked);
  if (liveProcs.checked) setLive("procs", true);
  if (liveNet.checked) setLive("net", true);
  for (const [id, key] of [
    ["tglProtection", "protectionEnabled"],
    ["tglQuarantine", "autoQuarantine"],
    ["tglKill", "autoKillProcesses"],
  ]) {
    $(id).onchange = async (e) => {
      const p = {}; p[key] = e.target.checked;
      await invoke("set_protection", p);
      await refresh();
    };
  }

  // events
  let rScheduled = false;
  const scheduleRefresh = () => {
    if (rScheduled) return;
    rScheduled = true;
    setTimeout(async () => { rScheduled = false; try { await refresh(); } catch {} }, 300);
  };
  await listen("devprotector://detection", scheduleRefresh);
  await listen("devprotector://quarantine", scheduleRefresh);
  await listen("devprotector://activity", (evt) => {
    if (evt && evt.payload) {
      state.activity = [evt.payload, ...state.activity].slice(0, 80);
      if (currentRoute() === "activity") renderActivity();
      if (currentRoute() === "overview") renderOverview();
    }
  });
  await listen("devprotector://scan-start", (evt) => {
    if (!state.stats) state.stats = {};
    state.stats.current_scan = evt.payload && evt.payload.path;
    if (currentRoute() === "overview") renderOverview();
    renderBottombar();
  });
  await listen("devprotector://scan-complete", () => {
    if (state.stats) state.stats.current_scan = null;
    renderBottombar();
    scheduleRefresh();
  });

  // initial
  setRoute();
  await refresh();
  await pollSystem();
  await refreshPanicButton();

  // polls
  setInterval(async () => {
    try {
      state.stats = await invoke("get_activity_stats");
      if (currentRoute() === "overview") renderOverview();
      renderBottombar();
    } catch {}
  }, 1000);
  setInterval(pollSystem, 2500);
  setInterval(refresh, 5000);
  setInterval(refreshPanicButton, 4000);
}

bootstrap();
