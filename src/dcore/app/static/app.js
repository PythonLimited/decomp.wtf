"use strict";
/* decomp.wtf GUI. Plain JS, no build step. Everything shown from agents is untrusted text:
   it only ever reaches the page through textContent or esc(). */

const $ = (id) => document.getElementById(id);
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
const hex8 = (n) => "0x" + (n >>> 0).toString(16).toUpperCase().padStart(8, "0");
const clock = (t) => new Date(t * 1000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false });
const pctOf = (best, insns) => (best == null ? null : Math.max(0, 1 - best / Math.max(1, insns * 100)));
/* A match percentage that never reads 100% before the function really matches (99.6% stays 99.6%). */
const pctText = (p) => (p >= 0.99 ? `${(Math.floor(p * 1000) / 10).toFixed(1)}%` : `${Math.floor(p * 100)}%`);
const pctNum = (p) => (p < 10 ? p.toFixed(2) : p.toFixed(1));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const plural = (n, word) => `${n.toLocaleString()} ${word}${n === 1 ? "" : "s"}`;
function since(t) {
  if (!t) return "";
  const s = Date.now() / 1000 - t;
  return s < 60 ? "just now" : s < 3600 ? `${Math.round(s / 60)} min ago` : s < 86400 ? `${Math.round(s / 3600)} h ago`
    : s < 172800 ? "yesterday" : `${Math.round(s / 86400)} days ago`;
}
function duration(h) { return h < 1 ? `${Math.max(1, Math.round(h * 60))} min` : h < 48 ? `${h.toFixed(h < 10 ? 1 : 0)} h` : `${Math.round(h / 24)} days`; }
function bytes(n) { return n >= 1 << 20 ? `${(n / 1048576).toFixed(1)} MB` : n >= 1024 ? `${(n / 1024).toFixed(1)} KB` : `${n} bytes`; }
function money(usd) { return usd >= 10 ? `$${usd.toFixed(0)}` : `$${usd.toFixed(2)}`; }

async function api(path, { method = "GET", body, raw } = {}) {
  const opts = { method, headers: {} };
  if (method !== "GET") opts.headers["X-Decomp"] = "1";
  if (raw !== undefined) { opts.body = raw; opts.headers["Content-Type"] = "application/octet-stream"; }
  else if (body !== undefined) { opts.body = JSON.stringify(body); opts.headers["Content-Type"] = "application/json"; }
  const res = await fetch(path, opts);
  let data = null;
  try { data = await res.json(); } catch { /* not json */ }
  if (!res.ok) throw new Error((data && data.error) || `request failed (${res.status})`);
  return data;
}

function toast(html, kind = "") {
  const t = document.createElement("div");
  t.className = "toast " + kind;
  t.innerHTML = html;
  $("toasts").append(t);
  setTimeout(() => { t.style.opacity = "0"; t.style.transition = "opacity .4s"; }, kind === "err" ? 7000 : 4200);
  setTimeout(() => t.remove(), kind === "err" ? 7500 : 4700);
}

async function followJob(id, logEl, onUpdate) {
  for (;;) {
    const job = await api(`/api/job?id=${id}`);
    if (logEl) { logEl.textContent = job.log.join("\n"); logEl.scrollTop = logEl.scrollHeight; }
    if (onUpdate) onUpdate(job.log);
    if (job.state === "done") return job.result;
    if (job.state === "error") { const err = new Error(job.error); err.job = job; throw err; }
    await sleep(500);
  }
}

/* The map's still cells are drawn once into `base` (again only when one of them changes); a frame copies it and
   draws just what moves on top: the functions being worked on, fresh matches, the selection. A big game is tens of
   thousands of cells, and redrawing them all 60 times a second while agents or autopilot work made the app lag. */
let base = null, baseDirty = true, moving = [];
function mapChanged() { baseDirty = true; }

/* ------------------------------------------------------------------ theme */
const THEME_KEY = "decomp-wtf-theme";
function applyTheme(t) {
  if (t) document.documentElement.dataset.theme = t; else delete document.documentElement.dataset.theme;
  colors = null; baseDirty = true;
  if (S.map.length) drawMap();
}
function setTheme(t) {
  try { if (t) localStorage.setItem(THEME_KEY, t); else localStorage.removeItem(THEME_KEY); } catch { /* storage off */ }
  applyTheme(t);
}
function savedTheme() { try { return localStorage.getItem(THEME_KEY) || ""; } catch { return ""; } }
$("themeBtn").onclick = () => setTheme(getComputedStyle(document.documentElement).colorScheme.includes("dark") ? "light" : "dark");

/* ------------------------------------------------------------------ state + routing */
const S = {
  st: null, slug: null, ov: null, map: [], byName: new Map(), e: 0, a: 0, seq: {}, sessions: [], tab: "overview",
  scores: new Map(), claims: [], flash: new Map(), timer: null, statsTimer: null, lastMapFetch: 0, fn: null, stats: null,
  projects: [],
};
const VIEWS = ["home", "project", "agentsPage", "toolsPage", "settingsPage"];
const TABS = ["overview", "functions", "plan", "agents", "activity", "source", "settings"];

/* The project folder in the computer's file manager (decomp.wtf in Docker says where it is instead). */
function openFolder() {
  return api("/api/open", { method: "POST", body: { slug: S.slug } })
    .then((r) => { if (r && r.message) toast(esc(r.message)); })
    .catch((e) => toast(esc(e.message), "err"));
}

async function loadState() { S.st = await api("/api/state"); $("navVersion").textContent = `v${S.st.version}`; return S.st; }

function route() {
  const h = location.hash;
  const m = h.match(/^#\/p\/([\w-]+)(?:\/(\w+))?/);
  closeAll();
  closeNav();
  hideLaunch();
  if (m) {
    if (S.slug === m[1] && !$("project").hidden) { setTab(m[2] || "overview"); markNav(); return; }
    leaveProject();
    openProject(m[1], m[2] || "overview");
  } else {
    leaveProject();
    if (h === "#/agents") showAgentsPage();
    else if (h === "#/tools") showToolsPage();
    else if (h === "#/settings") showSettingsPage();
    else showHome();
  }
  markNav();
}
window.addEventListener("hashchange", route);

function show(view) {
  for (const v of VIEWS) $(v).hidden = view !== v;
  $("main").scrollTo(0, 0);
  window.scrollTo(0, 0);
}
function leaveProject() {
  stopPolling();
  S.slug = null;
}

/* ------------------------------------------------------------------ sidebar */
/* The page's CSP allows no inline style attributes: widths are set through the DOM instead. */
function setWidths(root) { root.querySelectorAll("[data-w]").forEach((el) => { el.style.width = el.dataset.w + "%"; }); }

function markNav() {
  const h = location.hash || "#/";
  const route = h.startsWith("#/p/") ? "project" : (h.replace("#/", "") || "home");
  document.querySelectorAll(".nav [data-route]").forEach((a) => a.classList.toggle("on", a.dataset.route === route));
  document.querySelectorAll(".nav-proj").forEach((a) => a.classList.toggle("on", a.dataset.slug === S.slug && route === "project"));
}
async function loadNav() {
  try { S.projects = await api("/api/projects"); } catch (e) {
    if (!S.projects?.length) $("navProjects").innerHTML = `<p class="nav-empty">Couldn't load your projects: ${esc(e.message)}</p>`;
    return;
  }
  renderNav();
}
function renderNav() {
  const box = $("navProjects");
  if (!S.projects.length) { box.innerHTML = `<p class="nav-empty">None yet: drop in a game.</p>`; return; }
  box.innerHTML = S.projects.map((p) => {
    const pct = p.bytes ? (100 * p.matched_bytes) / p.bytes : 0;
    const short = [(p.binary?.format || "").toUpperCase(), p.binary?.arch || ""].filter(Boolean).join(" ") || (p.platform_name || "");
    const state = p.working ? `<span class="dot on" title="${p.working} agent${p.working === 1 ? "" : "s"} working"></span>`
      : p.autopilot === "running" ? `<span class="dot work" title="autopilot running"></span>` : "";
    if (p.broken) return `<a class="nav-proj broken" href="#/p/${esc(p.slug)}" data-slug="${esc(p.slug)}" title="${esc(p.broken)}">
      <span class="np-top"><span class="np-name">${esc(p.title)}</span></span>
      <span class="np-meta"><span>can't be opened: hover for why</span></span></a>`;
    return `<a class="nav-proj" href="#/p/${esc(p.slug)}" data-slug="${esc(p.slug)}" title="${esc(p.title)}">
      <span class="np-top"><span class="np-name">${esc(p.title)}</span>${state}</span>
      <span class="np-meta"><span>${esc(short)}</span><span class="grow"></span><span>${pctNum(pct)}%</span></span>
      <span class="np-bar"><i data-w="${pct.toFixed(2)}"></i></span></a>`;
  }).join("");
  setWidths(box);
  markNav();
}
setInterval(loadNav, 5000);
function openNav() { document.body.classList.add("nav-open"); $("navShade").hidden = false; }
function closeNav() { document.body.classList.remove("nav-open"); $("navShade").hidden = true; }
$("navOpen").onclick = openNav;
$("navClose").onclick = closeNav;
$("navShade").onclick = closeNav;

/* ------------------------------------------------------------------ home */
let picked = null;

async function showHome() {
  show("home");
  resetDrop();
  const st = await loadState();
    const box = $("projects");
  box.innerHTML = "";
  $("recent").hidden = !st.projects.length;
  for (const p of st.projects) {
    const pct = p.bytes ? (100 * p.matched_bytes) / p.bytes : 0;
    const a = document.createElement("a");
    a.className = "card";
    a.href = `#/p/${p.slug}`;
    if (p.broken) {
      a.innerHTML = `<div class="cc-top"><span class="plat">?</span></div><div><h4>${esc(p.title)}</h4>
        <p class="meta err-text">Can't be opened: ${esc(p.broken)}</p></div>`;
      box.append(a);
      continue;
    }
    const meta = `${esc((p.binary?.format || "").toUpperCase())} ${esc(p.binary?.arch || "")}` +
      `${p.binary?.kind ? " " + esc(p.binary.kind) : ""} · ${esc(p.compiler?.name || "")}`;
    a.innerHTML = `<div class="cc-top"><span class="plat">${esc(p.platform_name || "?")}</span><span class="meta">${esc(since(p.last_activity))}</span></div>
      <div><h4>${esc(p.title)}</h4><p class="meta">${meta}</p></div>
      <div class="meter"><i></i></div><p class="meta"><b>${pctNum(pct)}%</b> of code · ${(p.matched || 0).toLocaleString()} / ${(p.functions || 0).toLocaleString()} functions</p>`;
    box.append(a);
    requestAnimationFrame(() => { a.querySelector(".meter i").style.width = pct + "%"; });
  }
}

function resetDrop() {
  picked = null;
  $("dropIdle").hidden = false;
  $("dropPicked").hidden = true;
  $("dropBusy").hidden = true;
  $("dropError").hidden = true;
  $("own").checked = false;
  $("analyse").disabled = true;
  $("file").value = "";
}

const drop = $("drop");
drop.addEventListener("click", (e) => { if (!$("dropIdle").hidden && !e.target.closest("button")) $("file").click(); });
drop.addEventListener("keydown", (e) => { if ((e.key === "Enter" || e.key === " ") && !$("dropIdle").hidden && e.target === drop) { e.preventDefault(); $("file").click(); } });
drop.addEventListener("dragover", (e) => { e.preventDefault(); drop.classList.add("over"); });
drop.addEventListener("dragleave", () => drop.classList.remove("over"));
drop.addEventListener("drop", (e) => { e.preventDefault(); drop.classList.remove("over"); if (e.dataTransfer.files[0]) pickFile(e.dataTransfer.files[0]); });
$("file").addEventListener("change", () => { if ($("file").files[0]) pickFile($("file").files[0]); });
$("own").addEventListener("change", updateAnalyse);
$("cancelPick").onclick = resetDrop;

/* What the user dropped, from its first bytes (nothing is uploaded until they confirm). */
function identifyHead(head, file) {
  const dv = new DataView(head.buffer);
  const text = (a, b) => String.fromCharCode(...head.slice(a, b));
  const stem = file.name.replace(/\.[^.]*$/, "");
  const base = { title: stem, size: file.size, platform: "native" };
  if (text(0, 4) === "\x7fELF") {
    const machine = dv.getUint16(18, true);
    if (![0x3e, 0xb7, 0x03].includes(machine)) return null;
    const etype = dv.getUint16(16, true);
    return { ...base, format: "elf", arch: machine === 0x3e ? "x86_64" : machine === 0xb7 ? "aarch64" : "x86",
             bits: head[4] === 2 ? 64 : 32,
             order: etype === 3 ? "shared library / PIE" : etype === 2 ? "executable" : etype === 1 ? "object file" : "ELF" };
  }
  if (head[0] === 0x4d && head[1] === 0x5a && head.length >= 0x40) {
    const pe = dv.getUint32(0x3c, true);
    if (pe > 0 && pe + 6 <= head.length && text(pe, pe + 2) === "PE") {
      const machine = dv.getUint16(pe + 4, true);
      if (![0x8664, 0xaa64, 0x14c].includes(machine)) return null;
      const chars = dv.getUint16(pe + 22, true);
      return { ...base, format: "pe", arch: machine === 0x8664 ? "x86_64" : machine === 0xaa64 ? "aarch64" : "x86",
               bits: 64, order: chars & 0x2000 ? "DLL" : "executable" };
    }
    return null;
  }
  if (dv.getUint32(0) === 0xfeedfacf || dv.getUint32(0) === 0xcffaedfe) {
    const cpu = dv.getUint32(4);
    const arch = cpu === 0x01000007 ? "x86_64" : cpu === 0x0100000c ? "aarch64" : cpu === 7 ? "x86" : "";
    if (!arch) return null;
    const kind = { 2: "executable", 1: "object file", 6: "shared library", 8: "bundle" }[dv.getUint32(12)] || "Mach-O";
    return { ...base, format: "macho", arch, bits: 64, order: kind };
  }
  if (dv.getUint32(0) === 0xcafebabe || dv.getUint32(0) === 0xcafebabf) {
    const cpu = (head[8] << 24) | (head[9] << 16) | (head[10] << 8) | head[11];
    const arch = cpu === 0x01000007 ? "x86_64" : cpu === 0x0100000c ? "aarch64" : "";
    return arch ? { ...base, format: "macho", arch, bits: 64, order: "universal binary" } : null;
  }
  return null;
}
const MB = (n) => (n < 1048576 ? `${Math.max(1, Math.round(n / 1024))} KiB` : `${(n / 1048576).toFixed(n < 10485760 ? 1 : 0)} MiB`);

async function pickFile(file) {
  const head = new Uint8Array(await file.slice(0, 0x1000).arrayBuffer());
  const info = identifyHead(head, file);
  if (!info) {
    return toast("Pick a program this build can read: an ELF, PE or Mach-O file (Linux, Windows, macOS, Android — x86, x86_64 or aarch64).", "err");
  }
  picked = { buf: file, info, name: file.name };
  $("romFile").textContent = file.name;
  $("romTitle").textContent = info.title;
  const facts = [["Format", `${info.format.toUpperCase()} \u00b7 ${info.arch}`], ["Kind", info.order], ["Size", MB(info.size)],
                 ["Analysis", "IDA (or an existing .i64)"], ["Compiler", "Read from the build info; adjustable on the plan"]];
  $("romFacts").innerHTML = facts.map(([k, v]) => `<div><dt>${k}</dt><dd>${esc(v)}</dd></div>`).join("");
  $("dropIdle").hidden = true;
  $("dropPicked").hidden = false;
  updateAnalyse();
}

function updateAnalyse() {
  $("analyse").disabled = !$("own").checked;
}

function setupCompilers(info) {
  const note = $("compilerNote");
  note.hidden = false;
  note.textContent = "The compiler and flags are read from the binary's build info; adjust them on the plan screen.";
  updateAnalyse();
}

async function runImport(query, file, title, name = "") {
  $("dropIdle").hidden = true;
  $("dropPicked").hidden = true;
  $("dropBusy").hidden = false;
  $("busyTitle").textContent = title;
  $("busyStep").textContent = "starting";
  $("jobLog").textContent = "";
  $("impUp").hidden = !(file instanceof Blob);
  const t0 = Date.now();
  const tick = setInterval(() => {
    const s = Math.round((Date.now() - t0) / 1000);
    $("busyTime").textContent = s >= 3 ? ` · ${Math.floor(s / 60)}:${String(s % 60).padStart(2, "0")}` : "";
  }, 1000);
  try {
    let started;
    if (file instanceof Blob) {
      started = await uploadFile(`/api/import?${query}&name=${encodeURIComponent(name || file.name || "game.bin")}`, file,
        (p) => { $("impUp").firstElementChild.style.width = (p * 100).toFixed(1) + "%"; $("busyTitle").textContent = p < 1 ? `Copying ${title.replace(/^\w+ /, "")} into decomp.wtf… ${(p * 100).toFixed(0)}%` : title; });
    } else {
      started = await api(`/api/import?${query}`, { method: "POST", raw: file ?? new ArrayBuffer(0) });
    }
    $("impUp").hidden = true;
    const res = await followJob(started.job, $("jobLog"), (log) => {
      const last = log.filter((l) => l.trim()).pop();
      if (last) $("busyStep").textContent = last.trim().replace(/\s+/g, " ").slice(0, 120);
    });
    loadNav();
    location.hash = `#/p/${res.slug}`;
  } catch (e) {
    importFailed(name || title.replace(/^\w+ |…$/g, ""), e, $("jobLog").textContent);
  } finally { clearInterval(tick); $("busyTime").textContent = ""; }
}

/* A failed import stays on screen with what happened, ready to report: a toast is gone before it's read. */
function importFailed(name, e, logText) {
  const job = e.job || {};
  const log = (job.log ? job.log.join("\n") : logText || "").trim();
  $("dropIdle").hidden = true; $("dropPicked").hidden = true; $("dropBusy").hidden = true;
  $("dropError").hidden = false;
  $("errName").textContent = name || "the game";
  $("errMsg").textContent = e.message;
  $("errLog").textContent = [log, job.trace].filter(Boolean).join("\n\n") || "(nothing was logged)";
  $("errCopy").onclick = async () => {
    const st = S.st || {};
    const report = [`decomp.wtf ${st.version || "?"}${st.build ? ` (${st.build})` : ""} · ${st.runtime || st.platform || navigator.platform}`,
      `Importing: ${name}`, `Error: ${e.message}`, "", "Log:", "```", log.split("\n").slice(-80).join("\n"), job.trace || "", "```"].join("\n");
    try { await navigator.clipboard.writeText(report); toast("Copied: paste it into a GitHub issue"); }
    catch { toast("Couldn't reach the clipboard: select the text under What happened instead", "err"); }
  };
}
$("errBack").onclick = (e) => { e.stopPropagation(); resetDrop(); };

$("analyse").onclick = async () => {
  if (!picked || $("analyse").disabled) return;
  const title = `Analysing ${picked.info.title}…`;
  const body = picked.buf instanceof Blob ? picked.buf : new Blob([picked.buf]);
  runImport("confirmed=1", body, title, picked.name);
};
$("pathPick").onclick = (e) => {
  e.stopPropagation();
  const body = dialog("Use a file on this computer", `<p class="muted">For big disc images: decomp.wtf reads the file where it is instead of copying it through the browser.</p>
    <label class="field"><span>Path to the game file</span><input id="ppPath" class="mono" placeholder="/home/me/games/my-game.iso"></label>
    <label class="field"><span>IDA database (optional)</span><input id="ppI64" class="mono" placeholder="a .i64/.idb next to the file is used automatically"></label>
    <label class="check"><input type="checkbox" id="ppOwn"><span>This is my own copy of this game, obtained legally. The results stay with me for my own use.</span></label>
    <div class="row"><button class="primary" id="ppGo" type="button" disabled>Start decompiling</button><button class="ghost" data-close type="button">Cancel</button></div>`);
  body.querySelector("#ppOwn").onchange = () => { $("ppGo").disabled = !$("ppOwn").checked; };
  body.querySelector("#ppGo").onclick = () => {
    const path = $("ppPath").value.trim();
    const i64 = $("ppI64").value.trim();
    if (!path) return;
    $("dialog").hidden = true;
    runImport(`confirmed=1&path=${encodeURIComponent(path)}${i64 ? `&i64=${encodeURIComponent(i64)}` : ""}`,
      undefined, "Analysing your game…");
  };
};

/* ------------------------------------------------------------------ project */
async function openProject(slug, tab = "overview") {
  show("project");
  S.slug = slug; S.e = 0; S.a = 0; S.seq = {}; S.scores = new Map(); S.flash = new Map(); S.sessions = []; S.claims = [];
  S.apFeed = null; S.stats = null; S.map = []; S.mapSig = null; geo = null;
  $("activity").innerHTML = ""; $("thoughts").innerHTML = ""; $("now").innerHTML = ""; $("expLog").hidden = true; $("expResult").innerHTML = ""; $("teamBox").innerHTML = "";
  try {
    if (!S.st) await loadState();
    S.ov = await api(`/api/project?slug=${slug}`);
  } catch (e) {
    toast(esc(e.message), "err");
    location.hash = "#/";
    return;
  }
  document.querySelectorAll("#ptabs [data-ptab]").forEach((a) => { a.href = `#/p/${slug}/${a.dataset.ptab}`; });
  document.querySelectorAll('#ptabs [data-ptab="plan"]').forEach((a) => { a.hidden = false; });
  $("mapTitle").textContent = "Function map";
  $("mapHint").textContent = "Every square is a function, grouped by source file. Click one to see it.";
  $("thAddr").textContent = "File";
  groups.clear(); S.claimSig = "";
  L.q = ""; L.filter = "all"; L.limit = 200; $("fnSearch").value = "";
  $("instrEdit").value = S.ov.instructions || "";
  renderHeader(S.ov);
  markNav();
  const setup = !S.ov.ready;
  $("ptabs").hidden = setup;
  document.querySelectorAll("[data-pane]").forEach((p) => { p.hidden = true; });
  if (setup) {
    $("planPane").hidden = false;
    renderNativePlan();
    return;
  }
  setTab(tab);
  renderStats(S.ov);
  await refreshMap();
  await poll(true);
  S.timer = setInterval(() => poll(false), 1000);
  S.statsTimer = setInterval(loadStats, 8000);
  loadStats();
}

function stopPolling() {
  if (S.timer) clearInterval(S.timer);
  if (S.statsTimer) clearInterval(S.statsTimer);
  S.timer = null; S.statsTimer = null;
}

function setTab(tab) {
  if (!TABS.includes(tab)) tab = "overview";
  S.tab = tab;
  document.querySelectorAll("#ptabs [data-ptab]").forEach((a) => { a.classList.toggle("on", a.dataset.ptab === tab); a.setAttribute("aria-selected", a.dataset.ptab === tab); });
  if (S.ov && !S.ov.ready) return;
  document.querySelectorAll("[data-pane]").forEach((p) => { p.hidden = p.dataset.pane !== tab; });
  if (tab === "plan" && S.ov && S.ov.kind === "native") { renderNativePlan(); return; }
  if (tab === "overview") { if (S.map.length) layoutMap(); renderOverview(); }
  if (tab === "functions") renderList();
  if (tab === "agents") { renderLauncher($("launcher")); renderSessions(S.sessions); renderPrio(); }
  if (tab === "source" && S.ov) renderSource(S.ov);
  if (tab === "settings") renderProjectSettings();
}
document.querySelectorAll("[data-goto]").forEach((a) => {
  a.onclick = (e) => {
    e.preventDefault();
    if (a.dataset.filter) { L.filter = a.dataset.filter; L.limit = 200; }
    location.hash = `#/p/${S.slug}/${a.dataset.goto}`;
  };
});

/* The whole map only when something changed (`force`: a rename or a split, which the signature can't see). */
async function refreshMap(force = true) {
  const slug = S.slug;
  const data = await api(`/api/map?slug=${slug}${!force && S.mapSig ? `&since=${encodeURIComponent(S.mapSig)}` : ""}`);
  if (slug !== S.slug) return;
  S.lastMapFetch = Date.now();
  if (data.same) return;
  S.mapSig = data.sig;
  S.map = data.rows.map((r) => { const f = {}; data.keys.forEach((k, i) => { f[k] = r[i]; }); return f; });
  S.byName = new Map(S.map.map((f, i) => [f.name, i]));
  S.map.forEach((f, i) => { f.i = i; });
  baseDirty = true;
  $("fnTabCount").textContent = S.map.length.toLocaleString();
  if (S.tab === "overview") layoutMap(); else applyClaims(false);
  renderList();
  renderProgress();
  renderOverview();
}

/* Helpers that just stopped on an error (the provider out of credit, a sign-in...): said once per error, as eight
   agents on one account stop together */
function toastStopped(before, now) {
  const was = new Map(before.map((s) => [s.id, s.state]));
  const why = new Map();
  for (const s of now) {
    if (s.state !== "error" || !was.has(s.id) || was.get(s.id) === "error") continue;
    if (!why.has(s.error)) why.set(s.error, []);
    why.get(s.error).push(s.label);
  }
  for (const [error, labels] of why) {
    const who = labels.length > 1 ? `${labels[0]} and ${labels.length - 1} more` : labels[0];
    toast(`${esc(who)} stopped: ${esc(error || "an error")}`, "err");
  }
}

let polling = false;
async function poll(first) {
  if (polling || !S.slug) return;
  polling = true;
  const slug = S.slug;
  try {
    const live = await api(`/api/live?slug=${slug}&e=${S.e}&a=${S.a}&s=${encodeURIComponent(JSON.stringify(S.seq))}`);
    if (slug !== S.slug) return;
    S.ov = live.overview;
    let mapDirty = false;
    for (const ev of live.events) {
      S.e = Math.max(S.e, ev.id);
      if (["match", "split", "rename"].includes(ev.kind)) mapDirty = true;
      if (ev.kind === "match" && !first) {
        S.flash.set(ev.detail, performance.now());
        if (ev.agent !== AUTO && ev.agent !== "@" + AUTO) toast(`<code>${esc(ev.detail)}</code>&nbsp;matched by ${esc(ev.agent || "an agent")}`, "match");
      }
      if (ev.kind === "autopilot" && !first) toast(`Autopilot: ${esc(ev.detail)}`, "match");
      if (ev.kind === "link" && !first) toast(`🔗 <code>${esc(ev.detail)}</code>&nbsp;is linked into the game`, "match");
    }
    for (const at of live.attempts) {
      S.a = Math.max(S.a, at.id);
      if (!S.scores.has(at.function)) S.scores.set(at.function, []);
      S.scores.get(at.function).push({ score: at.score, t: at.created_at, insns: at.n_insns });
    }
    if (!first) applyAttempts(live.attempts);
    addActivity(live.events, live.attempts, first);
    S.claims = live.claims;
    if (!first) toastStopped(S.sessions || [], live.sessions);
    S.sessions = live.sessions;
    for (const s of live.sessions) {
      if (s.feed.length) S.seq[s.id] = s.feed[s.feed.length - 1].seq;
    }
    addThoughts(live.sessions, first);
    if (S.tab === "agents") renderSessions(live.sessions);
    renderNow(live.claims);
    renderStats(live.overview);
    const claimSig = live.claims.map((c) => c.name + "\u0000" + c.agent).join("\n");
    if (mapDirty || Date.now() - S.lastMapFetch > 20000) await refreshMap(mapDirty);
    else {
      applyClaims();
      if (claimSig !== S.claimSig || live.attempts.length) renderList();
    }
    S.claimSig = claimSig;
    if (S.fn && !$("drawer").hidden) {
      const touched = live.attempts.some((a) => a.function === S.fn) || live.events.some((e) => e.detail === S.fn);
      if (touched) refreshFn(false); else fnBadge();
    }
    $("feedHint").textContent = "";
  } catch (e) {
    if (String(e.message).includes("Failed to fetch")) $("feedHint").textContent = "app not reachable";
  } finally {
    polling = false;
  }
}

async function loadStats() {
  if (!S.slug || S.tab !== "overview") return;
  try { S.stats = await api(`/api/stats?slug=${S.slug}`); } catch { return; }
  renderOverview();
}

/* Agents at work on this project: the helpers this app runs, plus outside agents (yours) with a claim. */
function workingAgents() {
  const running = S.sessions.filter((s) => ["starting", "working", "waiting"].includes(s.state));
  const own = new Set(S.sessions.map((s) => s.agent));
  const outside = [...new Set(S.claims.filter((c) => !own.has(c.agent) && c.agent !== AUTO).map((c) => c.agent))];
  return { running, outside, n: running.length + outside.length };
}

/* recommended | beta | "" for a platform key, as the browser or a project names it. */
function platformStatus(p) {
  const st = (S.st && S.st.platform_status) || {};
  const key = { gcwii: "gc", ps: "psx", playstation: "psx" }[p] || p;
  return st[key] || "";
}
function markPlatforms() {
  const any = Object.keys((S.st && S.st.platform_status) || {}).length;
  document.querySelectorAll("#platRow [data-p]").forEach((s) => {
    const rec = platformStatus(s.dataset.p) === "recommended";
    s.classList.toggle("rec", rec);
    s.title = rec ? "Recommended: the most tested path to a full decomp you can port and mod" : "Beta: works, less tested on real games";
    if (rec && !s.querySelector(".rec-mark")) s.insertAdjacentHTML("afterbegin", `<span class="rec-mark">★</span>`);
  });
  $("platLegend").hidden = !any;
}

function renderHeader(ov) {
  const chips = [`<span class="plat">${esc(ov.platform_name || "?")}</span>`];
  if (ov.binary && ov.binary.debug) chips.push(`<span class="chip-s">${esc(ov.binary.debug)}</span>`);
  if (ov.compiler && ov.compiler.name) chips.push(`<span class="chip-s" title="${esc((ov.compiler.flags || []).join(" ") || ov.compiler.command || "")}">${esc(ov.compiler.name)}</span>`);
  $("phChips").innerHTML = chips.join("");
  $("phTitle").textContent = ov.title;
  const pct = ov.bytes ? (100 * ov.matched_bytes) / ov.bytes : 0;
  $("phPct").textContent = pctNum(pct);
  $("phBar").style.width = pct + "%";
  $("phSub").textContent = `${ov.matched.toLocaleString()} / ${ov.functions.toLocaleString()} functions · ${plural(ov.attempts || 0, "compile")}${S.today ? ` · ${S.today} matched today` : ""}`;
  const w = workingAgents();
  $("phWorking").hidden = !w.n;
  $("phWorkingText").textContent = `${w.n} agent${w.n === 1 ? "" : "s"} working`;
  $("phStartText").textContent = w.running.length ? "Add agents" : "Start agents";
  $("agTabCount").textContent = w.n || "";
}
$("phWorking").onclick = () => { location.hash = `#/p/${S.slug}/agents`; };

$("phFolder").onclick = () => openFolder();


function renderStats(ov) {
  renderHeader(ov);
  const pct = ov.bytes ? (100 * ov.matched_bytes) / ov.bytes : 0;
  $("pct").textContent = pctNum(pct);
  $("pctSub").textContent = (ov.bytes ? `${bytes(ov.matched_bytes)} of ${bytes(ov.bytes)}` : "") + (S.today ? ` · ${S.today} matched today` : "");
  $("fnCount").textContent = `${ov.matched.toLocaleString()} / ${ov.functions.toLocaleString()}`;
  renderAutopilot(ov);
  renderSteering(ov);
  if (S.tab === "source") renderSource(ov);
  renderCompilerNotice(ov);
  renderAgentsKpi(ov);
  renderNext(ov);
}

function renderCompilerNotice(ov) {
  // Native projects carry no per-compiler install notice: the plan screen shows the resolved driver
  // and the flags card edits them. Keep the hook so renderStats stays uniform.
  $("compilerNotice").hidden = true;
}

function fnCounts() {
  const c = { matched: 0, working: 0, tried: 0, open: 0, asm: 0, library: 0 };
  for (const f of S.map) c[fnState(f)]++;
  return c;
}

/* The overview's numbers: function states, pace, who matched what, recent matches. */
function renderOverview() {
  if (!S.ov || S.tab !== "overview") return;
  const c = fnCounts(), total = Math.max(1, S.map.length);
  const seg = (k, cls) => (c[k] ? `<i class="${cls}" data-w="${(100 * c[k]) / total}" title="${c[k]} ${k === "open" ? "to do" : k}"></i>` : "");
  $("fnStack").innerHTML = seg("matched", "s-match") + seg("working", "s-work") + seg("tried", "s-tried") + seg("asm", "s-asm") + seg("open", "s-open");
  setWidths($("fnStack"));
  const togo = S.ov.functions - S.ov.matched;
  $("fnSub").textContent = `${togo.toLocaleString()} to go${c.tried ? ` · ${c.tried.toLocaleString()} tried` : ""}${c.working ? ` · ${c.working} in progress` : ""}${c.asm ? ` · ${c.asm} assembly` : ""}`;
  const st = S.stats;
  if (st) {
    const ph = st.matches_per_hour, max = Math.max(1, ...ph);
    const last3 = ph.slice(-3).reduce((a, b) => a + b, 0) / 3;
    $("paceNum").textContent = `${ph[23]}`;
    $("paceBars").innerHTML = ph.map((n, i) => `<rect x="${i * 10 + 1}" y="${28 - Math.max(n ? 3 : 1, (26 * n) / max)}" width="8" height="${Math.max(n ? 3 : 1, (26 * n) / max)}" rx="1.5" class="${n ? "on" : ""}"><title>${n} matched ${23 - i ? `${23 - i} h ago` : "this hour"}</title></rect>`).join("");
    $("paceSub").textContent = `matched in the last hour · ${plural(st.compiles_last_hour, "compile")}` + (last3 > 0 && togo > 0 ? ` · ≈ ${duration(togo / last3)} to go at this pace` : "");
    $("board").innerHTML = st.agents.length ? st.agents.slice(0, 8).map((r) => `<li><span class="who">${esc(r.agent)}</span><span class="grow"></span>
        <span class="mono small">${r.matched ? `<b class="ok">${r.matched.toLocaleString()}</b> matched · ` : ""}${plural(r.compiles, "compile")}</span></li>`).join("")
      : `<li class="muted small">Nobody yet. Matches by agents, the autopilot and you show up here.</li>`;
  }
  const recent = S.map.filter((f) => f.status === "matched" && f.matched_at).sort((a, b) => b.matched_at - a.matched_at).slice(0, 8);
  $("recentMatches").innerHTML = recent.length ? recent.map((f) => `<li><span class="ok">✓</span>${fnLink(f.name)}<span class="grow"></span><span class="muted small">${esc(f.matched_by || "")} · ${esc(since(f.matched_at))}</span></li>`).join("")
    : `<li class="muted small">No matches yet.</li>`;
  $("recentMatches").querySelectorAll(".fn").forEach((x) => { x.onclick = () => openFn(x.dataset.fn); });
}

function renderAgentsKpi(ov) {
  const w = workingAgents();
  $("agNum").textContent = w.n;
  const names = [...w.running.map((s) => s.label), ...w.outside];
  $("agSub").textContent = names.length ? names.slice(0, 4).join(", ") + (names.length > 4 ? ` +${names.length - 4}` : "") : "none working right now";
  const sp = ov.spend, n = ov.helper_matches || 0, budget = S.st?.settings?.budget_usd || 0;
  $("spendSub").title = "cumulative tokens billed across every model call — each agent turn re-sends the conversation";
  $("spendSub").textContent = sp && sp.usd ? `${money(sp.usd)} spent${n ? ` · ${money(sp.usd / n)} per match` : ""}${budget ? ` · budget ${money(budget)}` : ""}`
    : sp && sp.tokens ? `${(sp.tokens / 1000).toFixed(0)}k tokens used` + (n ? "" : " so far") : budget ? `budget ${money(budget)}` : "";
}

/* What to do next, so a first project is plug and play. */
function renderNext(ov) {
  const box = $("nextStep");
  const w = workingAgents();
  const done = ov.functions > 0 && ov.matched >= ov.functions;
  if (done) {
    box.hidden = false;
    box.innerHTML = `<div class="next-text"><b>Every function matches.</b><span class="muted small">Export the project: a source tree that rebuilds your program byte for byte.</span></div><a class="primary small-btn as-btn" href="#/p/${esc(S.slug)}/source">Export</a>`;
    return;
  }
  if (w.n || !S.st || !ov.ready) { box.hidden = true; return; }
  launcherInit();
  const a = S.st.agents.find((x) => x.id === LZ.kind);
  const ap = ov.autopilot;
  const steps = [`<span class="ok">✓</span> Analysed: ${plural(ov.functions, "function")}`];
  if (ap) steps.push(ap.state === "running" ? `<span class="spin-dot"></span> Autopilot trying machine drafts` : `<span class="ok">✓</span> Autopilot: ${ap.matched.toLocaleString()} free match${ap.matched === 1 ? "" : "es"}`);
  steps.push(`<span class="todo">○</span> Agents`, `<span class="todo">○</span> Export`);
  box.hidden = false;
  box.innerHTML = `<div class="next-text"><b>Next: start your agents</b><span class="steps-line">${steps.join("")}</span></div>
    ${a && (a.installed || a.id === "api") ? `<button class="primary" id="nextGo" type="button">${esc(launchLabel(a, LZ.model, LZ.count))}</button>` : ""}
    <button class="ghost" id="nextPick" type="button">Choose agent &amp; model</button>`;
  const go = $("nextGo");
  if (go) go.onclick = () => a.id !== "api" ? startAgents(a, LZ.model, LZ.count, go)
    : (LZ.eps || []).length ? startAgents(a, "", LZ.count, go, { endpoints: LZ.eps }) : showLaunch();
  $("nextPick").onclick = (e) => { e.stopPropagation(); showLaunch(); };
}

function uploadFile(url, file, onProgress) {
  return new Promise((resolve, reject) => {
    const x = new XMLHttpRequest();
    x.open("POST", url);
    x.setRequestHeader("X-Decomp", "1");
    x.setRequestHeader("Content-Type", "application/octet-stream");
    x.upload.onprogress = (e) => { if (e.lengthComputable) onProgress(e.loaded / e.total); };
    x.onload = () => {
      let data = null;
      try { data = JSON.parse(x.responseText); } catch { /* not json */ }
      if (x.status >= 200 && x.status < 300) resolve(data); else reject(new Error((data && data.error) || `upload failed (${x.status})`));
    };
    x.onerror = () => reject(new Error("upload failed"));
    x.send(file);
  });
}

/* ------------------------------------------------------------------ map */
let colors = null, geo = null, animating = false;

function cssColor(name) {
  const probe = document.createElement("i");
  probe.style.color = `var(${name})`;
  document.body.append(probe);
  const rgb = getComputedStyle(probe).color.match(/\d+(\.\d+)?/g).slice(0, 3).map(Number);
  probe.remove();
  return rgb;
}
function readColors() {
  colors = { open: cssColor("--open"), tried: cssColor("--tried"), work: cssColor("--work"), match: cssColor("--match"), hi: cssColor("--match-hi"), ink: cssColor("--ink") };
}
const mix = (a, b, t) => a.map((v, i) => Math.round(v + (b[i] - v) * t));
const rgb = (c, a = 1) => `rgba(${c[0]},${c[1]},${c[2]},${a})`;

function layoutMap() {
  const wrap = $("mapWrap"), canvas = $("map");
  if (!wrap.clientWidth) return;  // not on screen: laid out when the overview shows
  const w = Math.max(200, wrap.clientWidth - 32), n = Math.max(1, S.map.length);
  let size = Math.floor(Math.sqrt((w * 300) / n));
  size = Math.max(5, Math.min(26, size));
  const gap = size >= 12 ? 3 : 2;
  const cols = Math.max(1, Math.floor((w + gap) / (size + gap)));
  const rows = Math.ceil(n / cols);
  const h = rows * (size + gap) - gap;
  const dpr = window.devicePixelRatio || 1;
  canvas.width = Math.round(w * dpr); canvas.height = Math.round(h * dpr);
  canvas.style.height = h + "px";
  geo = { size, gap, cols, w, h, dpr };
  mapChanged();
  applyClaims();
}

function applyClaims(draw = true) {
  const working = new Map(S.claims.map((c) => [c.name, c.agent]));
  let changed = false;
  for (const f of S.map) {
    // only states claims can move; library stays library
    const status = f.status === "matched" || f.status === "asm" || f.status === "library" ? f.status
      : working.has(f.name) ? "working" : "open";
    if (status !== f.status) { f.status = status; changed = true; }
    f.agent = working.get(f.name) || null;
  }
  if (changed) mapChanged();
  if (draw) drawMap();
}

/* New attempts, as the live feed brings them: each function's tries and best score, without a refetch. */
function applyAttempts(attempts) {
  for (const at of attempts) {
    const i = S.byName && S.byName.get(at.function);
    if (i == null) continue;
    const f = S.map[i];
    f.attempts = (f.attempts || 0) + 1;
    if (at.score != null && (f.best == null || at.score < f.best)) { f.best = at.score; mapChanged(); }
  }
}

function cellColor(f) {
  if (f.status === "matched") return [colors.match, 1];
  if (f.status === "asm") return [colors.tried, 0.35];
  if (f.status === "library") return [colors.tried, 0.22];  // glue: visible but not a dot to work on
  if (f.best != null) return [mix(colors.tried, colors.hi, Math.pow(pctOf(f.best, f.insns) || 0, 3)), 1];
  return [colors.open, 1];
}

function drawBase() {
  const { size, gap, cols, dpr } = geo;
  base = base || document.createElement("canvas");
  base.width = $("map").width; base.height = $("map").height;
  const ctx = base.getContext("2d");
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  const r = size >= 10 ? 2.5 : size >= 7 ? 1.5 : 1;
  moving = [];
  S.map.forEach((f, i) => {
    if (f.status === "working") { moving.push(i); return; }  // drawn every frame, pulsing
    const x = (i % cols) * (size + gap), y = Math.floor(i / cols) * (size + gap);
    const [c, a] = cellColor(f);
    ctx.fillStyle = rgb(c, a);
    ctx.beginPath(); ctx.roundRect(x, y, size, size, r); ctx.fill();
  });
  baseDirty = false;
}

function drawMap() {
  if (!geo || S.tab !== "overview") return;
  if (!colors) readColors();
  if (baseDirty || !base || base.width !== $("map").width || base.height !== $("map").height) drawBase();
  const ctx = $("map").getContext("2d");
  const { size, gap, cols, dpr } = geo;
  const now = performance.now();
  ctx.setTransform(1, 0, 0, 1, 0, 0);
  ctx.clearRect(0, 0, $("map").width, $("map").height);
  ctx.drawImage(base, 0, 0);
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  const r = size >= 10 ? 2.5 : size >= 7 ? 1.5 : 1;
  const at = (i) => [(i % cols) * (size + gap), Math.floor(i / cols) * (size + gap)];
  let live = moving.length > 0;
  for (const i of moving) {
    const [x, y] = at(i);
    ctx.fillStyle = rgb(colors.work, 0.55 + 0.45 * Math.sin(now / 260 + i));
    ctx.beginPath(); ctx.roundRect(x, y, size, size, r); ctx.fill();
  }
  for (const [name, fl] of S.flash) {
    const i = S.byName && S.byName.get(name), t = (now - fl) / 1600;
    if (i == null || t >= 1) { S.flash.delete(name); continue; }
    live = true;
    const [x, y] = at(i), g = size * (0.6 + 1.8 * t);
    ctx.strokeStyle = rgb(colors.match, 1 - t);
    ctx.lineWidth = 2;
    ctx.beginPath(); ctx.roundRect(x - g / 2, y - g / 2, size + g, size + g, r + 2); ctx.stroke();
  }
  const sel = S.fn && S.byName ? S.byName.get(S.fn) : null;
  if (sel != null) { const [x, y] = at(sel); ctx.strokeStyle = rgb(colors.ink, 0.9); ctx.lineWidth = 1.5; ctx.strokeRect(x - 1.5, y - 1.5, size + 3, size + 3); }
  if (live && !animating) {  // about 30 frames a second is plenty for a pulse
    animating = true;
    setTimeout(() => requestAnimationFrame(() => { animating = false; drawMap(); }), 33);
  }
}

function mapIndexAt(ev) {
  if (!geo) return -1;
  const rect = $("map").getBoundingClientRect();
  const x = ev.clientX - rect.left, y = ev.clientY - rect.top;
  const col = Math.floor(x / (geo.size + geo.gap)), row = Math.floor(y / (geo.size + geo.gap));
  if (col < 0 || col >= geo.cols || x % (geo.size + geo.gap) > geo.size || y % (geo.size + geo.gap) > geo.size) return -1;
  const i = row * geo.cols + col;
  return i < S.map.length ? i : -1;
}
$("map").addEventListener("mousemove", (ev) => {
  const i = mapIndexAt(ev), tip = $("tip");
  if (i < 0) { tip.hidden = true; return; }
  const f = S.map[i];
  const p = pctOf(f.best, f.insns);
  const status = f.status === "matched" ? `matched${f.matched_by ? " by " + esc(f.matched_by) : ""}` : f.status === "working" ? `${esc(f.agent)} is on it` : f.best != null ? `best ${pctText(p)}` : "not started";
  const where = S.ov && S.ov.kind === "fork" ? esc(f.unit || "") : hex8(f.vram);
  tip.innerHTML = `<b>${esc(f.name)}</b><br>${where} · ${f.insns} instructions<br>${status}`;
  tip.hidden = false;
  const wrap = $("mapWrap").getBoundingClientRect();
  let left = ev.clientX - wrap.left + 14, top = ev.clientY - wrap.top + 14;
  if (left + 240 > wrap.width) left -= 260;
  tip.style.left = left + "px"; tip.style.top = top + "px";
});
$("map").addEventListener("mouseleave", () => { $("tip").hidden = true; });
$("map").addEventListener("click", (ev) => { const i = mapIndexAt(ev); if (i >= 0) openFn(S.map[i].name); });
let resizeT = null;
window.addEventListener("resize", () => { clearTimeout(resizeT); resizeT = setTimeout(() => { if (S.map.length && S.tab === "overview") layoutMap(); }, 120); });
matchMedia("(prefers-color-scheme: dark)").addEventListener("change", () => { colors = null; baseDirty = true; drawMap(); });

/* ------------------------------------------------------------------ now working */
function spark(points, w = 240, h = 34) {
  const vals = points.filter((p) => p.score != null);
  if (!vals.length) return `<svg viewBox="0 0 ${w} ${h}"></svg>`;
  const max = Math.max(...vals.map((p) => p.score), 1);
  const step = vals.length > 1 ? w / (vals.length - 1) : 0;
  const pts = vals.map((p, i) => [i * step, 3 + (h - 6) * (p.score / max)]);
  const d = pts.map(([x, y], i) => `${i ? "L" : "M"}${x.toFixed(1)},${y.toFixed(1)}`).join("");
  const last = pts[pts.length - 1];
  const done = vals[vals.length - 1].score === 0;
  return `<svg viewBox="0 0 ${w} ${h}" preserveAspectRatio="none"><path d="${d}" fill="none" stroke="var(${done ? "--match" : "--work"})" stroke-width="1.6" vector-effect="non-scaling-stroke"/>
    <circle cx="${last[0]}" cy="${last[1]}" r="2.6" fill="var(${done ? "--match" : "--work"})"/></svg>`;
}

/* No compile yet: the agent is reading (the function, its file, look-alikes), for this long so far */
function reading(c) {
  const min = c.claimed_at ? Math.floor((Date.now() / 1000 - c.claimed_at) / 60) : 0;
  return min >= 1 ? `reading · ${min} min` : "reading";
}

function renderNow(claims) {
  const box = $("now");
  claims = claims.filter((c) => c.agent !== AUTO);
  if (!claims.length) { box.innerHTML = ""; return; }
  box.innerHTML = claims.map((c) => {
    const sc = S.scores.get(c.name) || [];
    const p = pctOf(c.best_score, c.n_insns);
    const [sym, unit] = c.name.split(/@(.*)/s);  // a fork's symbol@file: the symbol first, the file after it
    return `<div class="job" data-fn="${esc(c.name)}"><div class="job-top"><span class="job-name" title="${esc(c.name)}">${esc(sym)}${unit ? `<small>@${esc(unit)}</small>` : ""}</span><span class="job-who" title="${esc(c.agent)}">${esc(c.agent)}</span></div>
      ${spark(sc)}<div class="job-foot"><span>${c.n_insns} insns · ${c.attempts} tries</span><b>${p == null ? reading(c) : pctText(p)}</b></div></div>`;
  }).join("");
  box.querySelectorAll(".job").forEach((j) => { j.onclick = () => openFn(j.dataset.fn); });
}

/* ------------------------------------------------------------------ agents on this project */
const STATE_TEXT = { starting: "starting…", working: "working", waiting: "next session in a moment", stopped: "stopped", error: "stopped with an error" };

function renderSessions(sessions) {
  const box = $("sessions");
  const board = new Map((S.stats?.agents || []).map((r) => [r.agent, r]));
  const running = sessions.filter((s) => ["starting", "working", "waiting"].includes(s.state));
  $("stopAll").hidden = running.length < 2;
  box.innerHTML = sessions.map((s) => {
    const claim = S.claims.find((c) => c.agent === s.agent);
    const dot = s.state === "error" ? "err" : s.state === "working" ? "on" : s.state === "stopped" ? "" : "work";
    const live = ["starting", "working", "waiting"].includes(s.state);
    const b = board.get(s.agent);
    const facts = [s.model ? esc(s.model) : "default model", s.runs ? `session ${s.runs}` : "", b && b.matched ? `<b class="ok">${b.matched} matched</b>` : "", b ? plural(b.compiles, "compile") : "",
      s.usd ? money(s.usd) : s.tokens ? `${(s.tokens / 1000).toFixed(0)}k tokens` : "", s.started_at ? `since ${clock(s.started_at).slice(0, 5)}` : ""].filter(Boolean);
    return `<div class="session"><div class="session-top"><span class="dot ${dot}"></span><b>${esc(s.label)}</b>
        <span class="state ${s.state === "error" ? "err" : ""}">${esc(STATE_TEXT[s.state] || s.state)}</span>
        <button class="ghost" data-stop="${esc(s.id)}" data-remove="${live ? "" : "1"}" type="button">${live ? "Stop" : "Remove"}</button></div>
      <span class="facts-line">${facts.join(" · ")}</span>
      ${s.state === "error" ? `<span class="state err">${esc(s.error)}</span>` : ""}
      ${claim ? `<span class="last">on ${fnLink(claim.name)}</span>` : ""}</div>`;
  }).join("");
  const own = new Set(sessions.map((s) => s.agent));
  const outside = [...new Set(S.claims.filter((c) => !own.has(c.agent) && c.agent !== AUTO).map((c) => c.agent))];
  box.insertAdjacentHTML("beforeend", outside.map((a) => `<div class="session ext"><div class="session-top"><span class="dot on"></span><b>${esc(a)}</b><span class="tag">${a.startsWith("@") ? "in the room" : "connected agent"}</span>
      <button class="ghost" data-release="${esc(a)}" title="hand back the function(s) this agent still holds" type="button">Release</button></div>
      <span class="last">on ${S.claims.filter((c) => c.agent === a).map((c) => fnLink(c.name)).join(", ")}</span></div>`).join(""));
  box.querySelectorAll(".fn").forEach((x) => { x.onclick = () => openFn(x.dataset.fn); });
  $("noSessions").hidden = sessions.length + outside.length > 0;
  box.querySelectorAll("[data-release]").forEach((b) => {
    b.onclick = async () => {
      const r = await api("/api/agents/stop", { method: "POST", body: { slug: S.slug, agent: b.dataset.release } }).catch((e) => toast(esc(e.message), "err"));
      if (r) toast(r.released && r.released.length ? `Released ${plural(r.released.length, "function")}.` : "Nothing left to release.");
      poll(false);
    };
  });
  box.querySelectorAll("[data-stop]").forEach((b) => {
    b.onclick = async () => {
      await api("/api/agents/stop", { method: "POST", body: { id: b.dataset.stop, remove: !!b.dataset.remove } }).catch((e) => toast(esc(e.message), "err"));
      poll(false);
    };
  });
}
$("stopAll").onclick = async () => {
  await api("/api/agents/stop", { method: "POST", body: { slug: S.slug } }).catch((e) => toast(esc(e.message), "err"));
  toast("Stopping every agent on this project.");
  poll(false);
};

/* ------------------------------------------------------------------ the launcher: agent, model, how many */
const LZ = { kind: null, model: "", count: 1, per: null };
function launcherInit() {
  if (LZ.kind || !S.st) return;
  const l = S.st.settings.launcher || {};
  const ready = S.st.agents.filter((a) => a.installed && a.id !== "api");
  const known = S.st.agents.find((a) => a.id === l.kind && (a.installed || a.id === "api"));
  LZ.kind = known ? known.id : (ready[0] ? ready[0].id : "api");
  LZ.model = known ? (l.model || "") : "";
  LZ.count = l.count || 1;
  const eps = S.st.settings.endpoints || [];
  LZ.eps = (l.endpoints || []).filter((id) => eps.some((e) => e.id === id));
  if (!LZ.eps.length && eps.length) LZ.eps = [eps[0].id];
}
function modelOptions(a) {
  const recent = (S.st.settings.recent_models || {})[a.id] || [];
  const opts = [{ id: "", name: a.default_model ? `Default · ${a.default_model}` : "Default", note: "" }];
  for (const m of a.models || []) opts.push(m);
  for (const r of recent) if (!opts.some((o) => o.id === r)) opts.push({ id: r, name: r, note: "used before" });
  return opts;
}
function modelName(a, model) {
  if (!model) return "";
  const m = (a.models || []).find((x) => x.id === model);
  return m ? m.name : model;
}
function launchLabel(a, model, count) {
  if (a.id === "api") {
    const picked = (S.st.settings.endpoints || []).filter((e) => (LZ.eps || []).includes(e.id));
    if (picked.length > 1) return `Start ${count} across ${picked.length} endpoints`;
    return `Start ${picked[0] ? picked[0].name : "API model"}${count > 1 ? ` × ${count}` : ""}`;
  }
  return `Start ${a.name}${model ? ` · ${modelName(a, model)}` : ""}${count > 1 ? ` × ${count}` : ""}`;
}

async function startAgents(a, model, count, btn, extra = {}) {
  if (btn) btn.disabled = true;
  try {
    const options = { ...extra };
    if (model && a.id !== "api") options.model = model;
    if (LZ.per) options.per_session = LZ.per;
    await api("/api/agents/start", { method: "POST", body: { kind: a.id, slug: S.slug, count, options } });
    S.st.settings.launcher = { kind: a.id, model: model || "", count };
    if (model && a.id !== "api") {
      const rec = (S.st.settings.recent_models ||= {});
      rec[a.id] = [model, ...(rec[a.id] || []).filter((m) => m !== model)].slice(0, 8);
    }
    hideLaunch();
    toast(`${esc(a.id === "api" ? "Your API model" : a.name)} ${count > 1 ? `× ${count} are` : "is"} starting. Watch it on the map and in Activity.`, "match");
    poll(false);
    loadNav();
  } catch (e) { toast(esc(e.message), "err"); } finally { if (btn) btn.disabled = false; }
}

function renderLauncher(box, compact = false) {
  if (!box || !S.st) return;
  launcherInit();
  const list = S.st.agents;
  const a = list.find((x) => x.id === LZ.kind) || list[0];
  const kinds = list.map((x) => `<button type="button" class="lz-kind ${x.id === a.id ? "on" : ""}" data-k="${esc(x.id)}">
      <b>${esc(x.name)}</b><span>${x.id === "api" ? "DeepSeek, OpenRouter, Ollama…" : x.installed ? esc(x.version ? x.version.replace(/\s*\(.*\)/, "") : x.vendor) : "not installed"}</span>
      ${x.installed || x.id === "api" ? "" : `<em>install</em>`}</button>`).join("");
  let body = "";
  if (!a.installed) {
    body = `<p class="small"><b>${esc(a.name)}</b> isn't installed on this computer.${a.needs ? ` It needs ${esc(a.needs)} first.` : ""}</p>
      ${a.install ? cmdBox(a.install) : ""}
      <div class="row"><button class="primary" data-act="install" type="button" ${a.needs ? "disabled" : ""}>Install it for me</button><a class="link small" href="${esc(a.docs)}" target="_blank" rel="noopener">About ${esc(a.name)}</a></div>
      <p class="muted small">${esc(a.signin)}</p><pre class="joblog" data-log hidden></pre>`;
  } else if (a.id === "api") {
    const eps = S.st.settings.endpoints || [];
    LZ.eps = (LZ.eps || []).filter((id) => eps.some((e) => e.id === id));
    if (!LZ.eps.length && eps.length) LZ.eps = [eps[0].id];
    body = eps.length && !LZ.adding ? `<div class="ep-pick">${eps.map((e) => `<label class="check inline"><input type="checkbox" data-ep="${esc(e.id)}" ${LZ.eps.includes(e.id) ? "checked" : ""}>
        <span><b>${esc(e.name)}</b> <span class="mono small">${esc(e.model)}</span><br><span class="muted small mono">${esc(hostOf(e.base_url))}${e.max_sessions ? ` · at most ${e.max_sessions} at once` : ""}</span></span></label>`).join("")}</div>
      <p class="muted small">${eps.length > 1 ? "Tick several to spread the sessions across them. " : ""}<a class="link" href="#/agents">Manage endpoints</a> · <button type="button" class="link-btn" data-act="add-ep">Add one</button></p>`
      : `<div class="lz-fields">${endpointFields({ provider: "deepseek" }, compact)}</div>${eps.length ? `<p class="muted small"><button type="button" class="link-btn" data-act="pick-ep">Back to your endpoints</button></p>` : ""}`;
  } else {
    const opts = modelOptions(a);
    const known = opts.some((o) => o.id === LZ.model);
    body = `<label class="field"><span>Model</span><select data-f="model">${opts.map((o) => `<option value="${esc(o.id)}" ${known && o.id === LZ.model ? "selected" : ""}>${esc(o.name)}${o.note ? ` — ${esc(o.note)}` : ""}</option>`).join("")}
        <option value="__other" ${known ? "" : "selected"}>Another model…</option></select></label>
      <input data-f="custom" class="mono lz-custom" placeholder="model name, as ${esc(a.name)} calls it" value="${known ? "" : esc(LZ.model)}" ${known ? "hidden" : ""}>`;
  }
  const ready = a.installed;
  box.innerHTML = `<div class="lz-kinds">${kinds}</div>
    <div class="lz-body">${body}
      ${ready ? `<div class="lz-row">
        <div class="field"><span>How many</span><span class="stepper"><button type="button" data-step="-1">−</button><output>${LZ.count}</output><button type="button" data-step="1">+</button></span></div>
        ${compact ? "" : `<label class="field"><span>Functions per session</span><input data-f="per" type="number" min="1" max="20" value="${LZ.per || S.st.settings.per_session || 1}"></label>`}
        <span class="grow"></span>
        <button class="primary" data-act="start" type="button">${esc(launchLabel(a, LZ.model, LZ.count))}</button></div>
        <p class="muted small">${a.id === "api" ? "A built-in agent loop drives the model through the decomp tools." : esc(a.signin)} Each agent takes a different function; a fresh session every few functions keeps its context small.</p>` : ""}
    </div>`;
  wireCopies(box);
  const rerender = () => { renderLauncher(box, compact); if (box !== $("launcher") && S.tab === "agents") renderLauncher($("launcher")); };
  box.querySelectorAll(".lz-kind").forEach((b) => { b.onclick = () => { LZ.kind = b.dataset.k; LZ.model = (S.st.settings.launcher || {}).kind === LZ.kind ? S.st.settings.launcher.model || "" : ""; rerender(); }; });
  const sel = box.querySelector('select[data-f="model"]'), custom = box.querySelector('[data-f="custom"]');
  const label = () => { const btn = box.querySelector('[data-act="start"]'); if (btn) btn.textContent = launchLabel(a, LZ.model, LZ.count); };
  if (sel) sel.onchange = () => { if (sel.value === "__other") { custom.hidden = false; custom.focus(); LZ.model = custom.value.trim(); } else { custom.hidden = true; LZ.model = sel.value; } label(); };
  if (custom) custom.oninput = () => { LZ.model = custom.value.trim(); label(); };
  box.querySelectorAll("[data-step]").forEach((b) => { b.onclick = () => { LZ.count = Math.max(1, Math.min(8, LZ.count + Number(b.dataset.step))); box.querySelector(".stepper output").textContent = LZ.count; label(); }; });
  const per = box.querySelector('[data-f="per"]');
  if (per) per.onchange = () => { LZ.per = Math.max(1, Math.min(20, Number(per.value) || 4)); };
  wireEndpointFields(box);
  box.querySelectorAll("[data-ep]").forEach((c) => { c.onchange = () => { LZ.eps = [...box.querySelectorAll("[data-ep]:checked")].map((x) => x.dataset.ep); label(); }; });
  const addEp = box.querySelector('[data-act="add-ep"]'), pickEp = box.querySelector('[data-act="pick-ep"]');
  if (addEp) addEp.onclick = () => { LZ.adding = true; rerender(); };
  if (pickEp) pickEp.onclick = () => { LZ.adding = false; rerender(); };
  const inst = box.querySelector('[data-act="install"]');
  if (inst) inst.onclick = async () => {
    const log = box.querySelector("[data-log]");
    log.hidden = false; inst.disabled = true;
    try {
      const { job } = await api("/api/agents/install", { method: "POST", body: { kind: a.id } });
      await followJob(job, log);
      toast(`${esc(a.name)} installed. ${esc(a.signin)}`, "match");
      await loadState();
      rerender();
    } catch (e) { toast(esc(e.message), "err"); inst.disabled = false; }
  };
  const go = box.querySelector('[data-act="start"]');
  if (go) go.onclick = async () => {
    if (a.id === "api") {
      if (box.querySelector('[data-f="prov"]')) {  // a new endpoint, typed in here: saved, then started on
        const before = new Set((S.st.settings.endpoints || []).map((e) => e.id));
        try { S.st.settings = await api("/api/settings", { method: "POST", body: { endpoint: endpointData(box) } }); } catch (e) { return toast(esc(e.message), "err"); }
        const added = (S.st.settings.endpoints || []).find((e) => !before.has(e.id));
        LZ.eps = added ? [added.id] : LZ.eps;
        LZ.adding = false;
      }
      if (!(LZ.eps || []).length) return toast("Tick an endpoint to start on.", "err");
      return startAgents(a, "", LZ.count, go, { endpoints: LZ.eps });
    }
    startAgents(a, LZ.model, LZ.count, go);
  };
}

/* API endpoints: OpenAI-compatible servers (DeepSeek, a llama.cpp box on the network...), each with its own address,
   model and key. The same fields in the launcher and on the Agents & models page. */
function hostOf(url) { return String(url || "").replace(/^\w+:\/\//, "").split("/")[0]; }
function endpointFields(e, compact = false) {
  const presets = S.st.api_presets, prov = presets[e.provider] ? e.provider : "custom";
  return `<label class="field"><span>Provider</span><select data-f="prov">${Object.entries(presets).map(([k, p]) => `<option value="${k}" ${k === prov ? "selected" : ""}>${esc(p.name)}</option>`).join("")}</select></label>
    <label class="field"><span>Model</span><input data-f="model" class="mono" value="${esc(e.model || presets[prov].model)}"></label>
    <label class="field wide"><span>API address</span><input data-f="base" class="mono" value="${esc(e.base_url || presets[prov].base_url)}" placeholder="http://gpu-box:8080/v1"></label>
    <label class="field wide"><span>API key (stored only on this computer, sent only to this address)</span><input data-f="key" type="password" placeholder="${e.has_key ? esc(e.api_key) : "paste your key (none for local models)"}" autocomplete="off"></label>
    ${compact ? "" : `<label class="field"><span>Name</span><input data-f="name" value="${esc(e.id ? e.name : "")}" placeholder="${esc(e.id ? e.name : "e.g. gpu-box")}"></label>
    <label class="field"><span>Context size (tokens)</span><input data-f="ctx" class="mono" inputmode="numeric" placeholder="automatic" value="${esc(String(e.context_tokens || ""))}"></label>
    <label class="field"><span>Sessions at once</span><input data-f="max" class="mono" inputmode="numeric" placeholder="no limit" value="${esc(String(e.max_sessions || ""))}"></label>`}`;
}
function wireEndpointFields(box) {
  box.querySelectorAll('[data-f="prov"]').forEach((sel) => {
    sel.onchange = () => {
      const p = S.st.api_presets[sel.value], scope = sel.closest(".ep-card, .lz-fields") || box;
      scope.querySelector('[data-f="model"]').value = p.model;
      scope.querySelector('[data-f="base"]').value = p.base_url;
    };
  });
}
function endpointData(scope, id = "") {
  const f = (k) => scope.querySelector(`[data-f="${k}"]`);
  const out = { provider: f("prov").value, base_url: f("base").value, model: f("model").value, api_key: f("key").value };
  if (id) out.id = id;
  if (f("name")) Object.assign(out, { name: f("name").value, context_tokens: f("ctx").value, max_sessions: f("max").value });
  return out;
}

function showLaunch() {
  if (!S.st || !S.slug) return;
  $("launchPop").hidden = false;
  renderLauncher($("launchPopBody"), true);
}
function hideLaunch() { $("launchPop").hidden = true; }
$("phStart").onclick = (e) => { e.stopPropagation(); if ($("launchPop").hidden) showLaunch(); else hideLaunch(); };
// (the path as clicked: choosing an agent re-renders the popover, so the clicked tile isn't in the page any more)
document.addEventListener("click", (e) => {
  if (!$("launchPop").hidden && !e.composedPath().some((el) => el.classList && el.classList.contains("pop-wrap"))) hideLaunch();
});

/* ------------------------------------------------------------------ feeds */
function fnLink(name) { return `<span class="fn" data-fn="${esc(name)}">${esc(name)}</span>`; }
function eventHtml(ev) {
  const who = `<span class="who">${esc(ev.agent || "")}</span>`;
  const d = ev.detail || "";
  switch (ev.kind) {
    case "claim": return `${who} started ${fnLink(d)}`;
    case "match": return `<span class="ok">✓</span> ${who} matched ${fnLink(d)}`;
    case "link": return `<span class="ok">🔗</span> ${esc(d)} is linked: the game builds from its C, byte for byte`;
    case "release": return `${who} set ${fnLink(d)} aside, with notes for the next agent`;
    case "expired": return `${fnLink(d)} was left unfinished`;
    case "context": return `${who} updated ${ev.agent ? "shared code" : "context"}: ${esc(d)}`;
    case "rename": return `${who} renamed ${esc(d)}`;
    case "split": return `${who} split ${esc(d)}`;
    case "files": return `${who ? who + " " : ""}gave code without a source file one: ${esc(d)}`;
    case "import": return `Analysed: ${esc(d)}`;
    case "compiler": return `compiler set to ${esc(d)}`;
    case "collab": return esc(d);
    default: return `${who} ${esc(ev.kind)} ${esc(d)}`;
  }
}
/* One line per agent and function, updated in place: "claude-1 · lerp · 4 compiles · best 87%" until it's matched. */
const groups = new Map();
function groupHtml(g) {
  const who = `<span class="who">${esc(g.agent || "")}</span>`;
  const p = pctOf(g.best, g.insns);
  if (g.matched) return `<span class="ok">✓</span> ${who} matched ${fnLink(g.fn)}${g.tries ? ` <span class="score">after ${plural(g.tries, "compile")}</span>` : ""}`;
  if (g.released) return `${who} set ${fnLink(g.fn)} aside, with notes for the next agent${g.tries ? ` <span class="score">${plural(g.tries, "compile")}${p != null ? ` · best ${pctText(p)}` : ""}</span>` : ""}`;
  if (!g.tries) return `${who} started ${fnLink(g.fn)}`;
  const last = g.lastScore === undefined ? "" : g.lastScore === null ? ` · <span class="bad">last one didn't compile</span>` : "";
  return `${who} working on ${fnLink(g.fn)} <span class="score">${plural(g.tries, "compile")}${p != null ? ` · best ${pctText(p)}` : ""}</span>${last}`;
}
function addLine(t, html, first) {
  const list = $("activity");
  const li = document.createElement("li");
  if (!first) li.className = "fresh";
  li.innerHTML = `<time>${clock(t)}</time><span>${html}</span>`;
  list.querySelector(".placeholder")?.remove();
  list.prepend(li);
  return li;
}
function touchGroup(agent, fn, t, change, first) {
  const key = agent + "\u0000" + fn;
  let g = groups.get(key);
  if (!g) { g = { agent, fn, tries: 0, best: null, insns: 1, li: null }; groups.set(key, g); }
  change(g);
  if (g.li && g.li.isConnected) {
    g.li.querySelector("time").textContent = clock(t);
    g.li.querySelector("span").innerHTML = groupHtml(g);
    if (g.li !== $("activity").firstElementChild) $("activity").prepend(g.li);
    if (!first) { g.li.classList.remove("fresh"); void g.li.offsetWidth; g.li.classList.add("fresh"); }
  } else g.li = addLine(t, groupHtml(g), first);
  if (g.matched || g.released) groups.delete(key);
}

const AUTO = "autopilot";
function autopilotLine(t, first, done) {
  const a = S.apFeed || (S.apFeed = { tried: 0, matched: 0, li: null });
  const html = `<span class="who">autopilot</span> ${done ? esc(done) : `tried ${plural(a.tried, "machine draft")}${a.matched ? ` · <span class="ok">${a.matched} matched</span>` : ""}`}`;
  if (a.li && a.li.isConnected) { a.li.querySelector("time").textContent = clock(t); a.li.querySelector("span").innerHTML = html; }
  else a.li = addLine(t, html, first);
}
function addActivity(events, attempts, first) {
  const items = [...events.map((e) => ({ t: e.created_at, ev: e })), ...attempts.map((a) => ({ t: a.created_at, at: a }))];
  items.sort((a, b) => a.t - b.t);
  for (const it of items) {
    const auto = (who) => who === AUTO || who === "@" + AUTO;  // ours, or the room host's
    if ((it.at && auto(it.at.agent)) || (it.ev && auto(it.ev.agent) && ["match", "claim", "autopilot"].includes(it.ev.kind))) {
      const a = S.apFeed || (S.apFeed = { tried: 0, matched: 0, li: null });
      if (it.at) a.tried++;
      if (it.ev && it.ev.kind === "match") a.matched++;
      autopilotLine(it.t, first, it.ev && it.ev.kind === "autopilot" ? it.ev.detail : null);
      continue;
    }
    if (it.at) {
      const at = it.at;
      touchGroup(at.agent, at.function, it.t, (g) => {
        g.tries++; g.insns = at.n_insns; g.lastScore = at.score;
        if (at.score != null) g.best = g.best == null ? at.score : Math.min(g.best, at.score);
      }, first);
    } else if (it.ev.kind === "claim") touchGroup(it.ev.agent, it.ev.detail, it.t, () => {}, first);
    else if (it.ev.kind === "match") touchGroup(it.ev.agent, it.ev.detail, it.t, (g) => { g.matched = true; }, first);
    else if (it.ev.kind === "release") touchGroup(it.ev.agent, it.ev.detail, it.t, (g) => { g.released = true; }, first);
    else addLine(it.t, eventHtml(it.ev), first);
  }
  const list = $("activity");
  while (list.children.length > 300) list.lastChild.remove();
  list.querySelectorAll(".fn").forEach((x) => { x.onclick = () => openFn(x.dataset.fn); });
  if (!list.children.length) list.innerHTML = `<li class="placeholder"><time></time><span class="muted">Nothing yet. Start an agent and its work shows up here.</span></li>`;
}

/* Agents write Markdown. Escape everything first, then allow only **bold** and `code`. */
function miniMarkdown(text) {
  return esc(text)
    .replace(/\*\*([^*\n]+)\*\*/g, "<b>$1</b>")
    .replace(/`([^`\n]+)`/g, "<code>$1</code>")
    .replace(/^#{1,4} (.*)$/gm, "<b>$1</b>")
    .replace(/^- /gm, "• ");
}

function addThoughts(sessions, first) {
  const list = $("thoughts");
  const items = [];
  for (const s of sessions) for (const f of s.feed) items.push({ ...f, label: s.label });
  items.sort((a, b) => a.t - b.t);
  for (const it of items) {
    const li = document.createElement("li");
    if (!first) li.className = "fresh";
    const time = document.createElement("time"); time.textContent = clock(it.t);
    const src = document.createElement("span"); src.className = "src"; src.textContent = it.label;
    const body = document.createElement("span"); body.className = "t-" + it.type;
    if (it.type === "text") body.innerHTML = miniMarkdown(it.text.slice(0, 1600));
    else body.textContent = it.type === "think" ? it.text.slice(0, 1200) : it.text;
    li.append(time, src, body);
    list.prepend(li);
  }
  while (list.children.length > 400) list.lastChild.remove();
  if (!list.children.length) list.innerHTML = `<li class="placeholder"><time></time><span class="muted">Helper agents you start from decomp.wtf think out loud here.</span></li>`;
  else list.querySelector(".placeholder")?.remove();
}

/* ------------------------------------------------------------------ inspector */
function highlightAsm(text) {
  return text.split("\n").map((line) => {
    if (/^\s*(glabel|endlabel)/.test(line)) return `<span class="cm">${esc(line)}</span>`;
    if (/^\.L[0-9A-F]+:/.test(line)) return `<span class="lbl">${esc(line)}</span>`;
    const m = line.match(/^(\/\* [^*]+ \*\/)(\s+)(\S+)(.*)$/);
    if (!m) return esc(line);
    const addr = m[1].split(" ")[2] || "";
    return `<span class="addr">${esc(addr)}</span>  <span class="op">${esc(m[3].padEnd(8))}</span> ${esc(m[4].trimStart()).replace(/(\.L[0-9A-F]{8})/g, '<span class="lbl">$1</span>')}`;
  }).join("\n");
}
function highlightC(text) {
  const kw = /\b(void|int|char|short|long|float|double|unsigned|signed|struct|union|enum|typedef|static|extern|const|volatile|return|if|else|for|while|do|switch|case|default|break|continue|goto|sizeof|s8|u8|s16|u16|s32|u32|s64|u64|f32|f64)\b/g;
  return esc(text).split("\n").map((line) => {
    if (/^\s*(\/\*|\*|\/\/)/.test(line)) return `<span class="cm">${line}</span>`;
    return line.replace(kw, '<span class="kw">$1</span>').replace(/\b(0x[0-9A-Fa-f]+|\d+)\b/g, '<span class="num">$1</span>');
  }).join("\n");
}

async function openFn(name) {
  const again = S.fn === name && !$("drawer").hidden;
  if (!again) { giveBack(name); S.editDirty = false; $("tryMsg").hidden = true; }
  S.fn = name;
  $("drawer").hidden = false;
  document.body.classList.add("locked");
  if (!again) { S.ftab = null; S.which = "latest"; S.diffKey = null; S.headerKey = null; $("diff").innerHTML = ""; $("diffSum").textContent = ""; }
  drawMap();
  document.querySelectorAll("#fnRows tr").forEach((tr) => tr.classList.toggle("sel", tr.dataset.fn === name));
  await refreshFn(true);
}

function fnBadge(d = S.fnDetail) {
  if (!d) return;
  const working = S.claims.find((c) => c.name === d.name);
  const st = $("fnStatus");
  if (d.mode === "header" || d.mode === "skip") {
    st.className = "badge";
    st.textContent = d.mode === "header" ? "header only" : "skipped";
    return;
  }
  st.className = "badge " + (d.status === "matched" ? "matched" : working ? "working" : "");
  st.textContent = d.status === "matched" ? "matched" : working ? `${working.agent} working` : d.best != null ? `best ${pctText(pctOf(d.best, d.insns))}` : "not started";
}

function showFnTab(tab) {
  document.querySelectorAll("[data-ftab]").forEach((b) => b.classList.toggle("on", b.dataset.ftab === tab));
  $("fnDiffView").hidden = tab !== "diff";
  $("fnCodeView").hidden = tab !== "code";
  $("fnHeaderView").hidden = tab !== "header";
  if (tab === "header") loadHeader();
  if (tab === "diff") loadDiff();
}
async function loadHeader() {
  const key = S.fn;
  if (!key || S.headerKey === key) return;
  $("fnHeader").textContent = "Loading the generated header…";
  try {
    const r = await api(`/api/header?slug=${S.slug}&name=${encodeURIComponent(key)}`);
    if (S.fn === key) { $("fnHeader").textContent = r.header || "(no generated header for this project)"; S.headerKey = key; }
  } catch (e) { $("fnHeader").textContent = `Header unavailable: ${e.message}`; }
}
function openSigEditor() {
  const sig = (S.fnDetail && S.fnDetail.sig) || {};
  const inside = (S.fn.split("(", 1)[1] || "").replace(/\)$/, "");
  $("sigRet").value = sig.ret || "";
  $("sigParams").value = sig.params || (inside === "void" ? "" : inside);
  $("sigConst").checked = !!sig.const;
  $("sigStatic").checked = !!sig.static;
  $("sigVirtual").checked = !!sig.virtual;
  $("fnSigEditor").hidden = false;
  $("sigRet").focus();
}
function sigFlag(id, current) {
  const box = $(id);
  if (box.checked) return "true";
  return current ? "false" : "";
}
async function saveSignature() {
  const sig = (S.fnDetail && S.fnDetail.sig) || {};
  try {
    const r = await api("/api/signature", {
      method: "POST",
      body: {
        slug: S.slug, name: S.fn, ret: $("sigRet").value.trim(),
        params: $("sigParams").value.trim(),
        const: sigFlag("sigConst", sig.const), static: sigFlag("sigStatic", sig.static),
        virtual: sigFlag("sigVirtual", sig.virtual),
      },
    });
    toast(r.message);
    if ((r.message || "").startsWith("✅")) {
      $("fnSigEditor").hidden = true;
      S.headerKey = null;
      await loadHeader();
      refreshFn(false);
    }
  } catch (e) { toast(esc(e.message), "err"); }
}
document.querySelectorAll("[data-ftab]").forEach((b) => { b.onclick = () => { S.ftab = b.dataset.ftab; showFnTab(S.ftab); }; });
document.querySelectorAll("#diffWhich [data-which]").forEach((b) => {
  b.onclick = () => {
    S.which = b.dataset.which;
    document.querySelectorAll("#diffWhich [data-which]").forEach((x) => x.classList.toggle("on", x === b));
    loadDiff();
  };
});

let fnBusy = false;
async function refreshFn(first) {
  if (fnBusy || !S.fn) return;
  fnBusy = true;
  try {
    const d = await api(`/api/function?slug=${S.slug}&name=${encodeURIComponent(S.fn)}`);
    if (d.name !== S.fn) return;
    S.fnDetail = d;
    $("fnAddr").textContent = `${d.unit ? d.unit + " · " : ""}0x${(d.vram || 0).toString(16).toUpperCase()} · ${d.insns} instructions`;
    $("fnName").textContent = d.name;
    fnBadge(d);
    $("fnMode").value = d.mode || "decompile";
    $("tryBtn").disabled = d.mode !== "decompile";
    $("tryHint").textContent = d.mode === "decompile"
      ? "Ctrl+Enter · edit it yourself: you're judged like an agent"
      : d.mode === "header" ? "header-only: edit the signature/class from an agent or the Header tab"
      : "skipped: set the mode to decompile to work on the body";
    $("fnMode").onchange = async () => {
      const mode = $("fnMode").value;
      try {
        const r = await api("/api/mode", { method: "POST", body: { slug: S.slug, name: d.name, mode } });
        toast(r.message);
      } catch (e) { toast(esc(e.message), "err"); }
      refreshFn(false);
    };
    $("sigEdit").onclick = openSigEditor;
    $("sigSave").onclick = saveSignature;
    $("sigCancel").onclick = () => { $("fnSigEditor").hidden = true; };
    const pinned = (S.ov.priority || []).includes(d.name);
    $("fnPin").hidden = S.ov.kind === "fork" || d.status !== "open" || d.mode !== "decompile";
    $("fnPin").classList.toggle("on", pinned);
    $("fnPin").textContent = pinned ? "★ Next (on)" : "★ Next";
    $("fnPin").onclick = () => togglePrio(d.name, !pinned).then(() => refreshFn(false));
    $("noteAdd").onclick = async () => {
      const text = $("noteText").value.trim();
      if (!text) return;
      try {
        await api("/api/note", { method: "POST", body: { slug: S.slug, function: d.name, text } });
        $("noteText").value = "";
        toast("Note saved: the next agent on this function reads it.");
        refreshFn(false);
      } catch (e) { toast(esc(e.message), "err"); }
    };
    $("fnAsm").innerHTML = highlightAsm(d.asm);
    const kinds = { matched: "Matching C", best: "Best attempt so far", latest: S.ov.kind === "fork" ? "In the source now" : "Latest attempt",
      draft: "IDA draft (Hex-Rays)" };
    $("fnSrcKind").textContent = kinds[d.source_kind] || "No C yet";
    if (!S.editDirty || first) setEditor(d.source || "", d);
    $("copySrc").onclick = () => navigator.clipboard.writeText($("fnEdit").value).then(() => toast("Copied."));
    renderFnChart(d);
    $("diffWhich").hidden = d.status === "matched" || S.ov.kind === "fork" || d.scores.filter((x) => x.score != null).length < 2;
    const xr = [];
    if (d.calls.length) xr.push(`<div><b>calls</b>${d.calls.map(fnLink).join("")}</div>`);
    if (d.called_by.length) xr.push(`<div><b>called by</b>${d.called_by.map(fnLink).join("")}</div>`);
    $("fnXref").innerHTML = xr.join("");
    $("fnXref").querySelectorAll(".fn").forEach((x) => { x.onclick = () => openFn(x.dataset.fn.split("+")[0]); });
    $("fnNotes").innerHTML = d.notes.length ? `<p class="col-title">Notes from agents</p>` + d.notes.map((n) => `<div class="note"><small>${esc(n.agent)} · ${clock(n.created_at)}</small>${esc(n.text)}</div>`).join("") : "";
    const tab = S.ftab || (d.mode !== "decompile" ? "header"
      : d.status === "matched" || !d.scores.length ? "code" : "diff");
    showFnTab(tab);
  } catch (e) {
    if (first) toast(esc(e.message), "err");
  } finally { fnBusy = false; }
}

/* Editing a function yourself: a highlighted editor over a textarea, judged like an agent's attempt. */
function setEditor(source, d) {
  const ta = $("fnEdit");
  ta.value = source || (d && d.status !== "matched" ? `/* write ${d.name} here */\n` : "");
  paintEditor();
  S.editDirty = false;
}
function paintEditor() {
  const ta = $("fnEdit");
  $("fnSrc").innerHTML = highlightC(ta.value) + "\n";
  $("fnSrc").scrollTop = ta.scrollTop; $("fnSrc").scrollLeft = ta.scrollLeft;
}
$("fnEdit").addEventListener("input", () => { S.editDirty = true; paintEditor(); });
$("fnEdit").addEventListener("scroll", () => { $("fnSrc").scrollTop = $("fnEdit").scrollTop; $("fnSrc").scrollLeft = $("fnEdit").scrollLeft; });
$("fnEdit").addEventListener("keydown", (e) => {
  const ta = e.target;
  if (e.key === "Tab" && !e.shiftKey) {
    e.preventDefault();
    const { selectionStart: a, selectionEnd: b } = ta;
    ta.setRangeText("    ", a, b, "end");
    S.editDirty = true; paintEditor();
  } else if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) {
    e.preventDefault();
    tryIt();
  }
});
$("tryBtn").onclick = () => tryIt();

async function tryIt() {
  const name = S.fn, source = $("fnEdit").value, msg = $("tryMsg");
  if (!name || !source.trim() || $("tryBtn").disabled) return;
  $("tryBtn").disabled = true;
  msg.hidden = false; msg.className = "try-msg"; msg.textContent = "Compiling…";
  try {
    const r = await api("/api/try", { method: "POST", body: { slug: S.slug, name, source } });
    if (r.matched) {
      S.myClaim = null;
      msg.className = "try-msg ok"; msg.textContent = "Byte-identical. Saved as a match, credited to you.";
      toast(`<code>${esc(name)}</code>&nbsp;matched by you`, "match");
    } else {
      S.myClaim = name;
      msg.className = "try-msg" + (r.score == null ? " bad" : "");
      msg.textContent = r.score == null ? "It didn't compile:" : (r.text.split("\n")[0] || `score ${r.score}`);
      if (r.score == null) msg.textContent += "\n" + r.text.split("\n").slice(1, 12).join("\n");
    }
    S.editDirty = false;
    S.diffKey = null;
    await refreshFn(false);
    if (r.score != null) { S.ftab = "diff"; showFnTab("diff"); }
  } catch (e) {
    msg.className = "try-msg bad"; msg.textContent = e.message;
  } finally { $("tryBtn").disabled = false; }
}
/* The function stays yours only while you're on it: give it back when you move on. */
function giveBack(next) {
  if (S.myClaim && S.myClaim !== next && S.slug) {
    api("/api/release", { method: "POST", body: { slug: S.slug, name: S.myClaim } }).catch(() => {});
    S.myClaim = null;
  }
}

/* Score per compile, as a match percentage: dots for each compile, a line for the best so far. */
function renderFnChart(d) {
  const wrap = $("fnChartWrap"), svg = $("fnChart");
  const pts = d.scores;
  wrap.hidden = !pts.length;
  if (!pts.length) return;
  const w = Math.max(300, svg.clientWidth || 600), h = 92, padL = 34, padR = 10, padT = 8, padB = 16;
  svg.setAttribute("viewBox", `0 0 ${w} ${h}`);
  const n = pts.length;
  const X = (i) => padL + (n === 1 ? (w - padL - padR) / 2 : (i * (w - padL - padR)) / (n - 1));
  const Y = (p) => padT + (1 - p) * (h - padT - padB);
  let out = "";
  for (const g of [0, 0.5, 1]) out += `<line class="grid" x1="${padL}" x2="${w - padR}" y1="${Y(g)}" y2="${Y(g)}"/><text class="axis" x="${padL - 6}" y="${Y(g) + 3.5}">${g * 100}%</text>`;
  let best = null, path = "";
  const agents = [...new Set(pts.map((p) => p.agent))];
  pts.forEach((p, i) => {
    if (p.score != null) best = best == null ? p.score : Math.min(best, p.score);
    if (best != null) {
      const y = Y(pctOf(best, d.insns));
      path += path ? `H${X(i).toFixed(1)}V${y.toFixed(1)}` : `M${X(i).toFixed(1)},${y.toFixed(1)}`;
    }
  });
  if (path) out += `<path class="bestline" d="${path}"/>`;
  pts.forEach((p, i) => {
    const title = `<title>${esc(p.agent || "")} · ${clock(p.t)} · ${p.score == null ? "didn't compile" : p.score === 0 ? "byte-identical" : `score ${p.score}`}</title>`;
    if (p.score == null) out += `<g class="fail"><path d="M${X(i) - 3},${Y(0) + 5}l6,6m0,-6l-6,6"/>${title}</g>`;
    else out += `<circle class="${p.score === 0 ? "hit" : "pt"} a${agents.indexOf(p.agent) % 4}" cx="${X(i).toFixed(1)}" cy="${Y(pctOf(p.score, d.insns)).toFixed(1)}" r="${p.score === 0 ? 4.5 : 3}">${title}</circle>`;
  });
  svg.innerHTML = out;
  const fails = pts.filter((p) => p.score == null).length;
  const bp = best == null ? null : pctOf(best, d.insns);
  $("fnChartNote").innerHTML = `<b>${plural(n, "compile")}</b>${bp != null ? ` · best ${best === 0 ? "byte-identical" : pctText(bp)}` : ""}${fails ? ` · ${fails} didn't compile` : ""}${agents.length > 1 ? ` · ${agents.map(esc).join(", ")}` : ` · ${esc(agents[0] || "")}`}`;
}

/* The judge's diff: target and attempt side by side, instruction by instruction. */
const MARK = { " ": "eq", r: "arg", s: "arg", i: "arg", "|": "repl", "<": "del", ">": "ins", o: "mov" };
const MARK_TEXT = { r: "registers differ", s: "stack offset differs", i: "operand differs", "|": "different instruction", "<": "missing in yours", ">": "extra in yours", o: "in a different place" };
function insnHtml(text, other, cls) {
  if (!text) return "";
  const m = text.match(/^(\S+)(\s*)(.*)$/);
  if (!m) return esc(text);
  let ops = esc(m[3]);
  if (cls === "arg" && other) {
    const a = m[3].split(/(,\s*|\(|\))/), b = (other.match(/^\S+\s*(.*)$/) || [, ""])[1].split(/(,\s*|\(|\))/);
    ops = a.map((tok, k) => (tok !== b[k] && !/^(,\s*|\(|\))$/.test(tok) ? `<mark>${esc(tok)}</mark>` : esc(tok))).join("");
  }
  return `<span class="op">${esc(m[1])}</span>${m[2] ? " " : ""}${ops}`;
}
function renderDiff(d) {
  const sum = $("diffSum"), box = $("diff"), probs = $("diffProblems");
  probs.innerHTML = "";
  if (!d.rows) {
    const why = d.infra ? "The compiler crashed before your code ran (host/x86 translation problem, not your code)."
      : `The ${d.kind === "best" ? "best" : "latest"} attempt didn't compile.`;
    sum.innerHTML = d.error ? `<span class="bad">${why}</span>` : "No attempt yet. The diff appears after the first compile.";
    box.innerHTML = d.error ? `<pre class="code errlog">${esc(d.error)}</pre>` : "";
    return;
  }
  const rows = d.rows;
  const same = rows.filter((r) => r[0] === " ").length, target = rows.filter((r) => r[1]).length;
  const label = { matched: "Matching C", best: "Best attempt", latest: S.ov.kind === "fork" ? "The source now" : "Latest attempt" }[d.kind] || "Attempt";
  sum.innerHTML = `<b>${label}</b> · ${d.percent === 100 && d.score === 0 ? `<span class="ok">byte-identical</span>` : `${d.percent}%${d.score != null ? ` · score ${d.score}` : ""}`} · ${same} of ${target} instructions identical
    <span class="diff-key"><i class="k arg"></i>operands <i class="k repl"></i>different <i class="k mov"></i>moved</span>`;
  const html = [];
  let t = 0, run = [];
  const rowHtml = (r) => {
    const cls = MARK[r[0]] || "repl";
    if (r[1]) t++;
    return `<div class="dr ${cls}"${r[0] !== " " ? ` title="${MARK_TEXT[r[0]] || ""}"` : ""}><span class="dn">${r[1] ? t : ""}</span><code>${insnHtml(r[1], r[2], cls)}</code><span class="dm">${r[0] === " " ? "" : esc(r[0])}</span><code>${insnHtml(r[2], r[1], cls)}</code></div>`;
  };
  const flush = (end) => {
    if (run.length > 10 && end !== "all") {
      const head = run.slice(0, end === "start" ? 0 : 3), tail = run.slice(end === "end" ? run.length : run.length - 3);
      const mid = run.slice(head.length, run.length - tail.length);
      html.push(...head.map(rowHtml));
      html.push(`<button class="dfold" type="button">··· ${mid.length} identical instructions ···</button><div class="dfolded" hidden>${mid.map(rowHtml).join("")}</div>`);
      html.push(...tail.map(rowHtml));
    } else html.push(...run.map(rowHtml));
    run = [];
  };
  rows.forEach((r) => {
    if (r[0] === " ") { run.push(r); return; }
    flush(html.length ? "mid" : "start");
    html.push(rowHtml(r));
  });
  flush(html.length ? "end" : "all");
  box.innerHTML = `<div class="dh"><span></span><span>Target (your game)</span><span></span><span>${esc(label)}</span></div>` + html.join("");
  box.querySelectorAll(".dfold").forEach((b) => { b.onclick = () => { b.nextElementSibling.hidden = false; b.remove(); }; });
  probs.innerHTML = (d.problems || []).map((p) => `<li>${esc(p)}</li>`).join("");
}
async function loadDiff() {
  const d0 = S.fnDetail;
  if (!d0) return;
  const key = `${d0.name}|${S.which}|${d0.scores.length}|${d0.status}`;
  if (key === S.diffKey) return;
  S.diffKey = key;
  if (!$("diff").innerHTML) $("diffSum").textContent = "Compiling…";
  try {
    const d = await api(`/api/diff?slug=${S.slug}&name=${encodeURIComponent(d0.name)}&which=${S.which}`);
    if (S.fnDetail && S.fnDetail.name === d0.name) renderDiff(d);
  } catch (e) { $("diffSum").innerHTML = `<span class="bad">${esc(e.message)}</span>`; S.diffKey = null; }
}

function stepFn(delta) {
  if (!S.fn || !S.map.length) return;
  const order = S.tab === "functions" && L.rows.length ? L.rows : S.map;
  const k = order.findIndex((f) => f.name === S.fn);
  const next = order[(k + delta + order.length) % order.length];
  if (next) openFn(next.name);
}
$("fnPrev").onclick = () => stepFn(-1);
$("fnNext").onclick = () => stepFn(1);

/* ------------------------------------------------------------------ function list */
const L = { q: "", filter: "all", sort: "i", dir: 1, limit: 200, rows: [] };
const FILTERS = [["all", "All"], ["open", "To do"], ["working", "Working"], ["tried", "Tried"], ["matched", "Matched"], ["library", "Library"]];
const fnState = (f) => (f.status === "matched" ? "matched" : f.status === "library" ? "library" : f.status === "asm" ? "asm" : f.status === "working" ? "working" : f.best != null ? "tried" : "open");
const STATE_RANK = { working: 0, tried: 1, open: 2, matched: 3, asm: 4, library: 5 };

function renderList() {
  if (!S.map.length || S.tab !== "functions") return;
  const counts = { all: S.map.length, open: 0, working: 0, tried: 0, matched: 0, asm: 0, library: 0 };
  for (const f of S.map) counts[fnState(f)]++;
  $("fnFilter").innerHTML = FILTERS.map(([k, label]) => `<button type="button" role="radio" aria-checked="${L.filter === k}" class="${L.filter === k ? "on" : ""}" data-filter="${k}">${label}<span>${counts[k].toLocaleString()}</span></button>`).join("");
  const q = L.q.trim().toLowerCase();
  let rows = S.map.filter((f) => (L.filter === "all" || fnState(f) === L.filter)
    && (!q || f.name.toLowerCase().includes(q) || hex8(f.vram).toLowerCase().includes(q) || (f.unit || "").toLowerCase().includes(q)));
  const perFile = S.ov && (S.ov.kind === "fork" || S.ov.kind === "native");  // the header says "File" there
  const key = {
    i: (f) => f.i, name: (f) => f.name.toLowerCase(), insns: (f) => f.insns, attempts: (f) => f.attempts || 0,
    unit: (f) => ((f.unit || "") + "\u0000" + f.name).toLowerCase(),
    best: (f) => (f.status === "matched" ? 2 : f.best == null ? -1 : pctOf(f.best, f.insns)), status: (f) => STATE_RANK[fnState(f)],
  }[L.sort === "vram" ? (perFile ? "unit" : "i") : L.sort];
  rows = rows.slice().sort((a, b) => { const x = key(a), y = key(b); return (x < y ? -1 : x > y ? 1 : a.i - b.i) * L.dir; });
  L.rows = rows;
  const fork = S.ov && S.ov.kind === "fork";
  const shortUnit = (u) => String(u || "").split("/").slice(-2).join("/");
  $("fnRows").innerHTML = rows.slice(0, L.limit).map((f) => {
    const st = fnState(f), p = pctOf(f.best, f.insns);
    const best = st === "matched" ? `<span class="ok">100%</span>` : p == null ? `<span class="dim">–</span>` : pctText(p);
    const status = st === "matched" ? `<span class="st matched" title="${esc(f.matched_by ? "by " + f.matched_by : "")}">matched</span>` : st === "library" ? `<span class="st" title="std/boost/CRT glue or an import: skipped by default — claim it to take it on anyway">library</span>` : st === "asm" ? `<span class="st" title="hand-written assembly: no C compiles to it">assembly</span>` : st === "working" ? `<span class="st working">${esc(f.agent || "working")}</span>`
      : st === "tried" ? `<span class="st tried">tried</span>` : `<span class="st">to do</span>`;
    const first = perFile ? `<td class="mono dim" title="${esc((f.unit || "") + " — " + hex8(f.vram))}">${esc(shortUnit(f.unit))}</td>`
      : `<td class="mono dim">${hex8(f.vram)}</td>`;
    return `<tr data-fn="${esc(f.name)}" class="${S.fn === f.name ? "sel" : ""}" tabindex="0">${first}
      <td class="mono name">${(S.ov && (S.ov.priority || []).includes(f.name)) ? `<span class="star" title="agents take it next">★</span>` : ""}${esc(f.name)}</td><td class="r mono">${f.insns.toLocaleString()}</td><td class="r mono">${best}</td>
      <td class="r mono">${f.attempts || `<span class="dim">0</span>`}</td><td>${status}</td></tr>`;
  }).join("") || `<tr class="none"><td colspan="6">No function matches${q ? ` “${esc(L.q)}”` : ""}.</td></tr>`;
  $("fnShown").textContent = rows.length > L.limit ? `${L.limit.toLocaleString()} of ${rows.length.toLocaleString()} shown` : plural(rows.length, "function");
  $("fnMore").hidden = rows.length <= L.limit;
  const firstIsSorted = (th) => th.dataset.sort === L.sort || (th.dataset.sort === "vram" && (L.sort === "i" || (perFile && L.sort === "unit")));
  document.querySelectorAll(".fn-table th").forEach((th) => {
    th.classList.toggle("sorted", firstIsSorted(th));
    th.classList.toggle("desc", firstIsSorted(th) && L.dir < 0);
  });
}
$("fnFilter").addEventListener("click", (e) => { const b = e.target.closest("[data-filter]"); if (b) { L.filter = b.dataset.filter; L.limit = 200; renderList(); } });
$("fnSearch").addEventListener("input", () => { L.q = $("fnSearch").value; L.limit = 200; renderList(); });
$("fnMore").onclick = () => { L.limit += 500; renderList(); };
$("fnRows").addEventListener("click", (e) => { const tr = e.target.closest("tr[data-fn]"); if (tr) openFn(tr.dataset.fn); });
$("fnRows").addEventListener("keydown", (e) => { const tr = e.target.closest("tr[data-fn]"); if (tr && e.key === "Enter") openFn(tr.dataset.fn); });
document.querySelectorAll(".fn-table th[data-sort]").forEach((th) => {
  th.onclick = () => {
    const perFile = S.ov && (S.ov.kind === "fork" || S.ov.kind === "native");
    const k = th.dataset.sort === "vram" ? (perFile ? "unit" : "i") : th.dataset.sort;
    if (L.sort === k) L.dir = -L.dir;
    else { L.sort = k; L.dir = ["best", "attempts", "insns"].includes(k) ? -1 : 1; }
    renderList();
  };
});

/* Matched code over time, from when each function was matched. */
function renderProgress() {
  const svg = $("progress"), total = S.map.reduce((n, f) => n + (f.size || 0), 0);
  const done = S.map.filter((f) => f.status === "matched");
  S.today = done.filter((f) => f.matched_at > Date.now() / 1000 - 86400).length;
  const dated = done.filter((f) => f.matched_at).sort((a, b) => a.matched_at - b.matched_at);
  if (!total || dated.length < 2) { svg.innerHTML = ""; return; }
  let cum = done.filter((f) => !f.matched_at).reduce((n, f) => n + (f.size || 0), 0);
  const t0 = dated[0].matched_at, t1 = Math.max(Date.now() / 1000, dated[dated.length - 1].matched_at + 1);
  const top = cum + dated.reduce((n, f) => n + (f.size || 0), 0);  // scaled to what's done, so early progress shows
  const X = (t) => (200 * (t - t0)) / (t1 - t0), Y = (v) => 42 - (40 * v) / Math.max(top, 1);
  let line = `M0,${Y(cum).toFixed(1)}`;
  for (const f of dated) { cum += f.size || 0; line += `H${X(f.matched_at).toFixed(1)}V${Y(cum).toFixed(1)}`; }
  line += "H200";
  svg.innerHTML = `<path class="area" d="${line}V44H0Z"/><path class="line" d="${line}"/>`;
}

/* ------------------------------------------------------------------ drawers, keys */
function closeAll() {
  if (!$("drawer").hidden) giveBack(null);
  for (const id of ["drawer", "dialog"]) $(id).hidden = true;
  document.body.classList.remove("locked");
  S.fn = null;
  if (S.map.length) drawMap();
}
document.querySelectorAll(".drawer").forEach((d) => {
  d.addEventListener("click", (e) => {
    if (e.target !== d && !e.target.closest("[data-close]")) return;
    if (d.id === "drawer") { giveBack(null); S.fn = null; drawMap(); }
    d.hidden = true;
    if ($("drawer").hidden && $("dialog").hidden) document.body.classList.remove("locked");
  });
});
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape") { if (!$("launchPop").hidden) { hideLaunch(); return; } closeAll(); return; }
  if (e.target.closest("input, textarea, select") || e.metaKey || e.ctrlKey || e.altKey) return;  // typing
  if (!$("drawer").hidden && (e.key === "j" || e.key === "k")) { e.preventDefault(); stepFn(e.key === "j" ? 1 : -1); return; }
  if (e.key === "/" && S.slug && $("drawer").hidden) {
    e.preventDefault();
    if (S.tab !== "functions") location.hash = `#/p/${S.slug}/functions`;
    setTimeout(() => $("fnSearch").focus(), 50);
  }
});

function cmdBox(cmd) {
  return `<div class="cmd"><code>${esc(cmd)}</code><button type="button" data-copy="${esc(cmd)}">Copy</button></div>`;
}
function wireCopies(root) {
  root.querySelectorAll("[data-copy]").forEach((b) => { b.onclick = () => navigator.clipboard.writeText(b.dataset.copy).then(() => { b.textContent = "Copied"; setTimeout(() => (b.textContent = "Copy"), 1500); }); });
}

function dialog(title, html) {
  $("dialogTitle").textContent = title;
  $("dialogBody").innerHTML = html;
  $("dialog").hidden = false;
  document.body.classList.add("locked");
  wireCopies($("dialogBody"));
  return $("dialogBody");
}

$("askBtn").onclick = openConnect;
$("talkBtn").onclick = openConnect;
$("connectBtn").onclick = openConnect;

/* Your own agent with decomp.wtf's tools: registered once, then you just ask it. */
async function connectRows(box) {
  const render = (rows) => {
    box.innerHTML = rows.map((a) => `<div class="line-item"><div class="txt"><b>${esc(a.name)}</b><span class="mono">${esc(a.command)}</span></div>
      ${!a.installed ? `<span class="muted small">not installed</span>` : a.connected ? `<span class="ok-mark">connected</span>` : `<button class="primary small-btn" data-connect="${esc(a.id)}" type="button">Connect</button>`}</div>`).join("");
    box.querySelectorAll("[data-connect]").forEach((b) => {
      b.onclick = async () => {
        b.disabled = true; b.textContent = "Connecting…";
        try {
          await api("/api/connect", { method: "POST", body: { id: b.dataset.connect } });
          toast(`Connected. Ask it to decompile your game.`, "match");
          render((await api("/api/connect")).agents);
        } catch (e) { toast(esc(e.message), "err"); b.disabled = false; b.textContent = "Connect"; }
      };
    });
  };
  try {
    const r = await api("/api/connect");
    render(r.agents);
    return r;
  } catch (e) { box.innerHTML = `<p class="bad">${esc(e.message)}</p>`; return null; }
}
const HOST_NAMES = { windows: "Windows", macos: "your Mac", linux: "this computer" };
async function openConnect() {
  if (S.st && S.st.runtime && S.st.runtime !== "native") return openHostConnect();
  const body = dialog("Use decomp.wtf from your AI agent", `<p>Connect the agent you already use, once. Then ask it in your terminal, for example:</p>
    ${cmdBox("decompile my game at ~/roms/game.z64")}
    <p class="muted small">It confirms the game is your own copy, imports it, opens this live view and works with every tool here: the byte-for-byte judge, the autopilot, helper agents, export. Anything it does shows up here as it happens.</p>
    <div class="setup-group" id="connectRows"><p class="muted small">Looking for your agents…</p></div>
    <div class="setup-group"><h3>Any other MCP client (Cursor, Claude Desktop, Windsurf, your own)</h3><pre class="code" id="bridgeJson"></pre>
      <p class="muted small">It starts decomp.wtf when needed; no token, nothing to update when the app restarts.</p></div>`);
  const r = await connectRows(body.querySelector("#connectRows"));
  if (r) body.querySelector("#bridgeJson").textContent = JSON.stringify({ mcpServers: { decomp: { command: r.bridge[0], args: r.bridge.slice(1) } } }, null, 2);
}

/* decomp.wtf in WSL (Windows) or in Docker: the agents you talk to run on the computer itself, so they're
   connected from there, by the `decomp` command the installer put on it. */
async function openHostConnect() {
  const host = HOST_NAMES[S.st.host_os] || "your computer";
  const shell = S.st.host_os === "windows" ? "PowerShell" : "a terminal";
  const body = dialog("Use decomp.wtf from your AI agent", `<p>Run this once in ${esc(shell)} on ${esc(host)}: it connects Claude Code, Codex, Antigravity CLI and opencode there.</p>
    ${cmdBox("decomp connect")}
    <p>Then ask your agent, for example:</p>
    ${cmdBox(S.st.host_os === "windows" ? "decompile my game at C:\\Games\\game.z64" : "decompile my game at ~/roms/game.z64")}
    <p class="muted small">decomp.wtf runs in ${S.st.runtime === "wsl" ? "its own WSL 2 Linux on Windows" : "Docker"}; your agent reaches it through the command below. Anything it does shows up here as it happens.</p>
    <div class="setup-group"><h3>Any other MCP client (Cursor, Claude Desktop, Windsurf, your own)</h3><pre class="code" id="bridgeJson"></pre></div>`);
  try {
    const r = await api("/api/connect");
    body.querySelector("#bridgeJson").textContent = JSON.stringify({ mcpServers: { decomp: { command: r.bridge[0], args: r.bridge.slice(1) } } }, null, 2);
  } catch (e) { body.querySelector("#bridgeJson").textContent = e.message; }
}

/* ------------------------------------------------------------------ steering: instructions, next in line */
function renderSteering(ov) {
  const sp = ov.spend;
  const n = ov.helper_matches || 0;
  $("spendLine").title = "cumulative tokens billed across every model call — each agent turn re-sends the conversation";
  $("spendLine").textContent = sp && sp.usd ? `· ${money(sp.usd)} spent${n ? ` · ${money(sp.usd / n)}/match` : ""}`
    : sp && sp.tokens ? `· ${(sp.tokens / 1000).toFixed(0)}k tokens billed` : "";
  $("instrState").textContent = ov.instructions ? "agents get these" : "none yet";
}
$("instrSave").onclick = async () => {
  try {
    S.ov = await api("/api/instructions", { method: "POST", body: { slug: S.slug, text: $("instrEdit").value } });
    renderSteering(S.ov);
    toast("Saved. Agents get them from their next task on.");
  } catch (e) { toast(esc(e.message), "err"); }
};
async function togglePrio(name, on) {
  try {
    const r = await api("/api/priority", { method: "POST", body: { slug: S.slug, name, on } });
    S.ov.priority = r.priority;
    toast(on ? `Agents take <code>${esc(name)}</code> next.` : "No longer first in line.");
    renderList(); renderPrio();
  } catch (e) { toast(esc(e.message), "err"); }
}
function renderPrio() {
  const list = (S.ov && S.ov.priority) || [];
  const box = $("prioList");
  if (S.ov && S.ov.kind === "fork") { box.innerHTML = `<li class="muted small">Agents pick the easiest open functions first.</li>`; return; }
  box.innerHTML = list.length ? list.map((n) => `<li><span class="star">★</span>${fnLink(n)}<span class="grow"></span><button class="link-btn" data-unpin="${esc(n)}" type="button">remove</button></li>`).join("")
    : `<li class="muted small">Nothing pinned: agents take the easiest open functions first. Open a function and click ★ Next to put it first.</li>`;
  box.querySelectorAll(".fn").forEach((x) => { x.onclick = () => openFn(x.dataset.fn); });
  box.querySelectorAll("[data-unpin]").forEach((b) => { b.onclick = () => togglePrio(b.dataset.unpin, false); });
}

/* Autopilot: free matches before any agent spends a token: identical code (twins) of what's matched, then every
   function's machine draft through the judge; the permuter works on near misses meanwhile. */
function renderAutopilot(ov) {
  const box = $("autopilot"), ap = ov.autopilot, tw = ov.twins, pm = ov.permuter;
  const canRun = (ov.kind !== "fork" || ov.ready) && ov.functions - ov.matched > 0;
  box.hidden = !ap && !canRun && !tw && !pm;
  if (box.hidden) return;
  const running = ap && ap.state === "running";
  const native = ov.kind === "native";
  const blocked = native && !(ov.analysis || {}).ida;
  const twinsRunning = tw && tw.state === "running";
  box.classList.toggle("on", !!(running || twinsRunning));
  $("apBar").hidden = !running || ap.phase === "twins";
  const perm = pm && (pm.tried || pm.state === "running")
    ? ` The permuter ${pm.state === "running" ? `is rewriting near misses${pm.current ? ` (now ${pm.current})` : ""}` : "rewrote near misses"}: ${plural(pm.tried, "function")}, ${pm.matched} matched.` : "";
  const twinsDone = (ap && ap.twins) || (tw && tw.matched) || 0;
  if (running && ap.phase === "twins") {
    $("apTitle").textContent = "Autopilot: matching code the game has more than once (twins of matched functions)";
    $("apSub").textContent = `Each match's code is tried on its identical copies, names swapped; the judge decides.${perm}`;
    $("apBtn").textContent = "Stop";
  } else if (running) {
    $("apTitle").textContent = `Autopilot: trying each function's ${native ? "IDA draft" : "machine draft"} · ${ap.matched.toLocaleString()} matched for free`;
    $("apSub").textContent = `${ap.tried.toLocaleString()} of ${ap.total.toLocaleString()} tried${ap.near ? ` · ${ap.near} more are 90%+ there` : ""}${ap.twins ? ` · ${ap.twins.toLocaleString()} from identical code` : ""}. Agents work alongside it.${perm}`;
    $("apBar").firstElementChild.style.width = `${(100 * ap.tried) / Math.max(1, ap.total)}%`;
    $("apBtn").textContent = "Stop";
  } else if (ap || tw) {
    const total = (ap ? ap.matched : 0) + (ap ? 0 : twinsDone);
    $("apTitle").textContent = twinsRunning ? `Matching identical code: ${tw.matched.toLocaleString()} so far`
      : total ? `Autopilot matched ${total.toLocaleString()} function${total === 1 ? "" : "s"} for free` : "Autopilot found no free matches this time";
    const parts = [];
    if (twinsDone) parts.push(`${twinsDone.toLocaleString()} from identical code`);
    if (tw && tw.asm) parts.push(`${tw.asm.toLocaleString()} copies of assembly set aside (not for agents)`);
    if (ap && ap.tried) parts.push(`${ap.tried.toLocaleString()} ${native ? "IDA drafts" : "machine drafts"} tried${ap.near ? `, ${ap.near} more 90%+ there` : ""}`);
    $("apSub").textContent = (parts.length ? parts.join(" · ") + ". " : "") + (ap && ap.no_drafts ? "" : "Run it again after agents add types and names: drafts get better.") + perm;
    $("apBtn").textContent = "Run again";
  } else {
    $("apTitle").textContent = "Free matches first";
    $("apSub").textContent = blocked
      ? "The autopilot tries each function's IDA (Hex-Rays) draft: analyze the binary first (Plan tab)."
      : "Autopilot tries every function's IDA (Hex-Rays) draft through the judge" + `; whatever matches costs no agent time.${perm}`;
    $("apBtn").textContent = "Run autopilot";
  }
  $("apBtn").disabled = blocked;
  $("apBtn").onclick = async () => {
    $("apBtn").disabled = true;
    try {
      S.ov = await api("/api/autopilot", { method: "POST", body: { slug: S.slug, action: running ? "stop" : "start" } });
      renderAutopilot(S.ov);
    } catch (e) { toast(esc(e.message), "err"); } finally { $("apBtn").disabled = blocked; }
  };
}

/* ------------------------------------------------------------------ source: the base for ports and mods */
function renderSource(ov) {
  const ex = ov.export;
  $("srcExport").hidden = !ov.exportable;
  $("srcWhen").textContent = ex ? `exported ${since(ex.t)}` : "";
  if (!ov.exportable) {
    $("srcText").textContent = "Nothing is matched yet — once a function matches, this reconstructs the project's source tree from the binary's own debug info and re-verifies every function that goes in it.";
    $("srcState").innerHTML = "";
    return;
  }
  $("srcText").innerHTML = "decomp.wtf reconstructs the original source layout: class definitions and signatures come from the binary's own debug info, each function is stripped of the scaffolding it was matched with, and every function is recompiled and re-judged <b>byte for byte</b> before it is written to the tree. Anything that doesn't re-verify is listed in <code>reconstruct.json</code> instead of shipped. The program's code stays local.";
  const stale = ex && ex.matched != null && ex.matched < ov.matched;
  const bad = "✕ some functions didn't re-verify";
  const ok = "✓ every function in the tree re-verified";
  const what = "functions reconstructed";
  $("srcState").innerHTML = !ex ? `<span class="muted small">Not exported yet.</span>`
    : `<div class="src-line ${ex.identical === false ? "bad" : "ok"}">${ex.identical === false ? bad : ok}</div>
       <div class="src-line">${ex.matched != null ? `${ex.matched.toLocaleString()} of ${ex.functions.toLocaleString()} ${what}` : ""}${stale ? ` · <b>${ov.matched - ex.matched} new matches since</b>` : ""}</div>
       ${ex.path ? `<div class="src-line">${esc(ex.path)}</div>` : ""}`;
  $("srcExport").textContent = ex ? "Export again" : "Export project";
}
$("srcOpen").onclick = () => openFolder();
$("srcExport").onclick = async () => {
  $("srcExport").disabled = true;
  $("expLog").hidden = false;
  $("expResult").innerHTML = "";
  try {
    const { job } = await api("/api/export", { method: "POST", body: { slug: S.slug } });
    const r = await followJob(job, $("expLog"));
    if (S.ov.kind === "native") {
      $("expResult").innerHTML = r.identical === false
        ? `<div class="notice bad"><span><b>Exported with fallbacks.</b> ${(r.fallback || []).length} function(s) didn't re-verify; they are listed with the reason in <code>reconstruct.json</code> and not shipped.</span></div>`
        : `<div class="notice room"><span><b>Every function in the tree re-verified byte for byte.</b> ${r.matched != null ? `${r.matched} of ${r.functions} matched functions reconstructed.` : ""}</span></div><div class="src-line">${esc(r.path)}</div>`;
    } else {
      $("expResult").innerHTML = r.identical === false
        ? `<div class="notice bad"><span><b>Exported, but the rebuild differs.</b> ${esc(r.log.split("\n").filter(Boolean).pop() || "")}</span></div>`
        : `<div class="notice room"><span><b>Rebuilds byte for byte.</b> ${r.matched != null ? `${r.matched} of ${r.functions} functions are C.` : ""}</span></div>${cmdBox(`cd "${r.path}" && python build.py`)}`;
    }
    wireCopies($("expResult"));
    S.ov = await api(`/api/project?slug=${S.slug}`);
    renderSource(S.ov);
  } catch (e) { toast(esc(e.message), "err"); } finally { $("srcExport").disabled = false; }
};

/* ------------------------------------------------------------------ native programs: the plan */
/* Which original source files get decompiled, declared (interface) or left out. Excluding a file
   cascades to everything that calls into it — previewed inline before it applies. */
async function renderNativePlan() {
  if (!S.slug) return;
  let data;
  try { data = await api(`/api/native/plan?slug=${S.slug}`); }
  catch (e) { toast(esc(e.message), "err"); return; }
  paintNativePlan(data);
}

function paintNativePlan(data) {
  const keepScroll = document.scrollingElement ? document.scrollingElement.scrollTop : 0;
  NPSTATE.data = data;
  // Lists already fetched stay on screen: when treatments moved, they are marked stale and
  // refreshed behind the user's back — collapsing them to "loading" threw the scroll away.
  const sig = data.nodes.map((n) => `${n.path}|${n.treatment}|${n.overrides || 0}`).join("\n");
  if (sig !== NPSTATE.sig) {
    NPSTATE.sig = sig;
    for (const entry of NPSTATE.fnCache.values()) entry.stale = true;
  }
  const box = $("nativePlan");
  box.innerHTML = "";
  const head = document.createElement("div");
  head.className = "np-head";
  head.innerHTML = `<h2>Plan · ${esc(data.title)}</h2>
    <p class="muted small">${esc((data.binary.format || "").toUpperCase())} ${esc(data.binary.arch || "")} ${esc(data.binary.kind || "")} — pick what gets decompiled, declared (interface) or left out. A folder's buttons set everything under it; excluding a file also excludes whatever calls into it, and interface stops that cascade.</p>`;
  box.append(head);
  box.append(nativeCompilerCard(data));
  if (!data.analysis) {
    const run = document.createElement("section");
    run.className = "panel np-run";
    run.innerHTML = `<p><b>The analysis hasn't run yet.</b> decomp.wtf asks your IDA (through ida-mcp) to map the binary: files, functions, the call graph, types.</p>
      <div class="row"><button class="primary" id="npAnalyze" type="button">Analyze the binary</button>
      <span class="muted small">needs IDA 9+ with ida-mcp set up once</span></div>
      <pre class="joblog" id="npAnalyzeLog" hidden></pre>`;
    box.append(run);
    run.querySelector("#npAnalyze").onclick = () => runNativeJob("/api/native/analyze", run.querySelector("#npAnalyze"), run.querySelector("#npAnalyzeLog"), "Analysing…");
    return;
  }
  const t = (data.totals && data.totals.treatments) || {};
  const langs = (data.totals && data.totals.languages) || {};
  const sum = document.createElement("div");
  sum.className = "np-summary";
  sum.innerHTML = `<span class="chip-s">${(data.totals.files || 0).toLocaleString()} files</span>
    <span class="chip-s">${(data.totals.functions || 0).toLocaleString()} functions</span>
    <span class="chip-s">${bytes(data.totals.bytes || 0)}</span>
    <span class="chip-s">${t.decompile || 0} decompile</span>
    <span class="chip-s">${t.interface || 0} interface</span>
    <span class="chip-s">${t.exclude || 0} excluded</span>
    ${langs["c++"] ? `<span class="chip-s">${langs["c++"]} C++ files</span>` : ""}
    ${data.confirmed && data.functions ? `<span class="chip-s">confirmed: ${(data.functions.open || 0).toLocaleString()} open · ${(data.functions.matched || 0).toLocaleString()} matched</span>` : ""}`;
  box.append(sum);
  const bar = document.createElement("div");
  bar.className = "np-toolbar";
  const search = document.createElement("input");
  search.className = "search np-search";
  search.type = "search";
  search.placeholder = "Find a file or a function (name or address)";
  search.value = NPSTATE.q;
  search.oninput = () => {
    NPSTATE.q = search.value;
    paintNativeTree();  // narrows the tree by path as before
    clearTimeout(NPSTATE.findTimer);
    NPSTATE.findTimer = setTimeout(renderNativeFind, 200);  // and lists matching functions below
  };
  bar.append(search);
  const expand = document.createElement("button");
  expand.type = "button";
  expand.className = "ghost small-btn";
  expand.title = "Unfold every folder";
  expand.textContent = "Expand all";
  expand.onclick = () => { NPSTATE.closed.clear(); paintNativeTree(); };
  const collapse = document.createElement("button");
  collapse.type = "button";
  collapse.className = "ghost small-btn";
  collapse.title = "Fold everything to the top level";
  collapse.textContent = "Collapse all";
  collapse.onclick = () => { for (const key of npDirKeys(npModel(visibleNodes()))) NPSTATE.closed.add(key); paintNativeTree(); };
  bar.append(expand, collapse);
  const counts = { all: data.nodes.length, decompile: 0, interface: 0, exclude: 0, library: 0 };
  for (const n of data.nodes) {
    counts[n.treatment] = (counts[n.treatment] || 0) + 1;
    if (n.library) counts.library++;
  }
  const filters = document.createElement("div");
  filters.className = "np-filters";
  const show = document.createElement("span");
  show.className = "muted small";
  show.textContent = "Show";
  filters.append(show);
  for (const [k, label] of [["all", "All"], ["decompile", "Decompile"], ["interface", "Interface"], ["exclude", "Exclude"], ["library", "Library"]]) {
    const b = document.createElement("button");
    b.type = "button";
    b.className = "np-filter" + (NPSTATE.filter === k ? " on" : "");
    b.innerHTML = `${label} <span>${counts[k]}</span>`;
    b.onclick = () => { NPSTATE.filter = k; paintNativePlan(NPSTATE.data); };
    filters.append(b);
  }
  bar.append(filters);
  // One decision for everything the filter shows — with no filter, every file. This is the way
  // to carve a subset out of a global choice: exclude all, search a path, set the ones shown.
  const shownBulk = document.createElement("div");
  shownBulk.className = "np-set-shown";
  shownBulk.title = "One decision for every file the filter shows — with no filter, that is all of them";
  const shownLabel = document.createElement("span");
  shownLabel.className = "muted small";
  shownLabel.innerHTML = `Set <b class="np-shown-n">…</b> to`;
  shownBulk.append(shownLabel, segControl(null, (t) => applyNativeTreatments(visibleNodes().map((n) => n.path), t, null)));
  bar.append(shownBulk);
  refreshShownCount();
  box.append(bar);
  const mach = (data.totals && data.totals.machinery) || null;
  if (mach) {
    const total = (mach.plt || 0) + (mach.crt || 0) + (mach.extern || 0);
    if (total) {  // one switch for the linker's own code, wherever it sits
      const line = document.createElement("div");
      line.className = "np-machinery";
      const parts = [["plt", ".plt"], ["crt", "CRT"], ["extern", "extern"]].filter(([k]) => mach[k])
        .map(([k, l]) => `${l} ${mach[k].toLocaleString()}`);
      line.innerHTML = `<span class="muted small">import machinery: <b>${total.toLocaleString()}</b> — ${parts.join(" · ")}</span>`;
      line.append(segControl(data.glue || null, (t) => applyGlueTreatment(t)));
      box.append(line);
    }
  }
  NPSTATE.tree = document.createElement("section");
  NPSTATE.tree.className = "panel np-tree";
  box.append(NPSTATE.tree);
  paintNativeTree();
  NPSTATE.find = document.createElement("section");
  NPSTATE.find.className = "panel np-find";
  NPSTATE.find.hidden = true;
  box.append(NPSTATE.find);
  renderNativeFind();
  const foot = document.createElement("div");
  foot.className = "np-foot";
  foot.innerHTML = `<div class="row"><button class="primary" id="npConfirm" type="button">${data.confirmed ? "Re-confirm the plan" : "Confirm the plan"}</button>
    <button class="ghost small-btn" id="npReanalyze" type="button">Analyze again</button>
    <span class="muted small">Confirming makes the open functions claimable by agents — each file's context.h is generated the first time work starts in it.</span></div>
    ${data.analysis_stale ? `<div class="row"><span class="muted small np-stale">⚠ ${esc(data.analysis_stale)}</span></div>` : ""}
    <pre class="joblog" id="npConfirmLog" hidden></pre>`;
  box.append(foot);
  foot.querySelector("#npConfirm").onclick = () => runNativeJob("/api/native/confirm", foot.querySelector("#npConfirm"), foot.querySelector("#npConfirmLog"), "Confirming…", true);
  foot.querySelector("#npReanalyze").onclick = () => runNativeJob("/api/native/analyze", foot.querySelector("#npReanalyze"), foot.querySelector("#npConfirmLog"), "Analysing…");
  if (document.scrollingElement) document.scrollingElement.scrollTop = keepScroll;
}

const NPSTATE = { data: null, q: "", filter: "all", tree: null, find: null, findSeq: 0, findTimer: null,
                  closed: new Set(), byPath: new Map(),
                  fnOpen: new Set(), fnCache: new Map(), fnLimit: {}, sig: "" };
const NP_CHEV = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M9 5l7 7-7 7"/></svg>';

function visibleNodes() {
  const q = NPSTATE.q.trim().toLowerCase();
  return ((NPSTATE.data && NPSTATE.data.nodes) || []).filter((n) => {
    if (q && !n.path.toLowerCase().includes(q) && !npNorm(n.path).toLowerCase().includes(q)) return false;
    if (NPSTATE.filter === "library") return n.library;
    if (NPSTATE.filter !== "all" && n.treatment !== NPSTATE.filter) return false;
    return true;
  });
}

function refreshShownCount() {
  const el = document.querySelector(".np-shown-n");
  if (!el || !NPSTATE.data) return;
  const total = ((NPSTATE.data && NPSTATE.data.nodes) || []).length;
  const n = visibleNodes().length;
  el.textContent = n === total ? `all ${total.toLocaleString()}`
                              : `the ${n.toLocaleString()} shown (of ${total.toLocaleString()})`;
}

function segControl(current, onPick) {
  const seg = document.createElement("div");
  seg.className = "seg small np-seg";
  for (const [val, label] of [["decompile", "Decompile"], ["interface", "Interface"], ["exclude", "Exclude"]]) {
    const b = document.createElement("button");
    b.type = "button";
    b.dataset.t = val;
    b.textContent = label;
    b.className = current === val ? "on" : "";
    b.onclick = (e) => { e.stopPropagation(); onPick(val, seg); };
    seg.append(b);
  }
  return seg;
}

/* Unit paths come out of real builds in wild shapes (`/a/../../b/.//c.h`): the tree groups and shows
   the normalized path (chains of single-child folders collapse into one row), while every treatment
   still addresses the raw unit path. A folder's buttons act on its whole subtree. */
function npNorm(p) {
  if (!p || p[0] !== "/") return p;
  const out = [];
  for (const seg of p.split("/")) {
    if (!seg || seg === ".") continue;
    if (seg === "..") out.pop();
    else out.push(seg);
  }
  return "/" + out.join("/");
}

function npModel(nodes) {
  const root = { name: "", kids: new Map(), leaves: [], pseudo: [] };
  for (const n of nodes) {
    const norm = npNorm(n.path);
    if (norm[0] !== "/") { root.pseudo.push(n); continue; }
    const parts = norm.split("/").filter(Boolean);
    let cur = root;
    for (const part of parts.slice(0, -1)) {
      if (!cur.kids.has(part)) cur.kids.set(part, { name: part, kids: new Map(), leaves: [] });
      cur = cur.kids.get(part);
    }
    cur.leaves.push(n);
  }
  const compress = (dir) => {
    for (const kid of dir.kids.values()) compress(kid);
    while (!dir.leaves.length && dir.kids.size === 1) {  // /a → /b → /c with nothing between is one row
      const [only] = dir.kids.values();
      dir.name = `${dir.name}/${only.name}`;
      dir.kids = only.kids;
      dir.leaves = only.leaves;
    }
  };
  for (const kid of root.kids.values()) compress(kid);
  return root;
}

function npLeaves(dir) { return [...dir.leaves, ...[...dir.kids.values()].flatMap(npLeaves)]; }

function npDirKeys(model, prefix = "") {
  const out = [];
  for (const kid of model.kids.values()) {
    const full = prefix ? `${prefix}/${kid.name}` : kid.name;
    out.push(full, ...npDirKeys(kid, full));
  }
  return out;
}

function paintNativeTree() {
  const tree = NPSTATE.tree;
  if (!tree) return;
  refreshShownCount();  // the search narrows what "set the shown" addresses
  tree.innerHTML = "";
  const nodes = visibleNodes();
  if (!nodes.length) {
    tree.innerHTML = `<p class="muted small">No files match this filter.</p>`;
    return;
  }
  NPSTATE.byPath = new Map(nodes.map((n) => [n.path, n]));
  const model = npModel(nodes);
  const filtering = Boolean(NPSTATE.q.trim()) || NPSTATE.filter !== "all";  // never hide a match in a fold
  const paintDir = (dir, prefix, depth) => {
    const full = prefix ? `${prefix}/${dir.name}` : dir.name;
    const leaves = npLeaves(dir);
    const open = filtering || !NPSTATE.closed.has(full);
    const row = document.createElement("div");
    row.className = "np-dir";
    row.style.paddingLeft = `${16 + depth * 15}px`;
    const tw = document.createElement("button");
    tw.type = "button";
    tw.className = "np-tw" + (open ? " open" : "");
    tw.title = open ? "fold this folder" : "unfold this folder";
    tw.innerHTML = NP_CHEV;
    tw.onclick = () => { if (open) NPSTATE.closed.add(full); else NPSTATE.closed.delete(full); paintNativeTree(); };
    const label = document.createElement("span");
    label.className = "np-dirlabel mono";
    label.title = full;
    label.textContent = dir.name;
    label.onclick = tw.onclick;
    const meta = document.createElement("span");
    meta.className = "muted small";
    const fns = leaves.reduce((a, n) => a + (n.functions || 0), 0);
    meta.textContent = `${leaves.length} file${leaves.length === 1 ? "" : "s"}${fns ? ` · ${fns.toLocaleString()} fn` : ""}`;
    row.append(tw, label, meta);
    const kinds = new Set(leaves.map((n) => (NPSTATE.byPath.get(n.path) || {}).treatment));
    row.append(segControl(kinds.size === 1 ? [...kinds][0] : null,
                          (t) => applyNativeTreatments(leaves.map((n) => n.path), t, row)));
    tree.append(row);
    if (!open) return;
    for (const kid of [...dir.kids.values()].sort((a, b) => a.name.localeCompare(b.name))) paintDir(kid, full, depth + 1);
    for (const n of [...dir.leaves].sort((a, b) => npNorm(a.path).localeCompare(npNorm(b.path)))) paintUnit(n, depth + 1, tree);
  };
  const paintUnit = (n, depth, tree) => {
    tree.append(nativeRow(n, depth));
    if (!NPSTATE.fnOpen.has(n.path)) return;
    const entry = NPSTATE.fnCache.get(n.path);
    if (!entry) {  // fetch the leaves the first time this file is unfolded
      NPSTATE.fnCache.set(n.path, { list: [], stale: true, fetching: false });
      const loading = document.createElement("div");
      loading.className = "np-fnrow muted small";
      loading.style.paddingLeft = `${(depth + 1) * 15 + 54}px`;
      loading.textContent = "loading functions…";
      tree.append(loading);
      loadUnit(n.path);
      return;
    }
    if (entry.stale && !entry.fetching) loadUnit(n.path);  // refresh quietly under the rendered rows
    const fns = entry.list;
    const shown = NPSTATE.fnLimit[n.path] || 300;
    for (const fn of fns.slice(0, shown)) tree.append(fnLeaf(n, fn, depth + 1));
    if (fns.length > shown) {
      const more = document.createElement("button");
      more.type = "button";
      more.className = "ghost small-btn np-fnrow-more";
      more.style.marginLeft = `${(depth + 1) * 15 + 54}px`;
      more.textContent = `Show ${Math.min(1000, fns.length - shown).toLocaleString()} more of ${fns.length.toLocaleString()}`;
      more.onclick = () => { NPSTATE.fnLimit[n.path] = shown + 1000; paintNativeTree(); };
      tree.append(more);
    }
  };
  for (const kid of [...model.kids.values()].sort((a, b) => a.name.localeCompare(b.name))) paintDir(kid, "", 0);
  for (const n of model.pseudo) paintUnit(n, 0, tree);
}

function loadUnit(path) {
  const entry = NPSTATE.fnCache.get(path) || {};
  entry.fetching = true;
  NPSTATE.fnCache.set(path, entry);
  api(`/api/native/unit?slug=${S.slug}&path=${encodeURIComponent(path)}`).then((d) => {
    NPSTATE.fnCache.set(path, { list: d.functions || [], stale: false, fetching: false });
    paintNativeTree();
  }).catch(() => { entry.fetching = false; });
}

/* the search bar's other half: functions matching the query, wherever they live — each row takes
   the same treatments as a tree leaf, so a function can be found (and picked) without unfolding */
async function renderNativeFind() {
  const box = NPSTATE.find;
  if (!box) return;
  const q = NPSTATE.q.trim();
  if (!q) {
    box.hidden = true;
    box.innerHTML = "";
    return;
  }
  const seq = ++NPSTATE.findSeq;
  let res;
  try { res = await api(`/api/native/find?slug=${S.slug}&q=${encodeURIComponent(q)}&limit=200`); }
  catch (e) { return; }
  if (seq !== NPSTATE.findSeq || !NPSTATE.find || box !== NPSTATE.find) return;  // a newer keystroke won
  box.hidden = false;
  box.innerHTML = "";
  const head = document.createElement("p");
  head.className = "np-findhead";
  head.innerHTML = `<b>${res.total.toLocaleString()} function${res.total === 1 ? "" : "s"}</b> match “${esc(q)}”`
    + (res.total > res.functions.length ? ` — showing the first ${res.functions.length.toLocaleString()}` : "")
    + ` <span class="muted small">— pick answers right here; the tree above still narrows by file</span>`;
  box.append(head);
  if (!res.functions.length) return;
  for (const fn of res.functions) box.append(nativeFindRow(fn));
}

function nativeFindRow(fn) {
  const row = document.createElement("div");
  row.className = "np-fnrow np-findrow";
  const name = document.createElement("span");
  name.className = "np-fnname mono";
  name.title = `${fn.display || fn.name}\n0x${(fn.vram || fn.ea).toString(16).toUpperCase()} · ${fn.size} B · ${fn.unit}`;
  name.textContent = fn.display || fn.name;
  name.onclick = () => openFn(fn.name);
  const where = document.createElement("span");
  where.className = "muted small np-findunit";
  where.textContent = String(fn.unit || "").split("/").slice(-2).join("/") || "(no file)";
  where.title = String(fn.unit || "") || "(no file)";
  const meta = document.createElement("span");
  meta.className = "muted small";
  meta.textContent = fn.size >= 1024 ? bytes(fn.size) : `${fn.size} B`;
  const chips = document.createElement("span");
  chips.className = "np-badges";
  const glue = { plt: ".plt", crt: "CRT", extern: "extern" }[fn.glue] || fn.glue;
  chips.innerHTML = fn.status === "matched" ? '<span class="chip-s">matched</span>'
    : fn.status === "excluded" || fn.status === "interface" ? `<span class="chip-s">${esc(fn.status)}</span>`
    : fn.lib ? '<span class="chip-s">library</span>' : glue ? `<span class="chip-s">${esc(glue)}</span>` : "";
  const grow = document.createElement("span");
  grow.className = "grow";
  row.append(name, where, meta, chips, grow,
             segControl(fn.treatment, (t) => applyFunctionTreatment({ path: fn.unit }, fn, t, row)));
  return row;
}

function updateBulkBar() {
  const bar = NPSTATE.bulk;
  if (!bar) return;
  const n = NPSTATE.sel.size;
  bar.hidden = !n;
  if (!n) return;
  bar.innerHTML = `<span><b>${n}</b> selected</span>`;
  bar.append(segControl(null, (t) => applyNativeTreatments([...NPSTATE.sel], t, null)));
  const clear = document.createElement("button");
  clear.type = "button";
  clear.className = "ghost small-btn";
  clear.textContent = "Clear";
  clear.onclick = () => { NPSTATE.sel.clear(); paintNativePlan(NPSTATE.data); };
  bar.append(clear);
}

function nativeRow(n, depth) {
  const row = document.createElement("div");
  row.className = "np-row";
  row.style.paddingLeft = `${16 + (depth || 0) * 15}px`;  // the twisty shifts the name like a folder's
  const open = NPSTATE.fnOpen.has(n.path);
  const tw = document.createElement("button");
  tw.type = "button";
  tw.className = "np-tw" + (open ? " open" : "");
  tw.title = open ? "fold the functions" : "show the functions in this file";
  tw.innerHTML = NP_CHEV;
  tw.onclick = () => { if (open) NPSTATE.fnOpen.delete(n.path); else NPSTATE.fnOpen.add(n.path); paintNativeTree(); };
  const name = document.createElement("span");
  name.className = "np-name mono";
  name.title = n.path;
  name.textContent = n.name;
  name.onclick = () => toggleNativeDetail(row, n);
  const meta = document.createElement("span");
  meta.className = "muted small";
  meta.textContent = `${n.functions.toLocaleString()} fn`
    + (n.library_functions ? ` · ${n.library_functions.toLocaleString()} library` : "")
    + ` · ${bytes(n.bytes)}`;
  const badges = document.createElement("span");
  badges.className = "np-badges";
  badges.innerHTML = `${n.library ? '<span class="chip-s">library</span>' : ""}${n.language === "c++" ? '<span class="chip-s">C++</span>' : n.language === "asm" ? '<span class="chip-s">asm</span>' : ""}${n.flags && n.flags.length ? `<span class="chip-s" title="this file is judged with its own compiler flags">flags ${esc(n.flags.join(" "))}</span>` : ""}${n.treatment === n.suggested && n.suggested !== "decompile" ? `<span class="chip-s">suggested ${esc(n.suggested)}</span>` : ""}${n.overrides ? `<span class="chip-s" title="some functions here carry their own treatment">${n.overrides.toLocaleString()} picked</span>` : ""}`;
  const grow = document.createElement("span");
  grow.className = "grow";
  const dep = document.createElement("span");
  dep.className = "muted small";
  dep.textContent = n.dependents.length ? `${n.dependents.length} dependents` : "";
  // the file's own control is the everyone switch: it supersedes and clears per-function picks
  row.append(tw, name, meta, badges, grow, dep,
             segControl(n.overrides ? null : n.treatment, (t) => applyNativeTreatments([n.path], t, row)));
  return row;
}

function fnLeaf(n, fn, depth) {
  const row = document.createElement("div");
  row.className = "np-fnrow";
  row.dataset.ea = String(fn.ea);
  row.style.paddingLeft = `${depth * 15 + 54}px`;  // the file's name column
  const name = document.createElement("span");
  name.className = "np-fnname mono";
  name.title = `${fn.name}\n0x${fn.ea.toString(16).toUpperCase()} · ${fn.size} B${fn.status ? " · " + fn.status : ""}`;
  name.textContent = fn.name;
  const meta = document.createElement("span");
  meta.className = "muted small";
  meta.textContent = fn.size >= 1024 ? bytes(fn.size) : `${fn.size} B`;
  row.append(name, meta);
  const chips = document.createElement("span");
  chips.className = "np-badges";
  chips.innerHTML = `${fn.glue ? `<span class="chip-s" title="linker/import machinery">${esc({ plt: ".plt", crt: "CRT", extern: "extern" }[fn.glue] || fn.glue)}</span>` : ""}${fn.lib ? '<span class="chip-s">library</span>' : ""}`;
  row.append(chips);
  const grow = document.createElement("span");
  grow.className = "grow";
  row.append(grow, segControl(fn.treatment, (t) => applyFunctionTreatment(n, fn, t, row)));
  return row;
}

async function applyFunctionTreatment(n, fn, treatment, row) {
  let res;
  try { res = await api("/api/native/treatment", { method: "POST", body: { slug: S.slug, path: n.path, ea: fn.ea, treatment } }); }
  catch (e) { toast(esc(e.message), "err"); return; }
  const entry = NPSTATE.fnCache.get(n.path);  // this list is up to date: update it in place
  if (entry) {
    const cached = entry.list.find((x) => x.ea === fn.ea);
    if (cached) cached.treatment = treatment;
  }
  NPSTATE.sig = res.plan.nodes.map((x) => `${x.path}|${x.treatment}|${x.overrides || 0}`).join("\n");
  toast(`${esc(fn.name)} → <b>${esc(treatment)}</b>`, treatment === "exclude" ? "err" : treatment === "interface" ? "" : "match");
  paintNativePlan(res.plan);
}

async function applyGlueTreatment(treatment) {
  let res;
  try { res = await api("/api/native/glue", { method: "POST", body: { slug: S.slug, treatment } }); }
  catch (e) { toast(esc(e.message), "err"); return; }
  toast(`import machinery (${res.functions.toLocaleString()} functions) → <b>${esc(treatment)}</b>`,
        treatment === "exclude" ? "err" : treatment === "interface" ? "" : "match");
  paintNativePlan(res.plan);
}

function toggleNativeDetail(row, n) {
  const old = row.querySelector(".np-detail");
  if (old) { old.remove(); return; }
  const det = document.createElement("div");
  det.className = "np-detail";
  det.innerHTML = `<div class="mono small np-detail-path" title="click to select the whole path">${esc(n.path)}</div>
    ${n.sample.length ? `<div class="mono small">${n.sample.map(esc).join(" · ")}</div>` : ""}
    ${n.deps.length ? `<div class="small"><span class="muted">depends on:</span> <span class="mono">${n.deps.slice(0, 8).map(esc).join(", ")}${n.deps.length > 8 ? " …" : ""}</span></div>` : ""}
    ${n.dependents.length ? `<div class="small"><span class="muted">called by:</span> <span class="mono">${n.dependents.slice(0, 8).map(esc).join(", ")}${n.dependents.length > 8 ? " …" : ""}</span></div>` : ""}`;
  row.append(det);
}

async function applyNativeTreatments(paths, treatment, anchorRow) {
  const body = { slug: S.slug, paths, treatment };
  let res;
  try { res = await api("/api/native/treatments", { method: "POST", body }); }
  catch (e) { toast(esc(e.message), "err"); renderNativePlan(); return; }
  if (res.applied) {
    toast(paths.length === 1 ? `<code>${esc(paths[0])}</code> → ${treatment}` : `${paths.length} files → ${treatment}`, "match");
    paintNativePlan(res.plan);
    return;
  }
  const forced = res.forced || [];
  const panel = document.createElement("div");
  panel.className = "np-cascade";
  panel.innerHTML = `<div>Excluding ${paths.length === 1 ? `<code>${esc(paths[0])}</code>` : `these ${paths.length} files`} also excludes the ${forced.length} file(s) that call into them:
      <div class="mono small np-cascade-list">${forced.slice(0, 60).map(esc).join(", ")}${forced.length > 60 ? ` … +${forced.length - 60}` : ""}</div></div>
    <div class="row"><button class="primary small-btn np-go" type="button">Exclude ${forced.length + paths.length}</button>
    <button class="ghost small-btn np-stop" type="button">Cancel</button></div>`;
  if (anchorRow) anchorRow.after(panel); else (NPSTATE.tree || $("nativePlan")).prepend(panel);
  panel.querySelector(".np-stop").onclick = () => { panel.remove(); renderNativePlan(); };
  panel.querySelector(".np-go").onclick = async () => {
    panel.remove();
    try {
      const r2 = await api("/api/native/treatments", { method: "POST", body: { ...body, confirm: 1 } });
      paintNativePlan(r2.plan);
    } catch (e) { toast(esc(e.message), "err"); renderNativePlan(); }
  };
}

function nativeCompilerCard(data) {
  const c = data.compiler || {};
  const sec = document.createElement("section");
  sec.className = "panel np-compiler";
  const imgState = c.image ? (c.image_ready
      ? `<span class="ok small np-pulled">pulled ✓</span>`
      : `<button class="primary small-btn np-pull" type="button">Pull the image</button>`)
    : (c.suggested_image ? `<button class="ghost small-btn np-suggest" type="button" title="fill the field with the binary's own compiler — you still save and pull it yourself">use ${esc(c.suggested_image)}</button>` : "");
  sec.innerHTML = `<header class="panel-head"><h2>Compiler</h2><span class="muted small">${c.detected && c.detected.length ? `built with ${esc(c.detected.map((d) => d.compiler).join(", "))}` : ""}</span></header>
    <div class="row">
      <label class="field grow"><span>Driver (empty = auto-detect)</span><input class="mono np-cmd" placeholder="gcc / clang++ / zig cc -target x86_64-linux-gnu" value="${esc(c.command || "")}"></label>
      <label class="field grow"><span>Flags</span><input class="mono np-flags" placeholder="-O2 -fPIC" value="${esc((c.flags || []).join(" "))}"></label>
    </div>
    <div class="row">
      <label class="field grow"><span>Compile in container image (empty = on this machine)</span><input class="mono np-img" title="nothing runs in docker until you save an image and pull it" placeholder="gcc:8.1.0" value="${esc(c.image || "")}"></label>
      <button class="ghost small-btn np-save" type="button">Save</button>
      ${imgState}
    </div>
    <p class="muted small np-note">${c.error ? `<b class="bad">⚠ ${esc(c.error)}</b>` : esc(c.driver ? `${c.driver} — ${c.note}` : (c.note || "auto-detected"))}</p>`;
  const note = () => sec.querySelector(".np-note");
  const pull = sec.querySelector(".np-pull");
  if (pull) {
    pull.onclick = async () => {
      pull.disabled = true;
      pull.textContent = "Pulling…";
      try {
        const { job } = await api("/api/native/pull", { method: "POST", body: { slug: S.slug } });
        await followJob(job, null, (lines) => { note().textContent = String(lines[lines.length - 1] || "pulling…").slice(0, 220); });
        toast("Image pulled — compiles run in it from now on.", "match");
        await renderNativePlan();
      } catch (e) {
        note().innerHTML = `<b class="bad">⚠ ${esc(e.message)}</b>`;
        toast(esc(e.message), "err");
        pull.disabled = false;
        pull.textContent = "Pull the image";
      }
    };
  }
  const suggest = sec.querySelector(".np-suggest");
  if (suggest) suggest.onclick = () => { sec.querySelector(".np-img").value = c.suggested_image; sec.querySelector(".np-img").focus(); };
  sec.querySelector(".np-save").onclick = async () => {
    try {
      const r = await api("/api/native/compiler", { method: "POST", body: { slug: S.slug, command: sec.querySelector(".np-cmd").value, flags: sec.querySelector(".np-flags").value, image: sec.querySelector(".np-img").value } });
      toast(r.error ? "Saved — the compiler needs one more step below." : `Compiler saved: ${r.driver}`, r.error ? "" : "match");
      await renderNativePlan();  // the card comes back with the Pull button / state for the image
    } catch (e) { toast(esc(e.message), "err"); }
  };
  return sec;
}

async function runNativeJob(endpoint, btn, logEl, busyText, reopen) {
  if (btn) { btn.disabled = true; btn.textContent = busyText; }
  if (logEl) { logEl.hidden = false; logEl.textContent = ""; }
  try {
    const { job } = await api(endpoint, { method: "POST", body: { slug: S.slug } });
    await followJob(job, logEl);
    if (reopen) { await openProject(S.slug); return; }
    await renderNativePlan();
  } catch (e) {
    toast(esc(e.message), "err");
    if (btn) { btn.disabled = false; btn.textContent = reopen ? "Confirm the plan" : "Analyze the binary"; }
  }
}

/* ------------------------------------------------------------------ project settings */
async function renderProjectSettings() {
  const ov = S.ov;
  if (!ov) return;
  if (!S.st) await loadState();
  $("compilerPanel").hidden = false;  // the flags card is the native compiler setting
  $("setTc").closest("label")?.remove();  // no toolchain picker in this build
  $("setFlags").value = (ov.compiler.flags || []).join(" ");
  const facts = [["Platform", ov.platform_name], ["Program", ov.binary?.name || ov.title],
    ["Format", `${(ov.binary?.format || "").toUpperCase()} ${ov.binary?.arch || ""}`.trim()],
    ["Compiler", ov.compiler.name ? `${ov.compiler.name}${(ov.compiler.flags || []).length ? " " + ov.compiler.flags.join(" ") : ""}` : ov.compiler.command || "—"],
    ["Functions", `${ov.functions.toLocaleString()} (${bytes(ov.bytes || 0)} of code)`], ["Folder", ov.folder]];
  $("projFacts").innerHTML = facts.map(([k, v]) => `<div><dt>${esc(k)}</dt><dd>${esc(v || "—")}</dd></div>`).join("");
}
$("setTcReset").onclick = () => { $("setFlags").value = ""; };
$("setTcSave").onclick = async () => {
  try {
    const flags = $("setFlags").value.trim();
    S.ov = await api("/api/compiler", { method: "POST", body: { slug: S.slug, flags: flags ? flags.split(/\s+/) : null } });
    renderStats(S.ov);
    renderProjectSettings();
    toast("Compiler settings saved.");
  } catch (e) { toast(esc(e.message), "err"); }
};
$("folderBtn").onclick = () => openFolder();
$("deleteBtn").onclick = () => {
  dialog("Remove project", `<p>Remove <b>${esc(S.ov.title)}</b> from decomp.wtf? Matched functions and notes are deleted.</p>
    <label class="check"><input type="checkbox" id="delFiles"><span>Also delete the project folder (your copy of the program and exported sources in it)</span></label>
    <div class="row"><button class="primary" id="delGo" type="button">Remove</button><button class="ghost" data-close type="button">Cancel</button></div>`);
  $("delGo").onclick = async () => {
    try {
      await api("/api/delete", { method: "POST", body: { slug: S.slug, files: $("delFiles").checked } });
      $("dialog").hidden = true;
      document.body.classList.remove("locked");
      loadNav();
      location.hash = "#/";
    } catch (e) { toast(esc(e.message), "err"); }
  };
};

/* ------------------------------------------------------------------ agents & models page */
async function showAgentsPage() {
  show("agentsPage");
  $("agList").innerHTML = `<p class="muted small">Looking for your agents…</p>`;
  await loadState();
  renderAgentsPage();
}
function renderAgentsPage() {
  const rows = S.st.agents.filter((a) => a.id !== "api");
  $("agList").innerHTML = rows.map((a) => `<div class="agent-row">
      <div class="ar-head"><b>${esc(a.name)}</b><span class="muted small">${esc(a.vendor)}</span><span class="grow"></span>
        ${a.installed ? `<span class="ok-mark">installed</span>` : `<button class="primary small-btn" data-inst="${esc(a.id)}" type="button" ${a.needs ? "disabled" : ""}>Install</button>`}</div>
      ${a.installed ? `<dl class="facts"><div><dt>Version</dt><dd>${esc(a.version || "?")}</dd></div><div><dt>Default model</dt><dd>${esc(a.default_model || "the app's own")}</dd></div><div><dt>Models offered</dt><dd>${(a.models || []).length ? (a.models || []).length : "any you type"}</dd></div></dl>
        ${(a.models || []).length ? `<div class="model-chips">${a.models.slice(0, 12).map((m) => `<span class="chip-s mono" title="${esc(m.note || "")}">${esc(m.name)}</span>`).join("")}${a.models.length > 12 ? `<span class="muted small">+${a.models.length - 12} more</span>` : ""}</div>` : ""}
        <p class="muted small">${esc(a.signin)}</p>`
      : `<p class="muted small">${a.needs ? `Needs ${esc(a.needs)} first. ` : ""}Or install it yourself:</p>${cmdBox(a.install)}`}
      <pre class="joblog" data-ilog="${esc(a.id)}" hidden></pre></div>`).join("");
  wireCopies($("agList"));
  $("agList").querySelectorAll("[data-inst]").forEach((b) => {
    b.onclick = async () => {
      const log = $("agList").querySelector(`[data-ilog="${b.dataset.inst}"]`);
      log.hidden = false; b.disabled = true;
      try {
        const { job } = await api("/api/agents/install", { method: "POST", body: { kind: b.dataset.inst } });
        await followJob(job, log);
        toast("Installed.", "match");
        showAgentsPage();
      } catch (e) { toast(esc(e.message), "err"); b.disabled = false; }
    };
  });
  const eps = S.st.settings.endpoints || [];
  const card = (e) => `<div class="ep-card" data-id="${esc(e.id || "")}">
      ${e.id ? `<div class="ar-head"><b>${esc(e.name)}</b><span class="muted small mono">${esc(e.model)} · ${esc(hostOf(e.base_url))}</span></div>` : `<div class="ar-head"><b>A new endpoint</b></div>`}
      <div class="lz-fields">${endpointFields(e)}</div>
      <div class="row"><button class="primary small-btn" data-save type="button">${e.id ? "Save" : "Add"}</button>
        ${e.has_key ? `<button class="ghost small-btn" data-forget type="button">Forget the key</button>` : ""}
        ${e.id ? `<button class="ghost small-btn danger" data-remove type="button">Remove</button>` : eps.length ? `<button class="ghost small-btn" data-cancel type="button">Cancel</button>` : ""}</div></div>`;
  $("apiBox").innerHTML = `<p class="muted small">Any OpenAI-compatible API runs through decomp.wtf's built-in agent loop: DeepSeek, OpenRouter, OpenAI, or models on your own machines with llama.cpp, Ollama or LM Studio. Save one endpoint per machine or provider: when you start agents you tick the ones to use, and the sessions are spread across them. Each key stays on this computer and is only sent to its own endpoint.</p>
    ${eps.map(card).join("")}
    <div id="epNew" ${eps.length && !S.addingEndpoint ? "hidden" : ""}>${card({ provider: "custom" })}</div>
    ${eps.length && !S.addingEndpoint ? `<div class="row"><button class="ghost small-btn" id="epAdd" type="button">Add an endpoint</button></div>` : ""}
    <p class="muted small">Context size, for a local model: what you started it with (found by itself from llama.cpp). The agent keeps its conversation within it. Give it at least 16384 (llama.cpp: <code>-c 16384</code>; Ollama: <code>OLLAMA_CONTEXT_LENGTH=16384</code>, or it quietly cuts the start off). Sessions at once: for a machine that serves one request at a time, 1.</p>`;
  wireEndpointFields($("apiBox"));
  const post = async (body, said) => {
    try {
      S.st.settings = await api("/api/settings", { method: "POST", body });
      S.addingEndpoint = false;
      if (said) toast(said);
      renderAgentsPage();
    } catch (e) { toast(esc(e.message), "err"); }
  };
  $("apiBox").querySelectorAll(".ep-card").forEach((c) => {
    const id = c.dataset.id;
    c.querySelector("[data-save]").onclick = () => post({ endpoint: endpointData(c, id) }, id ? "Saved." : "Added. Tick it when you start agents (“API key”).");
    const forget = c.querySelector("[data-forget]"), remove = c.querySelector("[data-remove]"), cancel = c.querySelector("[data-cancel]");
    if (forget) forget.onclick = () => post({ endpoint: { id, clear_key: true } }, "The key is gone from this computer.");
    if (remove) remove.onclick = () => post({ remove_endpoint: id }, "Removed.");
    if (cancel) cancel.onclick = () => { S.addingEndpoint = false; renderAgentsPage(); };
  });
  if ($("epAdd")) $("epAdd").onclick = () => { S.addingEndpoint = true; renderAgentsPage(); };
  $("mcpBox").innerHTML = `<p class="muted small">Connect the agent you talk to, once. Then ask it in your terminal: <i>“decompile my game at ~/roms/game.z64”</i>. It imports it, opens this view and works with every tool here.</p>
    <div class="setup-group" id="mcpRows"><p class="muted small">Looking…</p></div>
    <p class="col-title">Any other MCP client (Cursor, Claude Desktop, Windsurf…)</p><pre class="code" id="mcpJson"></pre>
    <p class="col-title">A client that connects by URL (HTTP MCP)</p>
    <p class="muted small">It needs a token: a password for this app's tools, so keep it to yourself. Making a new one for the same name replaces the old one.</p>
    <div class="lz-row"><label class="field"><span>Name it goes by</span><input id="mcpName" class="mono" value="http-client"></label><button class="ghost small-btn" id="mcpToken" type="button">Make a token</button></div>
    <pre class="code" id="mcpHttp" hidden></pre>`;
  connectRows($("mcpRows")).then((r) => { if (r) $("mcpJson").textContent = JSON.stringify({ mcpServers: { decomp: { command: r.bridge[0], args: r.bridge.slice(1) } } }, null, 2); });
  $("mcpToken").onclick = async () => {
    try {
      const t = await api("/api/agents/token", { method: "POST", body: { name: $("mcpName").value.trim() || "http-client" } });
      $("mcpHttp").hidden = false;
      $("mcpHttp").textContent = JSON.stringify({ mcpServers: { decomp: { type: "http", url: t.url, headers: { Authorization: `Bearer ${t.token}` } } } }, null, 2);
    } catch (e) { toast(esc(e.message), "err"); }
  };
}
$("agRefresh").onclick = showAgentsPage;

/* ------------------------------------------------------------------ compilers & tools page */
async function showToolsPage() {
  show("toolsPage");
  const st = await loadState();
  const ps = st.platform_status || {};
  const names = { elf: "ELF · Linux", pe: "PE · Windows", macho: "Mach-O · macOS", android: "ELF · Android" };
  $("toolChips").innerHTML = "";
  $("toolGrid").innerHTML = Object.entries(names).map(([k, label]) => {
    const note = ps[k] || "";
    const ready = note === "ready";
    return `<div class="tool-card ${ready ? "ok" : ""}"><div class="tc-top"><b>${label}</b>${ready ? `<span class="ok-mark">✓ ready</span>` : `<span class="chip-s warn">partial</span>`}</div>
      <p class="muted small">${esc(note)}</p></div>`;
  }).join("") + `<div class="tool-card"><div class="tc-top"><b>Analysis backends</b></div><p class="muted small">IDA (through ida-mcp) is wired end to end and reuses an existing .i64 database. Ghidra sits behind the same adapter interface; its implementation is a later phase.</p></div>`;
}

/* ------------------------------------------------------------------ settings page */
async function showSettingsPage() {
  show("settingsPage");
  const st = await loadState();
  $("setAgents").innerHTML = `
    <label class="field"><span>Functions per agent session (a fresh session keeps the agent's context small)</span><input id="perSession" type="number" min="1" max="20" value="${st.settings.per_session}"></label>
    <label class="field"><span>Budget: stop helper agents when a project's agents have spent this much (US dollars, as the agents report it; 0 = no limit)</span><input id="budgetSet" type="number" min="0" step="0.5" value="${st.settings.budget_usd || 0}"></label>
    <label class="check"><input type="checkbox" id="autopilotSet" ${st.settings.autopilot !== false ? "checked" : ""}><span><b>Autopilot after each import</b>: try every function's machine draft first, so free matches cost no agent time.</span></label>`;
  const theme = savedTheme();
  $("setComputer").innerHTML = `
    <div class="field"><span>Appearance</span><div class="seg" id="themeSeg">${[["", "System"], ["light", "Light"], ["dark", "Dark"]].map(([k, l]) => `<button type="button" data-theme="${k}" class="${theme === k ? "on" : ""}">${l}</button>`).join("")}</div></div>
    <div class="field"><span>Projects live in</span>${cmdBox(st.home)}</div>`;
  const where = { wsl: " (in its own WSL 2 Linux)", docker: " (in Docker)" }[st.runtime] || "";
  $("setAbout").innerHTML = `<p class="small">decomp.wtf ${esc(st.version)} on ${esc(st.platform)}${esc(where)}. Free and open source (MIT). Everything runs on this computer: no account, nothing sent to us.</p>
    <div class="field"><span>Projects live in</span>${cmdBox(st.home)}</div>`;
  wireCopies($("setComputer"));
  const save = (body, msg) => api("/api/settings", { method: "POST", body }).then((s) => { S.st.settings = s; toast(msg); }).catch((e) => toast(esc(e.message), "err"));
  $("perSession").onchange = () => save({ per_session: Number($("perSession").value) }, "Saved.");
  $("autopilotSet").onchange = () => save({ autopilot: $("autopilotSet").checked }, "Saved.");
  $("budgetSet").onchange = () => save({ budget_usd: Number($("budgetSet").value) || 0 }, "Budget saved.");
}

$("quitBtn").onclick = async () => {
  if (!confirm("Quit decomp.wtf? Running agents stop.")) return;
  await api("/api/quit", { method: "POST" }).catch(() => {});
  document.body.innerHTML = `<main class="view"><p class="muted">decomp.wtf has stopped. You can close this tab.</p></main>`;
};

loadNav();
route();
