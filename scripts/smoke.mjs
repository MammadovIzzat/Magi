// Loads the real UI in a headless browser and fails on a blank screen.
//
//   node scripts/smoke.mjs
//
// `node --check` only catches syntax. A ReferenceError inside a render function is
// perfectly valid syntax and produces an app that starts, serves, answers the API —
// and paints nothing. That shipped once; this is here so it cannot ship again.
import { spawn, spawnSync } from 'node:child_process';
import { rmSync } from 'node:fs';

const PORT = 45997;
const PROFILE = '/tmp/magi-smoke-profile';
const BROWSERS = ['google-chrome-stable', 'google-chrome', 'chromium', 'chromium-browser'];
const has = (c) => spawnSync('sh', ['-c', `command -v ${c}`], { stdio: 'ignore' }).status === 0;
const sleep = (ms) => new Promise(r => setTimeout(r, ms));

const browser = BROWSERS.find(has);
if (!browser) {
  console.log('  smoke: no Chromium-based browser installed — skipping UI check');
  process.exit(0);
}

let chrome;
const db = `/tmp/magi-smoke-${process.pid}.db`;
const server = spawn(process.execPath, ['server.js'], {
  env: { ...process.env, MAGI_MFA: 'off', MAGI_PORT: String(PORT), MAGI_DB: db, MAGI_PASS: 'smoketestpass' },
  stdio: ['ignore', 'ignore', 'inherit'],
});

const cleanup = () => {
  try { chrome?.kill(); } catch {}
  try { server.kill(); } catch {}
  for (const s of ['', '-wal', '-shm']) rmSync(db + s, { force: true });
  try { rmSync(PROFILE, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 }); } catch {}
};
const die = (msg) => { console.error(`\n  SMOKE FAILED: ${msg}\n`); cleanup(); process.exit(1); };

for (let i = 0; i < 60; i++) {
  try { await fetch(`http://127.0.0.1:${PORT}/api/me`); break; } catch { await sleep(200); }
}

rmSync(PROFILE, { recursive: true, force: true });
chrome = spawn(browser, ['--headless=new', '--remote-debugging-port=9402', '--no-first-run',
  `--user-data-dir=${PROFILE}`, 'about:blank'], { stdio: 'ignore' });

let targets;
for (let i = 0; i < 80; i++) {
  try { targets = await (await fetch('http://localhost:9402/json')).json(); if (targets.length) break; } catch {}
  await sleep(250);
}
if (!targets?.length) die('headless browser never came up');

const ws = new WebSocket(targets.find(t => t.type === 'page').webSocketDebuggerUrl);
await new Promise(r => ws.addEventListener('open', r, { once: true }));
let id = 0; const pend = new Map(); const errors = [];
ws.addEventListener('message', (e) => {
  const m = JSON.parse(e.data);
  if (m.method === 'Runtime.exceptionThrown') {
    errors.push(m.params.exceptionDetails.exception?.description || m.params.exceptionDetails.text);
  }
  if (m.id && pend.has(m.id)) { pend.get(m.id)(m.result); pend.delete(m.id); }
});
const cdp = (method, params = {}) => new Promise(res => {
  const n = ++id; pend.set(n, res); ws.send(JSON.stringify({ id: n, method, params }));
});
const ev = async (expr) => (await cdp('Runtime.evaluate', {
  expression: `(async()=>{${expr}})()`, awaitPromise: true, returnByValue: true,
})).result?.value;

await cdp('Runtime.enable'); await cdp('Page.enable');
await cdp('Page.navigate', { url: `http://127.0.0.1:${PORT}` });
await sleep(2500);

const checks = [];
checks.push(['login screen paints', await ev('return !!document.querySelector(".login-card .btn.gold")')]);
checks.push(['sign in works', await ev(`
  const f = document.querySelector(".login-box");
  f.querySelector("input[name=username]").value = "admin";
  f.querySelector("input[name=password]").value = "smoketestpass";
  f.dispatchEvent(new Event("submit", { cancelable: true, bubbles: true }));
  await new Promise(r => setTimeout(r, 1500));
  return !!document.querySelector(".acct")`)]);
// Auth is now a Bearer JWT the app keeps in localStorage — no cookie. Verify it was stored, and
// make the test's own raw fetch() calls carry it too (the app's api() already does).
checks.push(['login stores a bearer token + requests carry it', await ev(`
  const t = localStorage.getItem("magi.jwt");
  if (!t) return false;
  const _f = window.fetch.bind(window);
  window.fetch = (u, o = {}) => {
    const h = new Headers(o.headers || {});
    if (!h.has("authorization")) h.set("authorization", "Bearer " + localStorage.getItem("magi.jwt"));
    return _f(u, { ...o, headers: h });
  };
  return (await _f("/api/me", { headers: { authorization: "Bearer " + t } })).status === 200`)]);
checks.push(['engagements screen paints', await ev(`
  const j = async (u, o) => (await fetch(u, { headers: { "content-type": "application/json" }, ...o })).json();
  const p = await j("/api/projects", { method: "POST", body: JSON.stringify({ name: "smoke" }) });
  const asset = await j("/api/projects/" + p.id + "/assets", { method: "POST", body: JSON.stringify({ grp: "external", label: "smoke ext" }) });
  await j("/api/assets/" + asset.id + "/targets", { method: "POST", body: JSON.stringify({ type: "web", label: "https://smoke.test" }) });
  // setting an already-empty hash fires no hashchange, and reloading would destroy
  // this execution context, so re-render by calling the router directly
  await route(); await new Promise(r => setTimeout(r, 600));
  return document.querySelectorAll(".prow").length > 0`)]);
checks.push(['asset folder screen paints', await ev(`
  const p = (await (await fetch("/api/projects")).json())[0];
  const d = await (await fetch("/api/projects/" + p.id)).json();
  location.hash = "#/asset/" + d.assets[0].id; await new Promise(r => setTimeout(r, 1200));
  return document.querySelectorAll(".trow").length > 0`)]);
checks.push(['target notebook + findings dock render', await ev(`
  const p = (await (await fetch("/api/projects")).json())[0];
  const d = await (await fetch("/api/projects/" + p.id)).json();
  const f = await (await fetch("/api/assets/" + d.assets[0].id)).json();
  location.hash = "#/target/" + f.targets[0].id; await new Promise(r => setTimeout(r, 1400));
  const hasNotebook = !!document.querySelector(".nb-wrap .nb-input");
  const hasTools = !!document.querySelector(".task-tools");
  const hasDock = /Findings/.test(document.querySelector(".dock-head")?.textContent || "");
  // type Markdown (header, table, task) into the notebook, let it autosave, confirm it persisted
  const ta = document.querySelector(".nb-input");
  ta.value = "## Recon\\n\\n| A | B |\\n| --- | --- |\\n| 1 | 2 |\\n\\n- [ ] revisit login"; ta.dispatchEvent(new Event("input", { bubbles: true }));
  await new Promise(r => setTimeout(r, 900));
  const saved = await (await fetch("/api/targets/" + f.targets[0].id)).json();
  const persisted = /Recon/.test(saved.notebook || "");
  // Split shows the editor AND the live preview together; the preview renders H2, a table and a task box
  [...document.querySelectorAll(".nb-tab")].find(b => /Split/.test(b.textContent))?.click();
  await new Promise(r => setTimeout(r, 200));
  const split = !!document.querySelector(".nb-body.split") && !document.querySelector(".nb-body.split .nb-input").hidden && !document.querySelector(".nb-body.split .nb-preview").hidden;
  const rendered = !!document.querySelector(".nb-preview h2") && !!document.querySelector(".nb-preview table.md-table") && !!document.querySelector(".nb-preview input.md-task");
  // Ticking the preview checkbox writes back to the source line (- [ ] -> - [x]) and autosaves.
  const box = document.querySelector(".nb-preview input.md-task");
  box.checked = true; box.dispatchEvent(new Event("change", { bubbles: true }));
  await new Promise(r => setTimeout(r, 800));
  const src2 = await (await fetch("/api/targets/" + f.targets[0].id)).json();
  const toggled = /- \\[x\\] revisit login/.test(src2.notebook || "");
  return hasNotebook && hasTools && hasDock && persisted && split && rendered && toggled`)]);
// Notebook images: upload → referenced by uid → rendered inline (loaded with auth) → served back.
checks.push(['notebook image uploads, renders inline, and serves', await ev(`
  const p = (await (await fetch("/api/projects")).json())[0];
  const d = await (await fetch("/api/projects/" + p.id)).json();
  const f = await (await fetch("/api/assets/" + d.assets[0].id)).json();
  const tid = f.targets[0].id;
  const b64 = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==";
  const bytes = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
  const up = await fetch("/api/targets/" + tid + "/notebook-images", { method: "POST", headers: { "content-type": "image/png", "x-filename": encodeURIComponent("şəkil 7 .png") }, body: bytes });
  const uj = await up.json();
  const uid = uj.uid;
  const randomName = /^image-[0-9a-f]{12}\\.png$/.test(uj.filename || ""); // stored under a fresh random name, not the client's
  await fetch("/api/targets/" + tid + "/notebook", { method: "PATCH", headers: { "content-type": "application/json" }, body: JSON.stringify({ notebook: "# S\\n\\n![shot](nbimg:" + uid + ")" }) });
  await renderTarget(tid); await new Promise(r => setTimeout(r, 500));
  [...document.querySelectorAll(".nb-tab")].find(b => /Preview/.test(b.textContent))?.click();
  await new Promise(r => setTimeout(r, 500));
  const img = document.querySelector(".nb-preview img.nb-img");
  const rendered = !!img && img.dataset.nbimg === uid;
  const loaded = !!img && /^blob:/.test(img.src || "");
  const g = await fetch("/api/notebook-images/" + uid);
  const served = g.status === 200 && (g.headers.get("content-type") || "").startsWith("image/");
  return up.status === 201 && !!uid && randomName && rendered && loaded && served`)]);
// Old kind:note findings (from the pre-notebook layout) surface in a banner and move into the notebook.
checks.push(['old notes surface and move into the notebook', await ev(`
  const p = (await (await fetch("/api/projects")).json())[0];
  const d = await (await fetch("/api/projects/" + p.id)).json();
  const f = await (await fetch("/api/assets/" + d.assets[0].id)).json();
  const tid = f.targets[0].id;
  await fetch("/api/targets/" + tid + "/findings", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ title: "Recon jottings", kind: "note", body: "checked the login and /admin" }) });
  await renderTarget(tid); await new Promise(r => setTimeout(r, 500));
  const banner = document.querySelector(".oldnotes");
  const shown = !!banner && /Recon jottings/.test(banner.textContent) && /checked the login/.test(banner.textContent);
  [...document.querySelectorAll(".oldnotes-hd button")].find(b => /Move into notebook/.test(b.textContent))?.click();
  await new Promise(r => setTimeout(r, 200));
  [...document.querySelectorAll(".modal .actions button")].find(b => /Move into notebook/.test(b.textContent))?.click();
  await new Promise(r => setTimeout(r, 900));
  const t2 = await (await fetch("/api/targets/" + tid)).json();
  const moved = /checked the login/.test(t2.notebook || "") && !(t2.findings || []).some(x => x.kind === "note");
  return shown && moved`)]);
// Toolbar formatting toggles: Bold adds then removes; a heading switches level (H1 -> H2).
checks.push(['notebook toolbar toggles/switches formatting', await ev(`
  const p = (await (await fetch("/api/projects")).json())[0];
  const d = await (await fetch("/api/projects/" + p.id)).json();
  const f = await (await fetch("/api/assets/" + d.assets[0].id)).json();
  location.hash = "#/target/" + f.targets[0].id; await new Promise(r => setTimeout(r, 1200));
  const ta = document.querySelector(".nb-input");
  const btn = (name) => [...document.querySelectorAll(".nb-tb")].find(b => b.title === name);
  const press = (b) => b.dispatchEvent(new MouseEvent("mousedown", { bubbles: true, cancelable: true }));
  const sel = (a, b) => { ta.focus(); ta.setSelectionRange(a, b); };
  ta.value = "hello"; ta.dispatchEvent(new Event("input", { bubbles: true }));
  sel(0, 5); press(btn("Bold")); await new Promise(r => setTimeout(r, 40));
  const boldOn = ta.value === "**hello**";
  sel(0, ta.value.length); press(btn("Bold")); await new Promise(r => setTimeout(r, 40));
  const boldOff = ta.value === "hello";
  sel(0, ta.value.length); press(btn("Heading 1")); await new Promise(r => setTimeout(r, 40));
  const h1 = ta.value === "# hello";
  sel(0, ta.value.length); press(btn("Heading 2")); await new Promise(r => setTimeout(r, 40));
  const h2 = ta.value === "## hello";
  sel(0, ta.value.length); press(btn("Heading 2")); await new Promise(r => setTimeout(r, 40));
  const h2off = ta.value === "hello";
  // combined marks: strike on top of bold, then strike again removes ONLY the strike (keeps bold)
  ta.value = "word"; ta.dispatchEvent(new Event("input", { bubbles: true }));
  sel(0, 4); press(btn("Bold")); await new Promise(r => setTimeout(r, 40));
  sel(0, ta.value.length); press(btn("Strikethrough")); await new Promise(r => setTimeout(r, 40));
  const combined = ta.value.includes("~~") && /\\*\\*word\\*\\*/.test(ta.value);
  sel(0, ta.value.length); press(btn("Strikethrough")); await new Promise(r => setTimeout(r, 40));
  const strikeGone = ta.value === "**word**";
  return boldOn && boldOff && h1 && h2 && h2off && combined && strikeGone`)]);
checks.push(['checklist popup paints', await ev(`
  const p = (await (await fetch("/api/projects")).json())[0];
  const d = await (await fetch("/api/projects/" + p.id)).json();
  const f = await (await fetch("/api/assets/" + d.assets[0].id)).json();
  location.hash = "#/target/" + f.targets[0].id; await new Promise(r => setTimeout(r, 1400));
  // the checklist now lives in a popup opened from the target page
  document.querySelector(".checklist-open")?.click(); await new Promise(r => setTimeout(r, 1000));
  document.querySelectorAll(".checklist-pop .ghdr")[0]?.click(); await new Promise(r => setTimeout(r, 900));
  return document.querySelectorAll(".checklist-pop .item").length > 0`)]);
// A retest target (no checklist) can still be assigned — the assignee control renders on its page and
// the assignment persists (regression: the retest/PoC branches returned before building the control).
checks.push(['retest targets expose an assignee control', await ev(`
  try {
    const p = (await (await fetch("/api/projects")).json())[0];
    const j = async (u, o) => (await fetch(u, { headers: { "content-type": "application/json" }, ...o })).json();
    const rf = await j("/api/projects/" + p.id + "/assets", { method: "POST", body: JSON.stringify({ grp: "retest", label: "retest folder" }) });
    const rt = await j("/api/assets/" + rf.id + "/targets", { method: "POST", body: JSON.stringify({ type: "retest", label: "retest-me" }) });
    location.hash = "#/target/" + rt.id; await new Promise(r => setTimeout(r, 1200));
    const isRetest = /Retest/i.test(document.querySelector(".page .kicker")?.textContent || "");
    const hasCtl = !!document.querySelector(".assign .assign-sel .sel-trigger");
    if (!isRetest || !hasCtl) return false;
    await fetch("/api/targets/" + rt.id + "/assignee", { method: "PATCH", headers: { "content-type": "application/json" }, body: JSON.stringify({ assignee: "admin" }) });
    const saved = await (await fetch("/api/targets/" + rt.id)).json();
    return (saved.assignee || "").includes("admin");
  } catch (e) { return false; }`)]);
// Pasting a multi-line / comma list of subdomains into a spawn box creates one sub-target per host.
checks.push(['paste a list of subdomains spawns a sub-target each', await ev(`
  try {
    const p = (await (await fetch("/api/projects")).json())[0];
    const d = await (await fetch("/api/projects/" + p.id)).json();
    const f = await (await fetch("/api/assets/" + d.assets[0].id)).json();
    const web = f.targets.find(t => t.type === "web" && /smoke\\.test/.test(t.label));
    location.hash = "#/target/" + web.id; await new Promise(r => setTimeout(r, 1200));
    document.querySelector(".checklist-open")?.click(); await new Promise(r => setTimeout(r, 900));
    let inp = null;
    for (let i = 0; i < 25; i++) {
      inp = document.querySelector(".subspawn .sub-input");
      if (inp) break;
      const h = [...document.querySelectorAll(".checklist-pop .ghdr")].find(x => !x.classList.contains("open"));
      if (!h) break; h.click(); await new Promise(r => setTimeout(r, 220));
    }
    if (!inp) return false;
    const dt = new DataTransfer(); dt.setData("text", "aa.smoke.test\\nbb.smoke.test, cc.smoke.test");
    inp.dispatchEvent(new ClipboardEvent("paste", { clipboardData: dt, bubbles: true, cancelable: true }));
    await new Promise(r => setTimeout(r, 60));
    const normalized = inp.value.split(",").map(s => s.trim()).filter(Boolean).length === 3;
    const btn = inp.closest(".sub-add").querySelector("button");
    const label3 = /Add 3 sub-targets/.test(btn.textContent);
    btn.click(); await new Promise(r => setTimeout(r, 1800));
    const f2 = await (await fetch("/api/assets/" + d.assets[0].id)).json();
    const made = ["aa.smoke.test", "bb.smoke.test", "cc.smoke.test"].every(hn => f2.targets.some(t => t.label === hn && t.type === "web"));
    return normalized && label3 && made;
  } catch (e) { return false; }`)]);
// Grading a vuln happens in the grade dialog (admins/editors), which carries a full CVSS 3.1 editor
// (segmented controls, live score) whose applied vector sets the severity. This local admin grades.
checks.push(['CVSS grade dialog: calculator opens, scores, applies a vector', await ev(`
  const p = (await (await fetch("/api/projects")).json())[0];
  const d = await (await fetch("/api/projects/" + p.id)).json();
  const fold = await (await fetch("/api/assets/" + d.assets[0].id)).json();
  const vuln = await (await fetch("/api/targets/" + fold.targets[0].id + "/findings", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ title: "CVSS smoke", kind: "vuln" }) })).json();
  gradeDialog(vuln, () => {}); await new Promise(r => setTimeout(r, 300));
  const hasSev = !!document.querySelector(".modal [data-sel=severity]");
  [...document.querySelectorAll(".modal button")].find(b => /CVSS calculator/i.test(b.textContent))?.click();
  await new Promise(r => setTimeout(r, 150));
  const opts = document.querySelectorAll(".cvss-overlay .cvss-opt");
  const scored = /^[0-9]/.test(document.querySelector(".cvss-badge-n")?.textContent || "");
  // Clicking an option must leave EXACTLY ONE button highlighted in that metric (regression: the
  // handler once compared a data-attribute el() never set, so a click deselected the whole row).
  const conf = [...document.querySelectorAll(".cvss-overlay .cvss-metric")].find(m => /Confidentiality$/.test(m.querySelector(".cvss-mlabel")?.textContent || ""));
  [...conf.querySelectorAll(".cvss-opt")].find(b => b.textContent.trim() === "High (H)").click();
  await new Promise(r => setTimeout(r, 40));
  const oneSelected = conf.querySelectorAll(".cvss-opt.on").length === 1;
  document.querySelector('.cvss-hactions .iconbtn[title=Apply]')?.click();
  await new Promise(r => setTimeout(r, 100));
  const gone = !document.querySelector(".cvss-overlay");
  const sev = document.querySelector(".modal [data-sel=severity]")?.value;
  const cvssVal = document.querySelector(".modal input[name=cvss]")?.value || "";
  return hasSev && opts.length >= 20 && scored && oneSelected && gone && !!sev && cvssVal.includes("AV:")`)]);
// A grader can set severity straight from the vuln card — no admin page needed (works standalone).
// (Call renderTarget directly: the hash is already on this target, so setting it fires no re-render.)
checks.push(['a vuln card exposes a grade control', await ev(`
  document.querySelector('.modal-x')?.click(); await new Promise(r => setTimeout(r, 120));
  const p = (await (await fetch("/api/projects")).json())[0];
  const d = await (await fetch("/api/projects/" + p.id)).json();
  const fold = await (await fetch("/api/assets/" + d.assets[0].id)).json();
  await renderTarget(fold.targets[0].id); await new Promise(r => setTimeout(r, 600));
  return !!document.querySelector(".dock .finding .f-sev.grade")`)]);
// The engagement-wide findings page lists vulnerabilities only — notes live in each target notebook.
checks.push(['the findings page is vulns-only (no note/cred tabs)', await ev(`
  const p = (await (await fetch("/api/projects")).json())[0];
  location.hash = "#/findings/" + p.id; await new Promise(r => setTimeout(r, 1200));
  return document.querySelectorAll(".pf-filter .evtab").length === 0 && !!document.querySelector(".pf-head")`)]);
// The engagement's Subdomains roll-up lists every web/API/domain host (IP targets excluded), deduped,
// with copy / .txt / .json export controls.
checks.push(['subdomains roll-up lists web domains and excludes IPs', await ev(`
  try {
    const p = (await (await fetch("/api/projects")).json())[0];
    const d = await (await fetch("/api/projects/" + p.id)).json();
    const fid = d.assets[0].id;
    const mk = (label, type) => fetch("/api/assets/" + fid + "/targets", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ type, label }) });
    await mk("https://api.smoke.test/v1", "web");   // a subdomain host -> included
    await mk("http://10.1.1.9:8080", "web");        // a web target whose label is a bare IP -> excluded
    location.hash = "#/project/" + p.id; await new Promise(r => setTimeout(r, 1200));
    [...document.querySelectorAll("#topActions .btn")].find(b => /Subdomains/.test(b.textContent))?.click();
    await new Promise(r => setTimeout(r, 400));
    const hosts = [...document.querySelectorAll(".subdom-host")].map(e => e.textContent);
    const hasBoth = hosts.includes("smoke.test") && hosts.includes("api.smoke.test");
    const noIp = !hosts.some(h => h.includes("10.1.1.9"));
    const exports = document.querySelectorAll(".subdom-actions button").length === 3;
    document.querySelector(".modal-x")?.click();
    return hasBoth && noIp && exports;
  } catch (e) { return false; }`)]);
// Engagements gain a 1..5 priority (meter + sort), an Overview landing page, and engagement-level
// assignees. Runs LAST of the project checks — it creates extra engagements, so no earlier
// projects[0] check must follow it.
checks.push(['engagement priority meter, overview + assignees', await ev(`
  try {
    document.querySelector(".modal-x")?.click();
    const j = async (u, o) => (await fetch(u, { headers: { "content-type": "application/json" }, ...o })).json();
    const hi = await j("/api/projects", { method: "POST", body: JSON.stringify({ name: "ZZ Priority Alpha", priority: 5, assignee: "admin" }) });
    await j("/api/projects", { method: "POST", body: JSON.stringify({ name: "ZZ Priority Omega", priority: 1 }) });
    const savedPrio = (await (await fetch("/api/projects/" + hi.id)).json()).priority === 5;
    // home: priority meters render and the priority-5 engagement sorts above the priority-1 one
    location.hash = "#/"; await route(); await new Promise(r => setTimeout(r, 500));
    const meters = document.querySelectorAll(".prow .pmeter").length > 0;
    const names = [...document.querySelectorAll(".prow .pname")].map(e => e.textContent);
    const ai = names.indexOf("ZZ Priority Alpha"), oi = names.indexOf("ZZ Priority Omega");
    const sorted = ai !== -1 && oi !== -1 && ai < oi;
    // overview: a full priority meter + assignee control + an Open-targets action
    location.hash = "#/project/" + hi.id; await new Promise(r => setTimeout(r, 800));
    const ovPrio = document.querySelectorAll(".ov-prio .pmeter .pseg.on").length === 5;
    const ovAssign = !!document.querySelector(".ov-meta .assign .assign-sel .sel-trigger");
    const openBtn = [...document.querySelectorAll("#topActions .btn")].find(b => /Open targets/.test(b.textContent));
    if (!openBtn) return false;
    openBtn.click(); await new Promise(r => setTimeout(r, 700));
    const onTargets = location.hash.includes("/targets") && !!document.querySelector(".srule");
    // engagement assignee endpoint persists a change (display-only, any user may set it)
    await fetch("/api/projects/" + hi.id + "/assignee", { method: "PATCH", headers: { "content-type": "application/json" }, body: JSON.stringify({ assignee: "admin,ana" }) });
    const asg = (await (await fetch("/api/projects/" + hi.id)).json()).assignee || "";
    return savedPrio && meters && sorted && ovPrio && ovAssign && onTargets && asg.includes("ana");
  } catch (e) { return false; }`)]);
checks.push(['template library paints', await ev(`
  location.hash = "#/editor"; await new Promise(r => setTimeout(r, 1400));
  return document.querySelectorAll(".tpl-type").length > 0`)]);
checks.push(['settings screen paints (local)', await ev(`
  location.hash = "#/settings"; await new Promise(r => setTimeout(r, 900));
  return !!document.querySelector(".setcard .linkbadge") && /local/i.test(document.querySelector(".linkbadge")?.textContent || "")`)]);
checks.push(['connect-to-server dialog opens', await ev(`
  [...document.querySelectorAll(".setcard-actions .btn")].find(b => /connect to a server/i.test(b.textContent))?.click();
  await new Promise(r => setTimeout(r, 400));
  return ["server_url","code","device_name"].every(n => document.querySelector(".modal input[name="+n+"]"))`)]);
// Admin is split into tabbed pages; the Ranking page renders a leaderboard. This standalone
// install isn't a server, so force admin context (ME.role is already 'admin' here) and stub the
// admin API, then verify the tab nav and the ranking table actually paint.
checks.push(['admin tabs + ranking page paint', await ev(`
  const real = window.fetch;
  const stub = {
    "/api/link": { unavailable: true },
    "/api/admin/ranking": { ranking: [
      { author: "ana", role: "worker", findings: 7, poc: 3, projects: 2, score: 41, types: { web: 4, poc: 3 }, topType: "web", sev: { critical: 2, high: 3, medium: 2, low: 0, info: 0, none: 0 } },
      { author: "bob", role: "editor", findings: 2, poc: 0, projects: 1, score: 4, types: { ad: 2 }, topType: "ad", sev: { critical: 0, high: 0, medium: 1, low: 1, info: 0, none: 0 } }],
      totals: { operators: 2, findings: 9, unattributed: 1 } },
    "/api/admin/requests": [], "/api/admin/users": [], "/api/admin/enroll-codes": [],
    "/api/admin/devices": [], "/api/admin/audit": [], "/api/admin/backup": { config: {}, backups: [] },
  };
  window.fetch = (u, o) => {
    const p = (typeof u === "string" ? u : u.url || "").split("?")[0];
    for (const k in stub) if (p.endsWith(k)) return Promise.resolve(new Response(JSON.stringify(stub[k]), { status: 200, headers: { "content-type": "application/json" } }));
    return real(u, o);
  };
  LINK = { unavailable: true };
  location.hash = "#/admin/ranking"; await new Promise(r => setTimeout(r, 1000));
  const rankRows = document.querySelectorAll(".ranktable .rankrow").length;
  const hasSev = document.querySelectorAll(".ranktable .sevchip").length > 0;
  const hasScore = /41/.test(document.querySelector(".rankrow .rank-score")?.textContent || "");
  const tabs = document.querySelectorAll(".admtabs .admtab").length;
  const activeIsRanking = /ranking/i.test(document.querySelector(".admtab.on")?.textContent || "");
  location.hash = "#/admin/users"; await new Promise(r => setTimeout(r, 700));
  const usersActive = /users/i.test(document.querySelector(".admtab.on")?.textContent || "");
  // Users page has "New operator"; the connection requests + codes moved to the Devices page.
  const usersHasCreate = [...document.querySelectorAll(".admbody button")].some(b => /new operator/i.test(b.textContent));
  location.hash = "#/admin/devices"; await new Promise(r => setTimeout(r, 700));
  const devicesText = document.querySelector(".admbody")?.textContent || "";
  const devicesHasCodesAndRequests = /connection requests/i.test(devicesText) && /one-time codes/i.test(devicesText);
  window.fetch = real;
  return rankRows === 2 && tabs === 6 && activeIsRanking && usersActive && hasSev && hasScore && usersHasCreate && devicesHasCodesAndRequests`)]);
// Regression: an MFA-enabled account returns 401 {mfa:'required'} on password-only login. The
// login flow must READ that challenge and show the code screen — not treat the 401 as a hard error.
// (This standalone server never enforces MFA, so stub fetch to return the challenge just for the login.)
checks.push(['password step advances to the two-factor screen on an MFA challenge', await ev(`
  showLogin(); await new Promise(r => setTimeout(r, 200));
  const real = window.fetch;
  window.fetch = (u, o) => (typeof u === "string" && u.includes("/api/auth/login"))
    ? Promise.resolve(new Response(JSON.stringify({ error: "a two-factor code is required", mfa: "required" }), { status: 401, headers: { "content-type": "application/json" } }))
    : real(u, o);
  const f = document.querySelector(".login-box");
  f.querySelector("input[name=username]").value = "izzat";
  f.querySelector("input[type=password]").value = "whatever12";
  f.dispatchEvent(new Event("submit", { cancelable: true, bubbles: true }));
  await new Promise(r => setTimeout(r, 500));
  window.fetch = real;
  const onCode = /two-factor/i.test(document.querySelector(".login-hd")?.textContent || "") && !!document.querySelector("input.mfa-code, input[inputmode=numeric]");
  const noError = !(document.querySelector(".loginerr")?.textContent || "").trim();
  return onCode && noError`)]);

ws.close();

let bad = 0;
for (const [name, ok] of checks) { console.log(`  ${ok ? 'ok  ' : 'FAIL'}  ${name}`); if (!ok) bad++; }
if (errors.length) { console.log('\n  uncaught JS errors:'); errors.forEach(e => console.log('   ', String(e).split('\n')[0])); }

cleanup();
if (bad || errors.length) { console.error(`\n  SMOKE FAILED\n`); process.exit(1); }
console.log('\n  smoke ok\n');
