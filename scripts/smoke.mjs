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
checks.push(['checklist screen paints', await ev(`
  const p = (await (await fetch("/api/projects")).json())[0];
  const d = await (await fetch("/api/projects/" + p.id)).json();
  const f = await (await fetch("/api/assets/" + d.assets[0].id)).json();
  location.hash = "#/target/" + f.targets[0].id; await new Promise(r => setTimeout(r, 1400));
  document.querySelectorAll(".ghdr")[0]?.click(); await new Promise(r => setTimeout(r, 700));
  return document.querySelectorAll(".item").length > 0`)]);
checks.push(['template library paints', await ev(`
  location.hash = "#/editor"; await new Promise(r => setTimeout(r, 1400));
  return document.querySelectorAll(".tpl-type").length > 0`)]);
checks.push(['settings screen paints (local)', await ev(`
  location.hash = "#/settings"; await new Promise(r => setTimeout(r, 900));
  return !!document.querySelector(".setcard .linkbadge") && /local/i.test(document.querySelector(".linkbadge")?.textContent || "")`)]);
checks.push(['connect-to-server dialog opens', await ev(`
  [...document.querySelectorAll(".setcard-actions .btn")].find(b => /connect to a server/i.test(b.textContent))?.click();
  await new Promise(r => setTimeout(r, 400));
  return ["server_url","code","username","display_name"].every(n => document.querySelector(".modal input[name="+n+"]"))`)]);
// Admin is split into tabbed pages; the Ranking page renders a leaderboard. This standalone
// install isn't a server, so force admin context (ME.role is already 'admin' here) and stub the
// admin API, then verify the tab nav and the ranking table actually paint.
checks.push(['admin tabs + ranking page paint', await ev(`
  const real = window.fetch;
  const stub = {
    "/api/link": { unavailable: true },
    "/api/admin/ranking": { ranking: [
      { author: "ana", role: "worker", findings: 7, poc: 3, projects: 2, types: { web: 4, poc: 3 }, topType: "web" },
      { author: "bob", role: "editor", findings: 2, poc: 0, projects: 1, types: { ad: 2 }, topType: "ad" }],
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
  const tabs = document.querySelectorAll(".admtabs .admtab").length;
  const activeIsRanking = /ranking/i.test(document.querySelector(".admtab.on")?.textContent || "");
  location.hash = "#/admin/users"; await new Promise(r => setTimeout(r, 700));
  const usersActive = /users/i.test(document.querySelector(".admtab.on")?.textContent || "");
  window.fetch = real;
  return rankRows === 2 && tabs === 5 && activeIsRanking && usersActive`)]);
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
