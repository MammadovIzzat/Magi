// Generate ui-template/ — standalone HTML snapshots of every Magi screen and key dialog, styled
// with the real style.css, for use as design references (e.g. Claude Design).
//
//   node scripts/gen-ui-templates.mjs
//
// It boots two throwaway instances (a standalone HTTP one for the local screens + settings, and a
// team-server HTTPS one for the admin panel), seeds realistic sample data, drives a headless
// browser to each view/modal, captures the rendered HTML, and writes it out with the CSS + fonts.
import { spawn, spawnSync } from 'node:child_process';
import { rmSync, mkdirSync, mkdtempSync, writeFileSync, readFileSync, existsSync, cpSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const ROOT = process.cwd();
const OUT = join(ROOT, 'ui-template');
const HTTP_PORT = 46011, TLS_PORT = 46012, CDP_PORT = 9412;
const PROFILE = mkdtempSync(join(tmpdir(), 'magi-uicap-'));
const httpDir = mkdtempSync(join(tmpdir(), 'magi-uihttp-'));
const tlsDir = mkdtempSync(join(tmpdir(), 'magi-uitls-'));
const sleep = (ms) => new Promise(r => setTimeout(r, ms));
const BROWSERS = ['google-chrome-stable', 'google-chrome', 'chromium', 'chromium-browser'];
const has = (c) => spawnSync('sh', ['-c', `command -v ${c}`], { stdio: 'ignore' }).status === 0;
const browser = BROWSERS.find(has);
if (!browser) { console.error('no Chromium-based browser found'); process.exit(1); }

const procs = [];
function boot(env, dir) {
  const p = spawn(process.execPath, ['server.js'], { env: { ...process.env, ...env }, stdio: ['ignore', 'ignore', 'pipe'] });
  p.stderr.on('data', () => {}); procs.push(p); return p;
}
let chrome;
function cleanup() {
  try { chrome?.kill(); } catch {}
  for (const p of procs) { try { p.kill(); } catch {} }
  for (const d of [PROFILE, httpDir, tlsDir]) { try { rmSync(d, { recursive: true, force: true, maxRetries: 3 }); } catch {} }
}
process.on('exit', cleanup);
process.on('uncaughtException', e => { console.error(e); cleanup(); process.exit(1); });

// ---- boot both instances ----
boot({ MAGI_MFA: 'off', MAGI_PORT: String(HTTP_PORT), MAGI_DB: join(httpDir, 'magi.db'), MAGI_DATA_DIR: httpDir, MAGI_PASS: 'demo-pass-123', MAGI_USER: 'operator' }, httpDir);
boot({ MAGI_SERVER: '1', MAGI_MFA: 'off', MAGI_HOST: '127.0.0.1', MAGI_PORT: String(TLS_PORT), MAGI_DB: join(tlsDir, 'magi.db'), MAGI_DATA_DIR: tlsDir, MAGI_PASS: 'demo-pass-123', MAGI_USER: 'lead' }, tlsDir);
for (let i = 0; i < 80; i++) { try { await fetch(`http://127.0.0.1:${HTTP_PORT}/api/me`); break; } catch { await sleep(200); } }
await sleep(800);

// ---- headless chrome + CDP ----
chrome = spawn(browser, ['--headless=new', `--remote-debugging-port=${CDP_PORT}`, '--no-first-run',
  '--ignore-certificate-errors', '--disable-gpu', `--user-data-dir=${PROFILE}`, 'about:blank'], { stdio: 'ignore' });
let targets;
for (let i = 0; i < 80; i++) { try { targets = await (await fetch(`http://localhost:${CDP_PORT}/json`)).json(); if (targets.length) break; } catch {} await sleep(250); }
if (!targets?.length) { console.error('headless browser never came up'); process.exit(1); }
const ws = new WebSocket(targets.find(t => t.type === 'page').webSocketDebuggerUrl);
await new Promise(r => ws.addEventListener('open', r, { once: true }));
let mid = 0; const pend = new Map();
ws.addEventListener('message', e => { const m = JSON.parse(e.data); if (m.id && pend.has(m.id)) { pend.get(m.id)(m.result); pend.delete(m.id); } });
const cdp = (method, params = {}) => new Promise(res => { const n = ++mid; pend.set(n, res); ws.send(JSON.stringify({ id: n, method, params })); });
const ev = async (expr) => { const r = await cdp('Runtime.evaluate', { expression: `(async()=>{${expr}})()`, awaitPromise: true, returnByValue: true }); if (r.exceptionDetails) throw new Error(r.exceptionDetails.exception?.description || r.exceptionDetails.text); return r.result?.value; };
await cdp('Runtime.enable'); await cdp('Page.enable');

const goto = async (url) => { await cdp('Page.navigate', { url }); await sleep(1500); };

// ---- seeding helpers (run in the page, authed via the app's own token) ----
const SEED_JS = `
  window.__login = async (u, p) => {
    const r = await fetch('/api/auth/login', { method:'POST', headers:{'content-type':'application/json'}, body: JSON.stringify({ username:u, password:p }) });
    const j = await r.json(); localStorage.setItem('magi.jwt', j.token); return j.token;
  };
  window.__P = async (u, b) => (await fetch(u, { method:'POST', headers:{'content-type':'application/json', authorization:'Bearer '+localStorage.getItem('magi.jwt')}, body: JSON.stringify(b||{}) })).json();
  window.__G = async (u) => (await fetch(u, { headers:{ authorization:'Bearer '+localStorage.getItem('magi.jwt') } })).json();
  window.__PATCH = async (u, b) => (await fetch(u, { method:'PATCH', headers:{'content-type':'application/json', authorization:'Bearer '+localStorage.getItem('magi.jwt')}, body: JSON.stringify(b) })).json();
`;

const SEED_ENGAGEMENT = `
  const p = await __P('/api/projects', { name:'Acme Corp — External Assessment', client:'Acme Corporation', scope:'*.acme.example, 203.0.113.0/24', notes:'Grey-box web + external infrastructure. Test window 09:00–18:00 UTC.', start_date:'2026-09-01', end_date:'2026-09-12' });
  const ext = await __P('/api/projects/'+p.id+'/assets', { grp:'external', label:'Perimeter' });
  const web = await __P('/api/assets/'+ext.id+'/targets', { type:'web', label:'https://app.acme.example' });
  await __P('/api/assets/'+ext.id+'/targets', { type:'api', label:'https://api.acme.example' });
  const intn = await __P('/api/projects/'+p.id+'/assets', { grp:'internal', label:'Corporate LAN' });
  await __P('/api/assets/'+intn.id+'/targets', { type:'ip', label:'10.0.0.0/24' });
  await __P('/api/assets/'+intn.id+'/targets', { type:'ad', label:'ACME.LOCAL' });
  const add = await __P('/api/projects/'+p.id+'/assets', { grp:'additional', label:'Extras' });
  await __P('/api/assets/'+add.id+'/targets', { type:'container', label:'registry.acme.example/app:latest' });
  const poc = await __P('/api/assets/'+add.id+'/targets', { type:'poc', label:'SSRF → cloud metadata → RCE' });
  const rt = await __P('/api/projects/'+p.id+'/assets', { grp:'retest', label:'Q2 remediation' });
  const rtt = await __P('/api/assets/'+rt.id+'/targets', { type:'retest', label:'Retest — Q2 findings' });
  await __P('/api/targets/'+web.id+'/findings', { title:'Reflected XSS in /search', kind:'vuln', severity:'high', body:'GET /search?q=<script>alert(document.domain)</script> reflects unencoded.' });
  await __P('/api/targets/'+web.id+'/findings', { title:'Weak admin credentials', kind:'credential', body:'admin : Password1!  (portal /admin)' });
  await __P('/api/targets/'+web.id+'/findings', { title:'Verbose 500 stack trace', kind:'note', body:'Leaks framework version and absolute paths.' });
  await __P('/api/targets/'+poc.id+'/findings', { title:'Full chain: SSRF → IMDS → RCE', kind:'vuln', severity:'critical', body:'1) SSRF in webhook URL  2) fetch 169.254.169.254 role creds  3) deploy via API → RCE.' });
  await __P('/api/targets/'+rtt.id+'/findings', { title:'ACME-1 SQL injection (login)', kind:'vuln', severity:'high', fix_status:'fixed' });
  await __P('/api/targets/'+rtt.id+'/findings', { title:'ACME-2 IDOR on /invoices', kind:'vuln', severity:'medium', fix_status:'half_fixed' });
  await __P('/api/targets/'+rtt.id+'/findings', { title:'ACME-3 Missing rate limit', kind:'vuln', severity:'low', fix_status:'not_fixed' });
  const wd = await __G('/api/targets/'+web.id);
  const checks = wd.items.filter(i => i.kind==='check').slice(0,7);
  const st = ['done','done','todo','na','done','todo','done'];
  for (let i=0;i<checks.length;i++) await __PATCH('/api/items/'+checks[i].id, { status: st[i] });
  window.__ids = { pid:p.id, webId:web.id, pocId:poc.id, rttId:rtt.id, assetId:ext.id };
  return window.__ids;
`;

const SEED_ADMIN = `
  const uuid = () => '00000000-0000-4000-8000-'+String(Math.abs(Date.now()%1e12)).padStart(12,'0');
  // a pending join request (left un-approved so it shows in the panel)
  const c1 = (await __P('/api/admin/enroll-codes', { note:'Ana laptop' })).code;
  await __P('/api/enroll', { code:c1, username:'ana', display_name:'Ana Rivera', device_id:'11111111-1111-4111-8111-111111111111', password:'ana-secret-8' });
  // an approved editor + worker (become members + devices)
  const c2 = (await __P('/api/admin/enroll-codes', { note:'Ben desktop' })).code;
  const r2 = await __P('/api/enroll', { code:c2, username:'ben', display_name:'Ben Carter', device_id:'22222222-2222-4222-8222-222222222222', password:'ben-secret-8' });
  await __P('/api/admin/requests/'+r2.request_id+'/approve', { role:'editor' });
  const c3 = (await __P('/api/admin/enroll-codes', { note:'Cara phone' })).code;
  const r3 = await __P('/api/enroll', { code:c3, username:'cara', display_name:'Cara Singh', device_id:'33333333-3333-4333-8333-333333333333', password:'cara-secret-8' });
  await __P('/api/admin/requests/'+r3.request_id+'/approve', { role:'worker' });
  // a spare active code
  await __P('/api/admin/enroll-codes', { note:'Spare' });
  return true;
`;

const captured = {};
async function capture(name) {
  const html = await ev('return document.documentElement.outerHTML;');
  captured[name] = html;
  console.error('  captured', name);
}

// ---------- PASS 1: standalone (local screens, settings, most modals) ----------
await goto(`http://127.0.0.1:${HTTP_PORT}/`);
await ev(SEED_JS);
await capture('login');                                   // the login screen (not yet authed)
await ev(`await __login('operator','demo-pass-123'); await afterAuth();`);
await sleep(500);
const ids = await ev(SEED_ENGAGEMENT);
await ev(`location.hash=''; await route();`); await sleep(900); await capture('engagements');
await ev(`location.hash='#/project/${ids.pid}'; await route();`); await sleep(900); await capture('engagement');
await ev(`location.hash='#/asset/${ids.assetId}'; await route();`); await sleep(900); await capture('asset-folder');
await ev(`location.hash='#/target/${ids.webId}'; await route();`); await sleep(1100);
await ev(`document.querySelectorAll('.ghdr')[0]?.click(); document.querySelectorAll('.ghdr')[1]?.click();`); await sleep(500);
await capture('target-checklist');
await ev(`location.hash='#/target/${ids.pocId}'; await route();`); await sleep(900); await capture('target-poc');
await ev(`location.hash='#/target/${ids.rttId}'; await route();`); await sleep(900); await capture('target-retest');
await ev(`location.hash='#/editor'; await route();`); await sleep(1000); await capture('templates-editor');
await ev(`location.hash='#/settings'; await route();`); await sleep(900); await capture('settings-local');
// modals
await ev(`location.hash=''; await route(); await new Promise(r=>setTimeout(r,300)); newProject();`); await sleep(500); await capture('modal-new-engagement');
await ev(`location.hash='#/asset/${ids.assetId}'; await route(); await new Promise(r=>setTimeout(r,600)); [...document.querySelectorAll('button')].find(b=>/add target/i.test(b.textContent))?.click();`); await sleep(500); await capture('modal-add-target');
await ev(`location.hash='#/target/${ids.webId}'; await route(); await new Promise(r=>setTimeout(r,700)); addFinding(${ids.webId}, false);`); await sleep(500); await capture('modal-finding');
await ev(`location.hash='#/settings'; await route(); await new Promise(r=>setTimeout(r,500)); connectDialog();`); await sleep(500); await capture('modal-connect-server');

// ---------- PASS 2: team server (admin panel) ----------
await goto(`https://127.0.0.1:${TLS_PORT}/`);
await ev(SEED_JS);
await ev(`await __login('lead','demo-pass-123'); await afterAuth();`); await sleep(600);
await ev(SEED_ADMIN); await sleep(400);
await ev(`location.hash='#/admin'; await route();`); await sleep(1200); await capture('admin-panel');

ws.close();

// ---------- write files ----------
mkdirSync(OUT, { recursive: true });
// CSS: copy + rewrite absolute /fonts/ to relative
let css = readFileSync(join(ROOT, 'public/style.css'), 'utf8').replace(/url\((['"]?)\/fonts\//g, 'url($1fonts/');
writeFileSync(join(OUT, 'style.css'), css);
if (existsSync(join(ROOT, 'public/fonts'))) cpSync(join(ROOT, 'public/fonts'), join(OUT, 'fonts'), { recursive: true });

const PLACEHOLDER = "data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='320' height='180'%3E%3Crect width='320' height='180' fill='%231b1e27'/%3E%3Crect x='.5' y='.5' width='319' height='179' fill='none' stroke='%23394150'/%3E%3Ctext x='160' y='96' fill='%236b7280' font-family='sans-serif' font-size='13' text-anchor='middle'%3Escreenshot%3C/text%3E%3C/svg%3E";
function processHtml(html, title) {
  html = html.replace(/<link rel="stylesheet" href="\/style\.css"\s*\/?>/i, '<link rel="stylesheet" href="style.css" />');
  html = html.replace(/<script src="\/(qr|app)\.js"><\/script>\s*/gi, '');
  html = html.replace(/\ssrc="(blob:[^"]*|\/api\/attachments\/[^"]*)"/gi, ` src="${PLACEHOLDER}"`);
  html = html.replace(/<title>[^<]*<\/title>/i, `<title>Magi — ${title}</title>`);
  return '<!doctype html>\n' + html;
}

const META = {
  'login': 'Sign-in (lock screen)',
  'engagements': 'Engagements — the home list',
  'engagement': 'One engagement — stats + its targets',
  'asset-folder': 'Asset folder — targets in one engagement type',
  'target-checklist': 'Target — attack checklist + evidence log',
  'target-poc': 'PoC target — checklist-free findings',
  'target-retest': 'Retest target — remediation items',
  'templates-editor': 'Template library / editor',
  'settings-local': 'Settings — local workspace + encryption',
  'admin-panel': 'Admin panel — team server management',
  'modal-new-engagement': 'Dialog — new engagement',
  'modal-add-target': 'Dialog — add a target',
  'modal-finding': 'Dialog — record a finding',
  'modal-connect-server': 'Dialog — connect to a team server',
};
const order = Object.keys(META).filter(k => captured[k]);
for (const name of order) writeFileSync(join(OUT, name + '.html'), processHtml(captured[name], META[name]));

// index gallery
const cards = order.map(n => `    <a class="card" href="${n}.html"><span class="tag">${n}</span><span class="desc">${META[n]}</span></a>`).join('\n');
const index = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Magi — UI templates</title><link rel="stylesheet" href="style.css" />
<style>
  body{padding:32px;max-width:900px;margin:0 auto}
  .g{display:grid;grid-template-columns:repeat(auto-fill,minmax(240px,1fr));gap:14px;margin-top:20px}
  .card{display:flex;flex-direction:column;gap:6px;padding:16px;border:1px solid var(--line,#2a2f3a);border-radius:12px;text-decoration:none;background:var(--panel,#12151d)}
  .card:hover{border-color:var(--gold,#E8B65A)}
  .tag{font-family:monospace;color:var(--gold,#E8B65A);font-size:13px}
  .desc{color:var(--muted,#9aa4b2);font-size:14px}
</style></head>
<body>
  <h1>Magi — UI templates</h1>
  <p class="muted">Static, real-CSS snapshots of every screen and key dialog, for design work. Each file links <code>style.css</code> (fonts in <code>fonts/</code>).</p>
  <div class="g">
${cards}
  </div>
</body></html>`;
writeFileSync(join(OUT, 'index.html'), index);

console.error(`\n  wrote ${order.length} templates + index + style.css to ui-template/`);
cleanup();
process.exit(0);
