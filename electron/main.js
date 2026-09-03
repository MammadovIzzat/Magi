// Magi as a desktop application.
//
// The UI is the same HTML/CSS/JS, but it is served over a private magi:// scheme
// handled inside this process — no port is opened, nothing is reachable from the
// network, and no browser is involved.
process.env.MAGI_EMBED = '1';               // stop server.js from listening

import { app, BrowserWindow, Menu, dialog, protocol, shell, safeStorage, ipcMain } from 'electron';
import { readFile } from 'node:fs/promises';
import { existsSync, readFileSync } from 'node:fs';
import { join, dirname, normalize } from 'node:path';
import { homedir } from 'node:os';
import { createRequire } from 'node:module';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { createDispatcher } from './dispatch.js';

const require = createRequire(import.meta.url);

// safeStorage (token-at-rest encryption) backend selection. Chromium only auto-detects
// GNOME and KDE; on tiling WMs (i3, sway, Hyprland) it silently uses a no-op "basic" store
// and reports encryption unavailable — even when gnome-keyring's Secret Service is running.
// Point it at the standard Secret Service (libsecret), which gnome-keyring and KWallet both
// provide, so the token gets real OS-keychain encryption. KDE keeps its native kwallet.
// Override anywhere with MAGI_PASSWORD_STORE=basic|gnome-libsecret|kwallet6|…
{
  const de = (process.env.XDG_CURRENT_DESKTOP || '').toLowerCase();
  const store = process.env.MAGI_PASSWORD_STORE || (/kde|plasma/.test(de) ? '' : 'gnome-libsecret');
  if (store) app.commandLine.appendSwitch('password-store', store);
}

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, '..');
const PUBLIC = join(ROOT, 'public');

// A packaged build must not keep the database inside its own install tree — that tree
// is replaced on upgrade and may be read-only. Running from a checkout keeps db.js's
// own choice (./data) so the app and `npm start` share one database while developing.
if (app.isPackaged && !process.env.MAGI_DATA_DIR && !process.env.MAGI_DB) {
  process.env.MAGI_DATA_DIR = join(
    process.env.XDG_DATA_HOME || join(homedir(), '.local', 'share'), 'magi');
}

const MIME = {
  '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8', '.woff2': 'font/woff2', '.svg': 'image/svg+xml',
  '.png': 'image/png', '.ico': 'image/x-icon', '.json': 'application/json',
};

// Must be declared before the app is ready. `standard` gives it a normal origin so
// relative fetches work; `secure` makes it a secure context (clipboard, fonts).
protocol.registerSchemesAsPrivileged([{
  scheme: 'magi',
  privileges: { standard: true, secure: true, supportFetchAPI: true, corsEnabled: true, stream: true },
}]);

// Single instance: focus the existing window instead of opening a second one on the
// same database. app.quit() does not stop this module, so bail out explicitly —
// otherwise a second launch still registers a ready handler and races the shutdown,
// which surfaces as ERR_FAILED loading the page.
const isPrimary = app.requestSingleInstanceLock();
if (!isPrimary) app.exit(0);

let win;

// ── unlock an encrypted workspace ───────────────────────────────────────────────────────
// If the local database is encrypted, ask for the passphrase and set MAGI_DB_KEY BEFORE the
// server bundle (and db.js) load — so no lazy-open plumbing is needed. The passphrase lives
// only in this process's env for the session; nothing is written to disk.
function resolveDbPath() {
  if (process.env.MAGI_DB) return process.env.MAGI_DB;
  const dir = process.env.MAGI_DATA_DIR || join(ROOT, 'data');
  const legacy = join(dir, 'checklister.db');
  return existsSync(legacy) ? legacy : join(dir, 'magi.db');
}
const isPlaintextSqlite = (p) => {
  try { return readFileSync(p).subarray(0, 16).toString('latin1').startsWith('SQLite format 3'); }
  catch { return false; }
};
function keyOpens(dbPath, passphrase) {
  let d;
  try {
    const Database = require('better-sqlite3-multiple-ciphers');
    d = new Database(dbPath);
    d.pragma("cipher='sqlcipher'");
    d.pragma("key='" + String(passphrase).replace(/'/g, "''") + "'");
    d.prepare('SELECT count(*) FROM sqlite_master').get();
    return true;
  } catch { return false; }
  finally { try { d?.close(); } catch { /* already gone */ } }
}
// Returns true to proceed, false if the user chose to quit (the app is exiting).
async function ensureUnlocked() {
  if (process.env.MAGI_DB_KEY || process.env.MAGI_KEY_FILE) return true;   // keyed by env already
  const dbPath = resolveDbPath();
  if (!existsSync(dbPath) || isPlaintextSqlite(dbPath)) return true;       // fresh or plaintext — no prompt
  const passphrase = await new Promise((resolve) => {
    const w = new BrowserWindow({
      width: 380, height: 340, resizable: false, backgroundColor: '#08090E',
      title: 'Magi — Unlock', autoHideMenuBar: true,
      // The unlock page is a shipped static file (unlock.html) with no remote/user content, so it
      // runs with nodeIntegration and talks to the main process directly. This is deliberately
      // simpler than a preload+contextBridge, which silently failed to attach on the old data: URL.
      webPreferences: { nodeIntegration: true, contextIsolation: false, sandbox: false },
    });
    // Surface anything the page logs or fails on, so a broken unlock is never silent again.
    w.webContents.on('console-message', (_e, _lvl, message) => console.error('[unlock]', message));
    w.webContents.on('did-fail-load', (_e, code, desc) => console.error('[unlock] load failed', code, desc));
    let settled = false;
    const cleanup = () => { ipcMain.removeAllListeners('magi-unlock:submit'); ipcMain.removeAllListeners('magi-unlock:quit'); };
    const finish = (v) => { if (settled) return; settled = true; cleanup(); if (!w.isDestroyed()) w.destroy(); resolve(v); };
    ipcMain.on('magi-unlock:submit', (_e, p) => {
      if (keyOpens(dbPath, p)) finish(String(p));
      else if (!w.isDestroyed()) w.webContents.send('magi-unlock:error', 'Wrong passphrase — try again.');
    });
    ipcMain.on('magi-unlock:quit', () => finish(null));
    w.on('closed', () => { if (!settled) { settled = true; cleanup(); resolve(null); } });
    w.loadFile(join(HERE, 'unlock.html'));
  });
  if (passphrase == null) { app.exit(0); return false; }
  process.env.MAGI_DB_KEY = passphrase;
  return true;
}

async function createWindow() {
  if (!(await ensureUnlocked())) return;   // encrypted DB → prompt first; user may quit
  // Installed builds ship one bundled CommonJS file, in a place that depends on how
  // they were packaged; a source checkout just uses server.js.
  const entry = [
    join(ROOT, 'magi-server.cjs'),          // Arch package (packaging/PKGBUILD)
    join(ROOT, 'dist', 'magi-server.cjs'),  // electron-builder (.deb, .AppImage, macOS)
    join(ROOT, 'server.js'),                // source checkout
  ].find(existsSync);
  if (!entry) throw new Error('Magi: could not find the server bundle next to ' + ROOT);

  // Encrypt the team-server token at rest with the OS keychain (Keychain / DPAPI / libsecret).
  // Set before the server bundle loads so its background sync reads it. A global so it reaches
  // client-link whether the server is bundled or a loose file.
  try {
    if (safeStorage.isEncryptionAvailable()) {
      globalThis.__MAGI_ENCRYPTOR = {
        available: true,
        encrypt: (s) => safeStorage.encryptString(s).toString('base64'),
        decrypt: (b) => safeStorage.decryptString(Buffer.from(String(b), 'base64')),
      };
    }
  } catch { /* no keychain available — client-link falls back to a 0600 file and the UI warns */ }

  const mod = await import(pathToFileURL(entry).href);
  const dispatch = createDispatcher(mod.default?.default ?? mod.default);

  protocol.handle('magi', async (request) => {
    const url = new URL(request.url);
    if (url.pathname.startsWith('/api/')) return dispatch(request);

    // static assets, path-traversal safe
    const rel = normalize(url.pathname === '/' ? '/index.html' : url.pathname).replace(/^(\.\.[/\\])+/, '');
    const file = join(PUBLIC, rel);
    if (!file.startsWith(PUBLIC)) return new Response('forbidden', { status: 403 });
    try {
      const ext = rel.slice(rel.lastIndexOf('.'));
      return new Response(await readFile(file), {
        headers: { 'content-type': MIME[ext] || 'application/octet-stream' },
      });
    } catch {
      return new Response('not found', { status: 404 });
    }
  });

  Menu.setApplicationMenu(null);
  win = new BrowserWindow({
    width: 1440, height: 920, minWidth: 960, minHeight: 600,
    backgroundColor: '#08090E',
    title: 'Magi',
    icon: join(ROOT, 'packaging', 'magi.png'),
    autoHideMenuBar: true,
    show: false,
    webPreferences: { contextIsolation: true, nodeIntegration: false, sandbox: true },
  });

  // Never paint a half-styled window: wait for the first frame.
  win.once('ready-to-show', () => win.show());

  // Anything that is not Magi opens in the real browser, not in this window.
  win.webContents.setWindowOpenHandler(({ url }) => {
    if (/^https?:/.test(url)) shell.openExternal(url);
    return { action: 'deny' };
  });
  win.webContents.on('will-navigate', (e, url) => {
    if (!url.startsWith('magi://')) { e.preventDefault(); if (/^https?:/.test(url)) shell.openExternal(url); }
  });

  await win.loadURL('magi://app/index.html');
}

app.on('second-instance', () => { if (win) { if (win.isMinimized()) win.restore(); win.focus(); } });

// Without this a startup failure is only an unhandled-rejection warning on a console
// nobody is looking at, and the app just never shows a window.
if (isPrimary) app.whenReady().then(createWindow).catch((err) => {
  console.error(err);
  dialog.showErrorBox('Magi could not start', String(err?.stack || err));
  app.exit(1);
});
app.on('window-all-closed', () => app.quit());
app.on('activate', () => { if (BrowserWindow.getAllWindows().length === 0) createWindow(); });
