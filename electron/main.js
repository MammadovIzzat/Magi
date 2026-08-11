// Magi as a desktop application.
//
// The UI is the same HTML/CSS/JS, but it is served over a private magi:// scheme
// handled inside this process — no port is opened, nothing is reachable from the
// network, and no browser is involved.
process.env.MAGI_EMBED = '1';               // stop server.js from listening

import { app, BrowserWindow, Menu, protocol, shell, net } from 'electron';
import { readFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { join, dirname, normalize } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { createDispatcher } from './dispatch.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, '..');
const PUBLIC = join(ROOT, 'public');

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

// Single instance: focus the existing window instead of opening a second one on
// the same database.
if (!app.requestSingleInstanceLock()) app.quit();

let win;

async function createWindow() {
  // Installed builds ship one bundled CommonJS file; a source checkout uses server.js.
  const bundled = join(ROOT, 'magi-server.cjs');
  const entry = existsSync(bundled) ? bundled : join(ROOT, 'server.js');
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
app.whenReady().then(createWindow);
app.on('window-all-closed', () => app.quit());
app.on('activate', () => { if (BrowserWindow.getAllWindows().length === 0) createWindow(); });
