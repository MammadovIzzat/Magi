// Preload for the unlock window. Kept minimal: it exposes only a way to send the typed
// passphrase to the main process and to receive an error back — nothing else is reachable.
const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('magiUnlock', {
  submit: (passphrase) => ipcRenderer.send('magi-unlock:submit', String(passphrase ?? '')),
  quit: () => ipcRenderer.send('magi-unlock:quit'),
  onError: (cb) => ipcRenderer.on('magi-unlock:error', (_e, msg) => cb(msg)),
});
