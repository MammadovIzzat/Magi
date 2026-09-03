// The running app version — bumped alongside package.json/PKGBUILD each release. Surfaced in
// /api/me so the desktop app can show both its own and the server's version (handy for confirming
// an update actually took). Kept as a tiny module so it inlines into the bundle correctly (reading
// package.json at runtime is wrong: the packaged app ships a different, static package.json).
export const VERSION = '0.7.7';
