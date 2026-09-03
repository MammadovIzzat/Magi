// Durable TLS identity for Magi server mode.
//
// Two hard rules drive this file:
//   1. A company's engagement data outlives any single run of the process, so the
//      identity must survive restarts. Restarting NEVER re-runs setup — if the files
//      already exist we load them untouched. (Losing this = losing the server.)
//   2. Every enrolled client PINS this exact certificate's fingerprint. Regenerating it
//      would lock out every client at once, so it is generated only the first time.
//
// The cert is self-signed (an internal company server, not a public site): clients trust
// it by pinning the fingerprint rather than via a public CA.
import { execFileSync } from 'node:child_process';
import { readFileSync, writeFileSync, existsSync, mkdirSync, chmodSync } from 'node:fs';
import { join } from 'node:path';
import { hostname } from 'node:os';
import { X509Certificate, randomBytes } from 'node:crypto';
import { DATA_DIR, env } from './db.js';

const DIR = join(DATA_DIR, 'server');
const KEY = join(DIR, 'server.key');
const CRT = join(DIR, 'server.crt');
const META = join(DIR, 'identity.json');
const JWT_SECRET = join(DIR, 'jwt.secret');

// The persistent HMAC key that signs access tokens. Kept next to the cert (0600), created once,
// reused across restarts so tokens survive a reboot. Deleting it invalidates every token at once.
export function jwtSecret() {
  mkdirSync(DIR, { recursive: true });
  if (existsSync(JWT_SECRET)) { try { return readFileSync(JWT_SECRET, 'utf8').trim(); } catch { /* recreate */ } }
  const secret = randomBytes(32).toString('hex');
  writeFileSync(JWT_SECRET, secret);
  try { chmodSync(JWT_SECRET, 0o600); } catch { /* best effort on non-POSIX */ }
  return secret;
}

/** SHA-256 fingerprint the clients pin, e.g. "48:9A:04:…:A9". */
export function certFingerprint(certPem) {
  return new X509Certificate(certPem).fingerprint256;
}

// Clients pin the fingerprint, so SAN accuracy is not security-critical — but some TLS
// stacks want a SAN present, and matching hostnames avoids noisy warnings. Admins can add
// their own reachable names/IPs with MAGI_SERVER_SAN=IP:10.0.0.9,DNS:magi.corp.local.
function subjectAltNames() {
  const base = ['DNS:magi-server', 'DNS:localhost', 'IP:127.0.0.1'];
  const host = hostname();
  if (host && /^[a-z0-9.-]+$/i.test(host)) base.push(`DNS:${host}`);
  const extra = (env('SERVER_SAN') || '').split(',').map(s => s.trim()).filter(Boolean);
  return [...new Set([...base, ...extra])].join(',');
}

function generate() {
  mkdirSync(DIR, { recursive: true });
  try {
    execFileSync('openssl', [
      'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1',
      '-nodes', '-keyout', KEY, '-out', CRT, '-days', '3650',
      '-subj', '/CN=magi-server', '-addext', `subjectAltName=${subjectAltNames()}`,
    ], { stdio: 'ignore' });
  } catch (e) {
    if (e.code === 'ENOENT') throw new Error('openssl is needed to create the server certificate but was not found on PATH');
    throw new Error(`openssl could not create the server certificate: ${e.message}`);
  }
  chmodSync(KEY, 0o600); // the private key must not be world-readable
  // Record the fingerprint so an admin can read it back later without openssl.
  writeFileSync(META, JSON.stringify(
    { created_at: new Date().toISOString(), fingerprint: certFingerprint(readFileSync(CRT)) }, null, 2));
}

/**
 * Load the server's TLS identity, generating it the first time only.
 * @returns {{ key: Buffer, cert: Buffer, fingerprint: string, dir: string, keyPath: string, certPath: string }}
 */
export function loadServerIdentity() {
  if (!existsSync(KEY) || !existsSync(CRT)) generate();
  const key = readFileSync(KEY);
  const cert = readFileSync(CRT);
  return { key, cert, fingerprint: certFingerprint(cert), dir: DIR, keyPath: KEY, certPath: CRT };
}

/** Read the stored identity metadata without creating one. Null if the server was never set up. */
export function readIdentityMeta() {
  if (existsSync(META)) { try { return JSON.parse(readFileSync(META, 'utf8')); } catch { /* fall through */ } }
  if (existsSync(CRT)) return { fingerprint: certFingerprint(readFileSync(CRT)), created_at: null };
  return null;
}

export const IDENTITY_DIR = DIR;
