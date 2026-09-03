// Minimal, dependency-free JWT (HS256) — Magi's server-issued access tokens.
//
// The server signs a short-lived token after a successful username + password (+ OTP) login and
// hands it to the client, which presents it on every sync. Claims are server-signed, so the
// client can READ its role/expiry but cannot forge them, and the server re-validates each time:
//   - signature (HMAC-SHA256 over header.payload) with the server's persistent secret,
//   - exp (short-lived; the client re-authenticates when it lapses),
//   - epoch: must equal the user's current cred_epoch — bumping that epoch (password/role change,
//     forced logout) instantly invalidates every outstanding token for that user, no blacklist.
// A `jti` is included for audit/logging, not for revocation.
import { createHmac, timingSafeEqual, randomBytes } from 'node:crypto';

const b64urlJson = (obj) => Buffer.from(JSON.stringify(obj)).toString('base64url');
const now = () => Math.floor(Date.now() / 1000);

export const DEFAULT_TTL = 4 * 60 * 60; // 4 hours

/** Sign a payload into a compact JWT string. Adds iat/exp/jti. */
export function sign(payload, secret, { ttlSeconds = DEFAULT_TTL } = {}) {
  if (!secret) throw new Error('jwt: a signing secret is required');
  const t = now();
  const body = { iat: t, exp: t + ttlSeconds, jti: randomBytes(12).toString('hex'), ...payload };
  const input = b64urlJson({ alg: 'HS256', typ: 'JWT' }) + '.' + b64urlJson(body);
  const sig = createHmac('sha256', secret).update(input).digest().toString('base64url');
  return input + '.' + sig;
}

/** Verify signature + expiry. Returns the payload object, or null if invalid/expired/tampered. */
export function verify(token, secret) {
  if (typeof token !== 'string' || !secret) return null;
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  const [h, p, s] = parts;
  const expected = createHmac('sha256', secret).update(h + '.' + p).digest();
  let given;
  try { given = Buffer.from(s, 'base64url'); } catch { return null; }
  if (given.length !== expected.length || !timingSafeEqual(given, expected)) return null;
  let payload;
  try { payload = JSON.parse(Buffer.from(p, 'base64url').toString('utf8')); } catch { return null; }
  if (typeof payload.exp === 'number' && now() >= payload.exp) return null;
  return payload;
}

/** Read the payload WITHOUT verifying — for non-security display only (never trust this). */
export function decodeUnsafe(token) {
  try { return JSON.parse(Buffer.from(String(token).split('.')[1], 'base64url').toString('utf8')); }
  catch { return null; }
}
