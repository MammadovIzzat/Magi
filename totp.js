// TOTP (RFC 6238) multi-factor auth — no dependencies, just node:crypto.
//
// A shared secret is shown to the user once (as a base32 key + otpauth URI) so they add it to
// an authenticator app (Google Authenticator, Authy, …). Thereafter the app and the server both
// derive the same rolling 6-digit code from the secret and the current 30-second window, so a
// stolen password alone no longer gets in. Recovery codes are one-time break-glass values for a
// lost phone; only their hashes are stored.
import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';

const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

export function base32Encode(buf) {
  let bits = 0, value = 0, out = '';
  for (const b of buf) {
    value = (value << 8) | b; bits += 8;
    while (bits >= 5) { out += B32[(value >>> (bits - 5)) & 31]; bits -= 5; }
  }
  if (bits > 0) out += B32[(value << (5 - bits)) & 31];
  return out;
}
function base32Decode(str) {
  let bits = 0, value = 0; const out = [];
  for (const c of String(str).toUpperCase().replace(/[^A-Z2-7]/g, '')) {
    value = (value << 5) | B32.indexOf(c); bits += 5;
    if (bits >= 8) { out.push((value >>> (bits - 8)) & 0xff); bits -= 8; }
  }
  return Buffer.from(out);
}

/** A fresh base32 secret (default 20 bytes = 160 bits, the RFC-recommended size). */
export function generateSecret(bytes = 20) { return base32Encode(randomBytes(bytes)); }

function hotp(secret, counter) {
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64BE(BigInt(counter));
  const h = createHmac('sha1', base32Decode(secret)).update(buf).digest();
  const off = h[h.length - 1] & 0x0f;
  const bin = ((h[off] & 0x7f) << 24) | ((h[off + 1] & 0xff) << 16) | ((h[off + 2] & 0xff) << 8) | (h[off + 3] & 0xff);
  return String(bin % 1_000_000).padStart(6, '0');
}

/** The current 6-digit code for a secret (used by clients/tests; the server only verifies). */
export function currentCode(secret, { step = 30, now = Date.now() } = {}) {
  return hotp(secret, Math.floor(now / 1000 / step));
}

/** True if `token` matches the secret within ±window steps (clock-skew tolerance). */
export function verifyTOTP(secret, token, { window = 1, step = 30, now = Date.now() } = {}) {
  const tok = String(token || '').trim();
  if (!secret || !/^\d{6}$/.test(tok)) return false;
  const counter = Math.floor(now / 1000 / step);
  for (let i = -window; i <= window; i++) {
    const cand = hotp(secret, counter + i);
    if (timingSafeEqual(Buffer.from(cand), Buffer.from(tok))) return true;
  }
  return false;
}

/** The otpauth:// URI an authenticator app imports (also renderable as a QR by the app). */
export function otpauthURI({ issuer = 'Magi', account, secret }) {
  const label = encodeURIComponent(`${issuer}:${account}`);
  const p = new URLSearchParams({ secret, issuer, algorithm: 'SHA1', digits: '6', period: '30' });
  return `otpauth://totp/${label}?${p.toString()}`;
}

/** N one-time recovery codes, formatted xxxx-xxxx. */
export function recoveryCodes(n = 10) {
  const codes = [];
  for (let i = 0; i < n; i++) {
    const raw = base32Encode(randomBytes(5)).toLowerCase().slice(0, 8);
    codes.push(raw.slice(0, 4) + '-' + raw.slice(4, 8));
  }
  return codes;
}
export const RECOVERY_RE = /^[a-z2-7]{4}-[a-z2-7]{4}$/;
