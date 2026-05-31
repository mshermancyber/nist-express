// TOTP (RFC 6238) implementation. No external dependency — base32
// encoding + HMAC-SHA1 + truncation. 30-second time step, 6-digit
// output. ±1 step tolerance.

import crypto from 'crypto';

const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

export function generateSecret(bytes = 20): string {
  const buf = crypto.randomBytes(bytes);
  return base32Encode(buf);
}

export function base32Encode(buf: Buffer): string {
  let bits = 0, value = 0, out = '';
  for (const b of buf) {
    value = (value << 8) | b;
    bits += 8;
    while (bits >= 5) { out += BASE32_ALPHABET[(value >>> (bits - 5)) & 31]; bits -= 5; }
  }
  if (bits > 0) out += BASE32_ALPHABET[(value << (5 - bits)) & 31];
  return out;
}
export function base32Decode(s: string): Buffer {
  const clean = s.toUpperCase().replace(/=+$/, '');
  let bits = 0, value = 0;
  const bytes: number[] = [];
  for (const ch of clean) {
    const idx = BASE32_ALPHABET.indexOf(ch);
    if (idx < 0) continue;
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) { bytes.push((value >>> (bits - 8)) & 0xff); bits -= 8; }
  }
  return Buffer.from(bytes);
}

function hotp(secret: Buffer, counter: number): string {
  const buf = Buffer.alloc(8);
  // 64-bit counter — high 32 are zero for our timestamps
  buf.writeUInt32BE(Math.floor(counter / 0x100000000), 0);
  buf.writeUInt32BE(counter & 0xffffffff, 4);
  const h = crypto.createHmac('sha1', secret).update(buf).digest();
  const offset = h[h.length - 1] & 0xf;
  const code = ((h[offset] & 0x7f) << 24) | ((h[offset + 1] & 0xff) << 16) | ((h[offset + 2] & 0xff) << 8) | (h[offset + 3] & 0xff);
  return String(code % 1_000_000).padStart(6, '0');
}

export function totpNow(secretBase32: string, period = 30): string {
  const counter = Math.floor(Date.now() / 1000 / period);
  return hotp(base32Decode(secretBase32), counter);
}

export function verifyTotp(secretBase32: string, code: string, period = 30, drift = 1): boolean {
  const now = Math.floor(Date.now() / 1000 / period);
  const secret = base32Decode(secretBase32);
  for (let i = -drift; i <= drift; i++) {
    if (hotp(secret, now + i) === code) return true;
  }
  return false;
}

// Per-user replay window. A TOTP code is valid for ~90s (period x 3
// steps with drift=1); without tracking, an attacker who captures the
// 6 digits can replay them within that window. We record the step
// number that was last accepted for each user and reject any code
// resolving to <= that step. Memory only — fine for single-process
// deployments; for clustered deployments use Redis with the same key.
const lastAcceptedStep = new Map<string, number>();
// Bound the map; very high cardinality (lots of users) would leak memory.
const MAX_TRACKED = 100_000;

export function verifyTotpAndConsume(
  userId: string,
  secretBase32: string,
  code: string,
  period = 30,
  drift = 1
): boolean {
  const now = Math.floor(Date.now() / 1000 / period);
  const secret = base32Decode(secretBase32);
  let matched: number | null = null;
  for (let i = -drift; i <= drift; i++) {
    const step = now + i;
    if (hotp(secret, step) === code) { matched = step; break; }
  }
  if (matched === null) return false;
  const prev = lastAcceptedStep.get(userId);
  if (prev !== undefined && matched <= prev) return false;  // replay
  if (lastAcceptedStep.size >= MAX_TRACKED) {
    // Drop the oldest half. O(n) but only fires on extreme cardinality.
    const entries = Array.from(lastAcceptedStep.entries()).sort((a, b) => a[1] - b[1]);
    for (const [k] of entries.slice(0, Math.floor(MAX_TRACKED / 2))) lastAcceptedStep.delete(k);
  }
  lastAcceptedStep.set(userId, matched);
  return true;
}

export function otpauthUri(secret: string, label: string, issuer: string): string {
  return `otpauth://totp/${encodeURIComponent(issuer)}:${encodeURIComponent(label)}?secret=${secret}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=6&period=30`;
}
