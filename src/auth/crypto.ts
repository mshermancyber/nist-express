// Envelope encryption for sensitive secrets at rest. Uses AES-256-GCM
// with a key derived from the Key Encryption Key (KEK):
//   - If KEY_ENCRYPTION_KEY env var is set (base64), use that.
//   - Else, derive from the session-secret active key + a domain label
//     so the encryption-of-rest key is bound to platform identity.
//   - Else (no session secret yet), use a file-derived KEK at
//     .data/kek (mode 0600).
//
// Ciphertext shape: "enc:v1:" + base64(iv (12) || tag (16) || ct).
// Decrypt accepts the same prefix; values without the prefix are
// treated as legacy plaintext and re-encrypted on next write.

import crypto from 'crypto';
import fs from 'fs';
import path from 'path';

const PREFIX = 'enc:v1:';
const DATA_DIR = path.join(__dirname, '..', '..', '.data');
const KEK_FILE = path.join(DATA_DIR, 'kek');
const DOMAIN = 'nist-express:field-encryption';

function deriveKey(): Buffer {
  const env = process.env.KEY_ENCRYPTION_KEY;
  if (env) {
    const raw = Buffer.from(env, 'base64');
    if (raw.length !== 32) throw new Error('KEY_ENCRYPTION_KEY must decode to 32 bytes');
    return raw;
  }
  // Derive from the session secret if present
  try {
    const SECRET_FILE = path.join(DATA_DIR, 'session-secret');
    if (fs.existsSync(SECRET_FILE)) {
      const buf = fs.readFileSync(SECRET_FILE);
      const seed = buf.length === 32 ? buf : Buffer.from(buf.toString('utf-8').split('\n').filter(Boolean)[0] ?? '', 'base64');
      if (seed.length === 32) return Buffer.from(crypto.hkdfSync('sha256', seed, Buffer.alloc(0), Buffer.from(DOMAIN), 32));
    }
  } catch { /* fall through */ }
  // File-derived fallback. Exclusive-create (flag: 'wx') eliminates the
  // TOCTOU between exists+write — two concurrent first-boots can't both
  // win and derive different keys.
  if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
  try {
    fs.writeFileSync(KEK_FILE, crypto.randomBytes(32), { mode: 0o600, flag: 'wx' });
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code !== 'EEXIST') throw e;
  }
  return fs.readFileSync(KEK_FILE);
}

export function encryptString(plaintext: string): string {
  if (!plaintext) return plaintext;
  const key = deriveKey();
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ct = Buffer.concat([cipher.update(plaintext, 'utf-8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return PREFIX + Buffer.concat([iv, tag, ct]).toString('base64');
}

export function decryptString(value: string): string {
  if (!value || !value.startsWith(PREFIX)) return value;  // legacy plaintext
  const raw = Buffer.from(value.slice(PREFIX.length), 'base64');
  const iv = raw.subarray(0, 12);
  const tag = raw.subarray(12, 28);
  const ct = raw.subarray(28);
  const decipher = crypto.createDecipheriv('aes-256-gcm', deriveKey(), iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ct), decipher.final()]).toString('utf-8');
}

export function isEncrypted(value: string | undefined): boolean {
  return !!value && value.startsWith(PREFIX);
}
