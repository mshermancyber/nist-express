// Per-user security extensions: TOTP secret + enabled flag, list of
// API keys (each stored as sha256 of the raw secret). TOTP secrets
// are field-encrypted at rest via AES-256-GCM; legacy plaintext values
// are re-encrypted on next write transparently.

import fs from 'fs';
import path from 'path';
import { UserSecurity, ApiKey } from '../types/assessment';
import { encryptString, decryptString } from '../auth/crypto';

const FILE = path.join(__dirname, '..', '..', '.data', 'user-security.json');

let cache: UserSecurity[] | null = null;

function load(): UserSecurity[] {
  if (cache) return cache;
  if (!fs.existsSync(FILE)) { cache = []; return cache; }
  try {
    const raw = JSON.parse(fs.readFileSync(FILE, 'utf-8')) as UserSecurity[];
    // Decrypt any encrypted-on-disk fields lazily; values without the
    // enc:v1: prefix are treated as plaintext (legacy) — they'll be
    // re-encrypted on next save.
    cache = raw.map(u => ({ ...u, totpSecret: u.totpSecret ? decryptString(u.totpSecret) : u.totpSecret }));
  } catch { cache = []; }
  return cache;
}

function persist(): void {
  const out = (cache ?? []).map(u => ({ ...u, totpSecret: u.totpSecret ? encryptString(u.totpSecret) : u.totpSecret }));
  fs.writeFileSync(FILE, JSON.stringify(out, null, 2));
}

export function getUserSecurity(userId: string): UserSecurity {
  const all = load();
  let s = all.find(x => x.userId === userId);
  if (!s) { s = { userId, apiKeys: [] }; all.push(s); persist(); }
  return s;
}
export function saveUserSecurity(s: UserSecurity): void {
  const all = load();
  const i = all.findIndex(x => x.userId === s.userId);
  if (i >= 0) all[i] = s; else all.push(s);
  persist();
}
import crypto from 'crypto';
export function findUserByApiKeyHash(hash: string): { userId: string; key: ApiKey } | undefined {
  const wantBuf = Buffer.from(hash, 'hex');
  const all = load();
  for (const u of all) {
    for (const k of u.apiKeys) {
      if (k.revokedAt) continue;
      const stored = Buffer.from(k.hash, 'hex');
      if (stored.length !== wantBuf.length) continue;
      // Timing-safe so we don't leak prefix matches across keys.
      if (crypto.timingSafeEqual(stored, wantBuf)) return { userId: u.userId, key: k };
    }
  }
  return undefined;
}
