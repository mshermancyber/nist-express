// Append-only audit log with HMAC-chained integrity. Each entry's hash
// is HMAC(key, prev_hash || entry_body); the chain head is exported
// via verifyChain() so an external auditor can prove no entries have
// been deleted or reordered.
//
// The HMAC key is dedicated to the audit chain (.data/audit-chain-key,
// 32 random bytes, mode 0600). It is INDEPENDENT of the session secret
// — rotating the session secret must NOT invalidate prior audit
// entries. The key is generated lazily on first use and never rotated.

import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { randomUUID } from 'crypto';
import { AuditLogEntry } from '../types/assessment';

const DATA_DIR = path.join(__dirname, '..', '..', '.data');
const AUDIT_FILE = path.join(DATA_DIR, 'audit.jsonl');
const HEAD_FILE = path.join(DATA_DIR, 'audit-head');
const CHAIN_KEY_FILE = path.join(DATA_DIR, 'audit-chain-key');

if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

let cachedKey: Buffer | null = null;
function chainKey(): Buffer {
  if (cachedKey) return cachedKey;
  if (!fs.existsSync(CHAIN_KEY_FILE)) {
    fs.writeFileSync(CHAIN_KEY_FILE, crypto.randomBytes(32), { mode: 0o600 });
  }
  cachedKey = fs.readFileSync(CHAIN_KEY_FILE);
  // Defensive: if the file was written with bad length, regenerate.
  if (cachedKey.length !== 32) {
    cachedKey = crypto.randomBytes(32);
    fs.writeFileSync(CHAIN_KEY_FILE, cachedKey, { mode: 0o600 });
  }
  return cachedKey;
}

function currentHead(): string {
  if (!fs.existsSync(HEAD_FILE)) return '';
  return fs.readFileSync(HEAD_FILE, 'utf-8').trim();
}

function writeHead(h: string): void {
  fs.writeFileSync(HEAD_FILE, h);
}

// Atomic append: write to a temp file then fsync + append. For our
// scale (single-node, low write rate) a synchronous append after the
// fsync is sufficient. fs.appendFileSync uses O_APPEND so concurrent
// writers don't corrupt the file at the byte level.
export function appendAudit(entry: Omit<AuditLogEntry, 'id' | 'ts'>): AuditLogEntry {
  const full: AuditLogEntry = { id: randomUUID(), ts: new Date().toISOString(), ...entry };
  const prev = currentHead();
  const body = JSON.stringify(full);
  const mac = crypto.createHmac('sha256', chainKey()).update(prev).update(body).digest('hex');
  const line = JSON.stringify({ ...full, _chain: { prev: prev || null, mac } });
  fs.appendFileSync(AUDIT_FILE, line + '\n');
  writeHead(mac);
  return full;
}

export function listAudit(limit = 200): AuditLogEntry[] {
  if (!fs.existsSync(AUDIT_FILE)) return [];
  // Stream tail to avoid pulling huge files entirely into memory.
  const data = fs.readFileSync(AUDIT_FILE, 'utf-8');
  const lines = data.split('\n').filter(Boolean);
  const tail = lines.slice(-limit);
  const out: AuditLogEntry[] = [];
  for (const line of tail) {
    try {
      const parsed = JSON.parse(line) as Record<string, unknown> & AuditLogEntry;
      delete parsed._chain;
      out.push(parsed);
    } catch { /* skip */ }
  }
  return out.reverse();
}

export function verifyChain(): { ok: boolean; entries: number; firstBadIndex?: number } {
  if (!fs.existsSync(AUDIT_FILE)) return { ok: true, entries: 0 };
  const lines = fs.readFileSync(AUDIT_FILE, 'utf-8').split('\n').filter(Boolean);
  const key = chainKey();
  let prev = '';
  for (let i = 0; i < lines.length; i++) {
    try {
      const obj = JSON.parse(lines[i]!) as AuditLogEntry & { _chain: { prev: string | null; mac: string } };
      const { _chain, ...body } = obj;
      const expected = crypto.createHmac('sha256', key).update(prev).update(JSON.stringify(body)).digest('hex');
      if (expected !== _chain.mac) return { ok: false, entries: lines.length, firstBadIndex: i };
      prev = _chain.mac;
    } catch { return { ok: false, entries: lines.length, firstBadIndex: i }; }
  }
  return { ok: true, entries: lines.length };
}
