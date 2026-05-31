// Login throttling. Per-account and per-IP sliding-window counters
// limit credential-stuffing. After N failures in W seconds a
// COOLDOWN_MS window is enforced. State is persisted to .data/throttle.json
// so a restart can't be used to escape an active cooldown; for multi-node
// deployments use Redis or DB.

import fs from 'fs';
import path from 'path';

const W = 15 * 60_000;       // 15 min window
const PER_USER_MAX = 5;      // 5 failures / 15 min
const PER_IP_MAX = 30;       // 30 failures / 15 min
const COOLDOWN_MS = 5 * 60_000;

interface Counter { failures: number[]; cooldownUntil?: number }
const userCounters = new Map<string, Counter>();
const ipCounters = new Map<string, Counter>();

const STATE_FILE = path.join(__dirname, '..', '..', '.data', 'login-throttle.json');
let loaded = false;
function loadIfNeeded(): void {
  if (loaded) return;
  loaded = true;
  if (!fs.existsSync(STATE_FILE)) return;
  try {
    const raw = JSON.parse(fs.readFileSync(STATE_FILE, 'utf-8')) as { users?: Record<string, Counter>; ips?: Record<string, Counter> };
    for (const [k, v] of Object.entries(raw.users ?? {})) userCounters.set(k, v);
    for (const [k, v] of Object.entries(raw.ips ?? {})) ipCounters.set(k, v);
  } catch { /* corrupt file — start clean */ }
}
function persist(): void {
  try {
    const dir = path.dirname(STATE_FILE);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    const tmp = STATE_FILE + '.tmp.' + process.pid;
    fs.writeFileSync(tmp, JSON.stringify({
      users: Object.fromEntries(userCounters),
      ips: Object.fromEntries(ipCounters)
    }), { mode: 0o600 });
    fs.renameSync(tmp, STATE_FILE);
  } catch { /* best-effort */ }
}

function prune(c: Counter, now: number): void {
  c.failures = c.failures.filter(t => t > now - W);
}

export function isLocked(username: string, ip: string | undefined): { locked: boolean; reason?: string; cooldownSeconds?: number } {
  loadIfNeeded();
  const now = Date.now();
  // Empty IP must still be throttled — otherwise an attacker behind a
  // proxy that strips X-Forwarded-For escapes per-IP limits entirely.
  // Bucket all unknown-IP requests under a single "unknown" key.
  for (const [k, m] of [[username, userCounters], [ip || 'unknown', ipCounters]] as [string, Map<string, Counter>][]) {
    if (!k) continue;
    const c = m.get(k);
    if (!c) continue;
    if (c.cooldownUntil && c.cooldownUntil > now) {
      return { locked: true, reason: 'too many failed attempts', cooldownSeconds: Math.ceil((c.cooldownUntil - now) / 1000) };
    }
  }
  return { locked: false };
}

export function recordFailure(username: string, ip: string | undefined): void {
  loadIfNeeded();
  const now = Date.now();
  for (const [k, m, max] of [[username, userCounters, PER_USER_MAX], [ip || 'unknown', ipCounters, PER_IP_MAX]] as [string, Map<string, Counter>, number][]) {
    if (!k) continue;
    let c = m.get(k);
    if (!c) { c = { failures: [] }; m.set(k, c); }
    prune(c, now);
    c.failures.push(now);
    if (c.failures.length >= max) c.cooldownUntil = now + COOLDOWN_MS;
  }
  persist();
}

export function recordSuccess(username: string, ip: string | undefined): void {
  loadIfNeeded();
  userCounters.delete(username);
  if (ip) ipCounters.delete(ip);
  persist();
}

// Snapshot the current locked-out usernames and IPs for the admin
// security dashboard. Returns only entries whose cooldown is still in
// the future relative to `now`; expired cooldowns are filtered out.
export interface Lockout {
  kind: 'user' | 'ip';
  key: string;
  cooldownUntil: string;          // ISO timestamp
  cooldownSecondsRemaining: number;
  failuresInWindow: number;
}
// Cap the response size. Under credential-stuffing attack from many
// unique IPs we could otherwise emit tens of MB of JSON. The cap
// reflects what's actionable for an operator (clearing a few
// at-most); the truncation flag tells them more exist.
export const LOCKOUTS_RESPONSE_CAP = 100;

export function getLockouts(): { lockouts: Lockout[]; truncated: boolean; totalActive: number } {
  loadIfNeeded();
  const now = Date.now();
  const out: Lockout[] = [];
  const collect = (map: Map<string, Counter>, kind: 'user' | 'ip') => {
    for (const [key, c] of map.entries()) {
      if (!c.cooldownUntil || c.cooldownUntil <= now) continue;
      const remaining = Math.ceil((c.cooldownUntil - now) / 1000);
      out.push({
        kind, key,
        cooldownUntil: new Date(c.cooldownUntil).toISOString(),
        cooldownSecondsRemaining: remaining,
        failuresInWindow: c.failures.filter(t => t > now - W).length
      });
    }
  };
  collect(userCounters, 'user');
  collect(ipCounters, 'ip');
  out.sort((a, b) => b.cooldownSecondsRemaining - a.cooldownSecondsRemaining);
  return {
    lockouts: out.slice(0, LOCKOUTS_RESPONSE_CAP),
    truncated: out.length > LOCKOUTS_RESPONSE_CAP,
    totalActive: out.length
  };
}

// Admin "unlock" — clears the cooldown for a username and/or IP so the
// affected party can attempt to log in again before the window expires.
export function clearLock(target: { username?: string; ip?: string }): { cleared: boolean } {
  loadIfNeeded();
  let cleared = false;
  if (target.username) cleared = userCounters.delete(target.username) || cleared;
  if (target.ip) cleared = ipCounters.delete(target.ip) || cleared;
  if (cleared) persist();
  return { cleared };
}
