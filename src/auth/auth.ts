// Authentication and authorization. Signed-cookie sessions backed by
// the local user store. Open mode (no users provisioned) treats every
// request as an admin; a banner in the UI calls this out. The session
// secret is generated on first start and persisted under .data/.

import crypto from 'crypto';
import fs from 'fs';
import net from 'net';
import path from 'path';
import { NextFunction, Request, Response, Router } from 'express';
import bcrypt from 'bcryptjs';
import { z } from 'zod';
import { randomUUID as uuid } from 'crypto';
import { getUserById, getUserByUsername, getUserByIdIncludingDeleted, isOpenMode, listUsers, rawUsers, saveUser, softDeleteUser, hardDeleteUser } from '../store/userStore';
import { appendAudit } from '../store/auditStore';
import { SessionInfo, User, UserRole } from '../types/assessment';
import { getUserSecurity, findUserByApiKeyHash, saveUserSecurity } from '../store/userSecurityStore';
import { verifyTotpAndConsume } from './totp';
import { isLocked, recordFailure, recordSuccess, getLockouts, clearLock } from './loginThrottle';
import { requireSudo } from './sudo';

// ---- Audit-log sanitisers ----
// The login schema bounds `username` to 80 chars but DOES NOT
// charset-restrict it (so users typing the wrong thing get a clean
// error). Their failed attempt still has to be audit-logged for
// security telemetry, but we MUST NOT let arbitrary bytes
// (control chars, ANSI escape sequences, mock-HTML) land in the
// `actor` / `target` / `ip` fields of the audit JSONL. JSON encoding
// stops line-split / file-corruption attacks, but log-shippers /
// terminal viewers can still render those bytes maliciously.
//
// Pattern: validate; on hit, keep verbatim; on miss, normalise to a
// `<malformed:N>` marker that preserves the length signal without
// preserving the bytes.
const AUDIT_USERNAME_RE = /^[A-Za-z0-9._\-]{1,80}$/;
const AUDIT_IP_MAX_LEN = 64;

function safeUsername(v: string | undefined | null): string {
  if (!v) return '';
  if (AUDIT_USERNAME_RE.test(v)) return v;
  return `<malformed:${v.length}>`;
}

// IP validation uses Node's stdlib `net.isIP`, which is the
// authoritative parser for both IPv4 and IPv6 (rejects structural
// garbage like `....`, `[[[`, `::::` that a pure charset regex would
// accept). Brackets surrounding an IPv6 address are stripped before
// validation because some reverse proxies emit the bracketed form;
// the original (bracketed or not) is preserved in the audit entry.
function isValidIp(v: string): boolean {
  const stripped = v.startsWith('[') && v.endsWith(']') ? v.slice(1, -1) : v;
  return net.isIP(stripped) !== 0;
}
function safeIp(v: string | undefined | null): string {
  if (!v) return '';
  if (v.length > AUDIT_IP_MAX_LEN) return `<malformed:${v.length}>`;
  if (isValidIp(v)) return v;
  return `<malformed:${v.length}>`;
}

// Password policy. Enterprise: length AND complexity AND deny-list.
// Requires every character class (upper, lower, digit, special) +
// minimum 12 chars + denies a curated set of trivially-breached
// patterns. The simpler 2-class policy that lived here previously
// is preserved as `legacyPasswordPolicy` for back-compat with any
// migration tooling that needs to accept old-style passwords.
function strongPasswordPolicy(pw: string): { ok: boolean; reason?: string } {
  if (pw.length < 12) return { ok: false, reason: 'password must be at least 12 characters' };
  if (pw.length > 200) return { ok: false, reason: 'password too long' };
  if (!/[a-z]/.test(pw)) return { ok: false, reason: 'password must include a lowercase letter' };
  if (!/[A-Z]/.test(pw)) return { ok: false, reason: 'password must include an uppercase letter' };
  if (!/[0-9]/.test(pw)) return { ok: false, reason: 'password must include a digit' };
  if (!/[^A-Za-z0-9]/.test(pw)) return { ok: false, reason: 'password must include a special character' };
  const banned = new Set(['password', 'qwerty', 'changeme', 'welcome', 'iloveyou', '123456', '12345678', 'letmein', 'admin', 'monkey']);
  if (banned.has(pw.toLowerCase().replace(/[^a-z]+/g, ''))) {
    return { ok: false, reason: 'password matches a commonly-breached pattern' };
  }
  return { ok: true };
}
const passwordPolicy = strongPasswordPolicy;

const DATA_DIR = path.join(__dirname, '..', '..', '.data');
const SECRET_FILE = path.join(DATA_DIR, 'session-secret');
const COOKIE_NAME = 'arb_session';
// 5-minute absolute idle timeout per operator policy. A sliding-refresh
// hook (see `withSession` below) re-issues the cookie on every
// authenticated request so an active user isn't kicked out mid-form —
// but five minutes of true inactivity expires the session.
const SESSION_TTL_SECONDS = 5 * 60;

// Session secret with rotation. File is a JSONL of base64-encoded
// keys (newest first). New keys are prepended; older keys remain
// verifiable until tokens expire. Legacy 32-byte single-key files
// are upgraded transparently.
function loadSecrets(): Buffer[] {
  if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
  if (!fs.existsSync(SECRET_FILE)) {
    const seed = crypto.randomBytes(32);
    fs.writeFileSync(SECRET_FILE, seed.toString('base64') + '\n', { mode: 0o600 });
    return [seed];
  }
  const buf = fs.readFileSync(SECRET_FILE);
  if (buf.length === 32) return [buf]; // legacy raw-32 format
  return buf.toString('utf-8').split('\n').filter(Boolean).map(l => Buffer.from(l, 'base64'));
}
let SECRETS = loadSecrets();
function activeSecret(): Buffer { return SECRETS[0]!; }
export function rotateSessionSecret(): void {
  const next = crypto.randomBytes(32);
  SECRETS = [next, ...SECRETS].slice(0, 3);
  fs.writeFileSync(SECRET_FILE, SECRETS.map(s => s.toString('base64')).join('\n') + '\n', { mode: 0o600 });
}

function b64url(buf: Buffer): string {
  return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function fromB64url(s: string): Buffer {
  return Buffer.from(s.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
}

interface TokenPayload {
  sub: string;        // user id
  exp: number;        // epoch seconds
  iat: number;
}

export function signToken(userId: string): string {
  const payload: TokenPayload = {
    sub: userId,
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + SESSION_TTL_SECONDS
  };
  const body = b64url(Buffer.from(JSON.stringify(payload)));
  const sig = b64url(crypto.createHmac('sha256', activeSecret()).update(body).digest());
  return body + '.' + sig;
}

export function verifyToken(token: string): TokenPayload | null {
  const dot = token.indexOf('.');
  if (dot < 0) return null;
  const body = token.slice(0, dot);
  const sig = token.slice(dot + 1);
  // Try each known secret (active first, then any older keys still in
  // rotation). This lets us rotate without invalidating live sessions.
  let matched = false;
  for (const k of SECRETS) {
    const expected = b64url(crypto.createHmac('sha256', k).update(body).digest());
    if (sig.length === expected.length && crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) {
      matched = true; break;
    }
  }
  if (!matched) return null;
  let payload: TokenPayload;
  try {
    const p = JSON.parse(fromB64url(body).toString('utf-8')) as Partial<TokenPayload>;
    if (typeof p.sub !== 'string' || typeof p.exp !== 'number' || !Number.isFinite(p.exp) || typeof p.iat !== 'number') return null;
    payload = { sub: p.sub, exp: p.exp, iat: p.iat };
  } catch { return null; }
  if (payload.exp < Math.floor(Date.now() / 1000)) return null;
  return payload;
}

// Express middleware that resolves the current user. In open mode,
// every request becomes a virtual admin; otherwise a missing or
// invalid token is left as anonymous (route guards decide what to do).
export function withSession(req: Request, res: Response, next: NextFunction) {
  if (isOpenMode()) {
    (req as Request & { session?: SessionInfo }).session = {
      userId: 'open-mode',
      username: 'open-mode',
      displayName: 'Open Mode (no users provisioned)',
      roles: ['admin']
    };
    return next();
  }
  // 1) API key via Authorization: Bearer arb_...
  const auth = (req.headers.authorization || '').trim();
  if (auth.toLowerCase().startsWith('bearer ')) {
    const raw = auth.slice(7).trim();
    if (raw.startsWith('arb_')) {
      const hash = crypto.createHash('sha256').update(raw).digest('hex');
      const found = findUserByApiKeyHash(hash);
      if (found) {
        const user = getUserById(found.userId);
        if (user) {
          found.key.lastUsedAt = new Date().toISOString();
          saveUserSecurity({ ...getUserSecurity(user.id) });
          (req as Request & { session?: SessionInfo }).session = {
            userId: user.id, username: user.username, displayName: user.displayName, roles: user.roles
          };
          return next();
        }
      }
    }
  }

  // 2) Cookie session
  const cookie = (req.headers.cookie || '')
    .split(';')
    .map(s => s.trim())
    .find(s => s.startsWith(COOKIE_NAME + '='));
  if (!cookie) return next();
  const token = cookie.split('=', 2)[1];
  const payload = verifyToken(token!);
  if (!payload) return next();
  const user = getUserById(payload.sub);
  if (!user) return next();
  (req as Request & { session?: SessionInfo }).session = {
    userId: user.id,
    username: user.username,
    displayName: user.displayName,
    roles: user.roles
  };
  // Sliding refresh: every request the user makes with a valid session
  // cookie re-issues the cookie with a fresh 5-minute window. True
  // inactivity (no requests for 5 minutes) lets the cookie expire and
  // forces re-auth. Only refresh when at least half the TTL has been
  // burned, so we don't fight cache headers on chatty pages.
  const issuedAt = payload.iat;
  const ageSec = Math.floor(Date.now() / 1000) - issuedAt;
  if (ageSec > SESSION_TTL_SECONDS / 2) {
    const fresh = signToken(user.id);
    res.cookie(COOKIE_NAME, fresh, {
      httpOnly: true,
      sameSite: 'strict',
      secure: true,
      maxAge: SESSION_TTL_SECONDS * 1000,
      path: '/'
    });
  }
  next();
}

export function requireSession(req: Request, res: Response, next: NextFunction) {
  const s = (req as Request & { session?: SessionInfo }).session;
  if (!s) { res.status(401).json({ error: 'authentication required' }); return; }
  next();
}

export function requireRole(...roles: UserRole[]) {
  return (req: Request, res: Response, next: NextFunction) => {
    const s = (req as Request & { session?: SessionInfo }).session;
    if (!s) { res.status(401).json({ error: 'authentication required' }); return; }
    if (s.roles.includes('admin')) return next();
    if (roles.some(r => s.roles.includes(r))) return next();
    res.status(403).json({ error: 'insufficient role', required: roles });
  };
}

// ---- Auth routes ----

export const authRouter = Router();

const loginSchema = z.object({
  username: z.string().min(1).max(80),
  password: z.string().min(1).max(200),
  totp: z.string().regex(/^\d{6}$/).optional()
});

authRouter.post('/login', async (req, res) => {
  const parsed = loginSchema.safeParse(req.body);
  if (!parsed.success) { res.status(400).json({ error: 'invalid credentials' }); return; }
  const username = parsed.data.username;
  const ip = req.ip;
  // Audit-safe forms of the raw attacker input — see safeUsername /
  // safeIp at the top of the file. The throttle layer still uses the
  // *original* strings as map keys (so the same attempted username
  // accrues failures).
  const auditUsername = safeUsername(username);
  const auditIp = safeIp(ip);
  const lock = isLocked(username, ip);
  if (lock.locked) {
    appendAudit({ actor: auditUsername, action: 'auth.login.locked', target: auditUsername, ip: auditIp, details: { cooldownSeconds: lock.cooldownSeconds } });
    res.status(429).json({ error: 'too many failed attempts; try again later', cooldownSeconds: lock.cooldownSeconds });
    return;
  }
  const user = getUserByUsername(username);
  if (!user || !await bcrypt.compare(parsed.data.password, user.passwordHash)) {
    recordFailure(username, ip);
    appendAudit({ actor: auditUsername, action: 'auth.login.fail', target: auditUsername, ip: auditIp });
    res.status(401).json({ error: 'invalid credentials' });
    return;
  }
  if (user.disabled) {
    appendAudit({ actor: user.id, action: 'auth.login.disabled', target: user.id, ip: auditIp });
    res.status(403).json({ error: 'account disabled' });
    return;
  }
  const sec = getUserSecurity(user.id);
  if (sec.totpEnabled) {
    if (!parsed.data.totp) {
      res.status(401).json({ error: 'TOTP required', totp_required: true });
      return;
    }
    if (!verifyTotpAndConsume(user.id, sec.totpSecret!, parsed.data.totp)) {
      recordFailure(username, ip);
      appendAudit({ actor: user.id, action: 'auth.totp.fail', target: user.id, ip: auditIp });
      res.status(401).json({ error: 'invalid TOTP code' });
      return;
    }
  }
  recordSuccess(username, ip);
  // Track last login for the admin user list and any future
  // "Inactive accounts" report.
  user.lastLoginAt = new Date().toISOString();
  saveUser(user);
  const token = signToken(user.id);
  res.cookie(COOKIE_NAME, token, {
    httpOnly: true,
    sameSite: 'strict',
    // The app terminates TLS itself — Secure is unconditional.
    secure: true,
    maxAge: SESSION_TTL_SECONDS * 1000,
    path: '/'
  });
  appendAudit({ actor: user.id, action: 'auth.login.success', target: user.id, ip: safeIp(req.ip) });
  res.json({
    userId: user.id, username: user.username, displayName: user.displayName, roles: user.roles,
    forcePasswordChange: !!user.forcePasswordChange
  });
});

authRouter.post('/logout', (req, res) => {
  const s = (req as Request & { session?: SessionInfo }).session;
  res.clearCookie(COOKIE_NAME, { path: '/' });
  if (s) appendAudit({ actor: s.userId, action: 'auth.logout', target: s.userId, ip: safeIp(req.ip) });
  res.status(204).end();
});

authRouter.get('/me', (req, res) => {
  const s = (req as Request & { session?: SessionInfo }).session;
  res.json({ session: s ?? null, openMode: isOpenMode() });
});

const provisionSchema = z.object({
  username: z.string().min(1).max(80).regex(/^[A-Za-z0-9._-]+$/, 'username may use letters, digits, dot, underscore, dash'),
  displayName: z.string().min(1).max(200),
  password: z.string().min(12).max(200),
  roles: z.array(z.enum(['admin', 'architect', 'analyst', 'product-owner', 'approver-security', 'approver-risk', 'approver-architecture', 'approver-compliance'])).min(1),
  team: z.string().max(80).optional()
});

// In open mode anyone can provision the first user (typically the
// admin), which immediately closes the open-mode hatch. Once at least
// one user exists, provisioning requires admin role.
authRouter.post('/users', async (req, res) => {
  const parsed = provisionSchema.safeParse(req.body);
  if (!parsed.success) { res.status(400).json({ error: 'invalid user', issues: parsed.error.format() }); return; }
  if (!isOpenMode()) {
    const s = (req as Request & { session?: SessionInfo }).session;
    if (!s || !s.roles.includes('admin')) { res.status(403).json({ error: 'admin required' }); return; }
  }
  const pol = passwordPolicy(parsed.data.password);
  if (!pol.ok) { res.status(400).json({ error: pol.reason }); return; }
  if (getUserByUsername(parsed.data.username)) { res.status(409).json({ error: 'username exists' }); return; }
  const user: User = {
    id: uuid(),
    username: parsed.data.username,
    displayName: parsed.data.displayName,
    passwordHash: await bcrypt.hash(parsed.data.password, 10),
    roles: parsed.data.roles,
    createdAt: new Date().toISOString(),
    team: parsed.data.team
  };
  saveUser(user);
  appendAudit({ actor: (req as Request & { session?: SessionInfo }).session?.userId ?? 'bootstrap', action: 'user.create', target: user.id, details: { username: user.username, roles: user.roles } });
  res.status(201).json({ id: user.id, username: user.username, displayName: user.displayName, roles: user.roles });
});

authRouter.get('/users', requireRole('admin'), (_req, res) => {
  res.json({ users: listUsers() });
});

authRouter.post('/users/:id/disable', requireRole('admin'), requireSudo, (req, res) => {
  const u = getUserById(req.params.id);
  if (!u) { res.status(404).json({ error: 'not found' }); return; }
  // Bound + sanitise the reason. Strip control characters that would
  // confuse log shippers; cap length so a single audit entry can't
  // balloon. The "$unset" sentinel used by the PATCH audit logger is
  // free-text but cannot collide here because the reason is stored as
  // a literal string field, not normalised through the same coder.
  const rParsed = z.object({ reason: z.string().max(500).optional() }).safeParse(req.body ?? {});
  if (!rParsed.success) { res.status(400).json({ error: 'invalid reason' }); return; }
  const reason = (rParsed.data.reason ?? '').replace(/[\x00-\x08\x0b\x0c\x0e-\x1f]/g, '');
  u.disabled = true;
  u.disabledAt = new Date().toISOString();
  u.disabledReason = reason;
  saveUser(u);
  // Audit captures the length plus a short preview, not the whole
  // reason — defends against an admin pasting PII or a secret into
  // the field while still letting reviewers spot the disable.
  const preview = reason.length > 80 ? reason.slice(0, 80) + '…' : reason;
  appendAudit({
    actor: (req as Request & { session?: SessionInfo }).session?.userId ?? 'admin',
    action: 'user.disable', target: u.id,
    details: { reasonLength: reason.length, reasonPreview: preview }
  });
  res.json({ id: u.id, disabled: true });
});

authRouter.post('/users/:id/enable', requireRole('admin'), requireSudo, (req, res) => {
  const u = getUserById(req.params.id);
  if (!u) { res.status(404).json({ error: 'not found' }); return; }
  u.disabled = false;
  delete u.disabledAt; delete u.disabledReason;
  saveUser(u);
  appendAudit({ actor: (req as Request & { session?: SessionInfo }).session?.userId ?? 'admin', action: 'user.enable', target: u.id });
  res.json({ id: u.id, disabled: false });
});

// PATCH profile fields. Admin-only — self-service profile edit is a
// separate future endpoint that doesn't need sudo. Username,
// passwordHash, id, createdAt are NOT mutable through this surface;
// password changes go through the dedicated reset routes.
const profilePatchSchema = z.object({
  displayName: z.string().min(1).max(120).optional(),
  email: z.string().email().max(200).optional(),
  firstName: z.string().max(60).optional(),
  lastName: z.string().max(60).optional(),
  department: z.string().max(80).optional(),
  jobTitle: z.string().max(80).optional(),
  phone: z.string().max(30).optional(),
  timezone: z.string().max(60).optional(),
  notes: z.string().max(2000).optional(),
  team: z.string().max(60).optional(),
  roles: z.array(z.enum(['admin', 'architect', 'analyst', 'product-owner', 'approver-security', 'approver-risk', 'approver-architecture', 'approver-compliance'])).min(1).optional()
}).strict();

authRouter.patch('/users/:id', requireRole('admin'), requireSudo, (req, res) => {
  const u = getUserById(req.params.id);
  if (!u) { res.status(404).json({ error: 'not found' }); return; }
  const parsed = profilePatchSchema.safeParse(req.body);
  if (!parsed.success) { res.status(400).json({ error: 'invalid', issues: parsed.error.format() }); return; }
  const actorId = (req as Request & { session?: SessionInfo }).session?.userId ?? 'admin';
  // Last-admin safeguard: never let an admin demote the only remaining
  // active admin (themselves or anyone else). Same protection applied
  // on disable; mirror it here.
  if (parsed.data.roles && !parsed.data.roles.includes('admin')) {
    const otherAdmins = listUsers().filter(x => x.id !== u.id && !x.disabled && x.roles.includes('admin'));
    if (u.roles.includes('admin') && otherAdmins.length === 0) {
      res.status(409).json({ error: 'cannot demote the last active admin' });
      return;
    }
  }
  // Capture before/after on only the fields the PATCH touched. We
  // deliberately do not log `notes` content (large free-text, possible
  // PII) — log its length instead so reviewers can spot deletions.
  // Use the sentinel "<unset>" rather than null so a reviewer can
  // unambiguously distinguish "field was empty" (empty string) from
  // "field was not present" — if the schema ever evolves to accept
  // null/undefined, the audit trail still tells the truth.
  const UNSET = '<unset>';
  const norm = (v: unknown): unknown => v === undefined || v === null ? UNSET : v;
  const touched = Object.keys(parsed.data) as (keyof typeof parsed.data)[];
  const before: Record<string, unknown> = {};
  const after: Record<string, unknown> = {};
  for (const k of touched) {
    if (k === 'notes') {
      before[k] = typeof u.notes === 'string' ? `<${u.notes.length} chars>` : UNSET;
      after[k] = typeof parsed.data.notes === 'string' ? `<${parsed.data.notes.length} chars>` : UNSET;
    } else {
      before[k] = norm((u as unknown as Record<string, unknown>)[k]);
      after[k] = norm((parsed.data as unknown as Record<string, unknown>)[k]);
    }
  }
  Object.assign(u, parsed.data);
  u.updatedAt = new Date().toISOString();
  saveUser(u);
  appendAudit({
    actor: actorId, action: 'user.update', target: u.id,
    details: { fields: touched, before, after }
  });
  res.json({ id: u.id, ...parsed.data });
});

// Soft delete by default. ?hard=1 requires sudo (already enforced) and
// is irreversible — it's the GDPR "right to erasure" surface. Hard
// delete must be able to target rows that were *previously*
// soft-deleted, so look up via the including-deleted helper.
authRouter.delete('/users/:id', requireRole('admin'), requireSudo, (req, res) => {
  const hard = req.query.hard === '1';
  const u = hard ? getUserByIdIncludingDeleted(req.params.id) : getUserById(req.params.id);
  if (!u) { res.status(404).json({ error: 'not found' }); return; }
  const actorId = (req as Request & { session?: SessionInfo }).session?.userId ?? 'admin';
  // Refuse to delete yourself — same anti-lockout argument as disable.
  if (actorId === u.id) {
    res.status(409).json({ error: 'cannot delete your own account' });
    return;
  }
  // Refuse to delete the last active admin. (A soft-deleted admin is
  // already not "active," so this only fires for soft-delete or for
  // hard-delete of an active admin.)
  if (u.roles.includes('admin') && !u.deletedAt) {
    const otherAdmins = listUsers().filter(x => x.id !== u.id && !x.disabled && x.roles.includes('admin'));
    if (otherAdmins.length === 0) {
      res.status(409).json({ error: 'cannot delete the last active admin' });
      return;
    }
  }
  const ok = hard ? hardDeleteUser(u.id) : softDeleteUser(u.id);
  appendAudit({
    actor: actorId, action: hard ? 'user.hard_delete' : 'user.soft_delete',
    target: u.id, details: { username: u.username, wasAlreadySoftDeleted: !!u.deletedAt }
  });
  res.status(ok ? 204 : 404).end();
});

// Flag the user to be required to set a new password on next login.
// The login flow checks this and returns forcePasswordChange:true in
// the response; the UI gates further navigation until the user resets.
authRouter.post('/users/:id/force-password-change', requireRole('admin'), requireSudo, (req, res) => {
  const u = getUserById(req.params.id);
  if (!u) { res.status(404).json({ error: 'not found' }); return; }
  u.forcePasswordChange = true;
  u.updatedAt = new Date().toISOString();
  saveUser(u);
  appendAudit({
    actor: (req as Request & { session?: SessionInfo }).session?.userId ?? 'admin',
    action: 'user.force_password_change', target: u.id
  });
  res.json({ id: u.id, forcePasswordChange: true });
});

// Per-user rate limit on change-password attempts. Defence against an
// attacker with a stolen session cookie attempting to brute-force the
// current password. bcrypt cost already makes brute force slow; this
// caps the attempt count cheaply.
const CHANGE_PWD_WINDOW_MS = 60 * 60 * 1000;  // 1h
const CHANGE_PWD_MAX_FAIL = 5;
const changePwdFails = new Map<string, number[]>();

function tooManyChangePwdAttempts(userId: string): boolean {
  const now = Date.now();
  const arr = (changePwdFails.get(userId) ?? []).filter(t => t > now - CHANGE_PWD_WINDOW_MS);
  // Drop the entry entirely once the window has cleared, so the Map
  // doesn't accumulate one empty-array entry per user ever seen.
  if (arr.length === 0) changePwdFails.delete(userId);
  else changePwdFails.set(userId, arr);
  return arr.length >= CHANGE_PWD_MAX_FAIL;
}
function recordChangePwdFail(userId: string): void {
  const now = Date.now();
  // Filter stale entries on every record so the recorded count is
  // always a valid window snapshot — closes the race where
  // tooManyChangePwdAttempts deletes the key during the bcrypt await
  // and recordChangePwdFail then reads undefined and starts a fresh
  // bucket containing only the new timestamp.
  const arr = (changePwdFails.get(userId) ?? []).filter(t => t > now - CHANGE_PWD_WINDOW_MS);
  arr.push(now);
  changePwdFails.set(userId, arr);
}

// Self-service password change. Requires the current password; clears
// forcePasswordChange on success.
authRouter.post('/change-password', requireSession, async (req, res) => {
  const s = (req as Request & { session?: SessionInfo }).session!;
  if (tooManyChangePwdAttempts(s.userId)) {
    res.status(429).json({ error: 'too many attempts; try again later' });
    return;
  }
  const schema = z.object({
    currentPassword: z.string().min(1).max(200),
    newPassword: z.string().min(12).max(200)
  });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) { res.status(400).json({ error: 'invalid' }); return; }
  const u = getUserById(s.userId);
  if (!u) { res.status(401).json({ error: 'unknown user' }); return; }
  if (!await bcrypt.compare(parsed.data.currentPassword, u.passwordHash)) {
    recordChangePwdFail(s.userId);
    appendAudit({ actor: u.id, action: 'user.change_password.fail', target: u.id });
    res.status(401).json({ error: 'current password incorrect' });
    return;
  }
  const pol = strongPasswordPolicy(parsed.data.newPassword);
  if (!pol.ok) { res.status(400).json({ error: pol.reason }); return; }
  u.passwordHash = await bcrypt.hash(parsed.data.newPassword, 10);
  u.updatedAt = new Date().toISOString();
  u.forcePasswordChange = false;
  saveUser(u);
  // Clear the failure counter on success so the user doesn't carry
  // accumulated penalty into a future legitimate change.
  changePwdFails.delete(s.userId);
  appendAudit({ actor: u.id, action: 'user.change_password.ok', target: u.id });
  res.json({ ok: true });
});

// ---- Lockouts (admin security dashboard) ----
// Read-only listing of usernames / IPs currently in the login-throttle
// cooldown window. The security dashboard pulls this on every refresh.
authRouter.get('/lockouts', requireRole('admin'), (_req, res) => {
  // Passes through { lockouts, truncated, totalActive } from the store.
  // The cap (defined in loginThrottle.ts) keeps the response bounded
  // even under credential-stuffing across many unique IPs.
  res.json(getLockouts());
});

// Admin "unlock" — clear a specific cooldown. Requires sudo because it
// undoes a credential-stuffing defence.
//
// `username` is bounded to the project username charset
// (matches user-store validation) and `ip` to the canonical IPv4 /
// IPv6 charset. This ensures the audit log can't carry arbitrary
// bytes (control characters, ANSI escapes, Unicode tricks) supplied
// by whatever attempted-login the throttle bucketed — even though
// JSON encoding defangs CR/LF line-splits, charset-bounding is the
// proper defence.
// IP uses Node's authoritative `net.isIP` (via isValidIp). Bracketed
// IPv6 like `[fe80::1]` is supported because admins commonly paste
// that form from access logs.
const lockoutClearSchema = z.object({
  username: z.string().min(1).max(80).regex(/^[A-Za-z0-9._\-]+$/).optional(),
  ip: z.string().min(1).max(AUDIT_IP_MAX_LEN).refine(isValidIp, 'must be a valid IPv4 or IPv6 address').optional()
});

authRouter.post('/lockouts/clear', requireRole('admin'), requireSudo, (req, res) => {
  const parsed = lockoutClearSchema.safeParse(req.body);
  if (!parsed.success || (!parsed.data.username && !parsed.data.ip)) {
    res.status(400).json({ error: 'specify a valid username and/or IP' });
    return;
  }
  const result = clearLock(parsed.data);
  appendAudit({
    actor: (req as Request & { session?: SessionInfo }).session?.userId ?? 'admin',
    action: 'auth.lockout.clear',
    target: parsed.data.username || parsed.data.ip || '?',
    details: { ...parsed.data, cleared: result.cleared }
  });
  res.json(result);
});

// M65 — session-secret rotation
authRouter.post('/rotate-secret', requireRole('admin'), requireSudo, (req, res) => {
  rotateSessionSecret();
  appendAudit({ actor: (req as Request & { session?: SessionInfo }).session?.userId ?? 'admin', action: 'auth.rotate-secret', target: 'session-secret' });
  res.json({ rotated: true, note: 'Existing sessions remain valid until they expire; older keys are retained for verification.' });
});

export function getSession(req: Request): SessionInfo | undefined {
  return (req as Request & { session?: SessionInfo }).session;
}

export { isOpenMode } from '../store/userStore';
