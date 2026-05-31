// Admin-initiated password reset. The admin asks for a reset for a
// target user; the platform issues a single-use, signed, 24h reset
// token (returned ONCE in the response — the admin hands it off
// out-of-band). The user redeems the token to set a new password.
//
// There is no self-service "forgot my password" flow because the
// platform has no email integration. Adding email is a separate
// milestone.

import { Router, Request, Response } from 'express';
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import { z } from 'zod';
import bcrypt from 'bcryptjs';
import { getSession, requireRole } from '../auth/auth';
import { requireSudo } from '../auth/sudo';
import { getUserById, saveUser, getUserByUsername } from '../store/userStore';
import { appendAudit } from '../store/auditStore';

export const passwordResetRouter = Router();

const RESET_FILE = path.join(__dirname, '..', '..', '.data', 'password-resets.json');

interface ResetToken { id: string; userId: string; tokenHash: string; expiresAt: string; used: boolean }

function loadResets(): ResetToken[] {
  if (!fs.existsSync(RESET_FILE)) return [];
  try { return JSON.parse(fs.readFileSync(RESET_FILE, 'utf-8')) as ResetToken[]; } catch { return []; }
}
function persistResets(rs: ResetToken[]): void {
  // Atomic write: stage in a sibling temp file, fsync, rename. A crash
  // mid-write can never leave a half-truncated reset journal.
  const tmp = RESET_FILE + '.tmp.' + process.pid;
  fs.writeFileSync(tmp, JSON.stringify(rs, null, 2), { mode: 0o600 });
  fs.renameSync(tmp, RESET_FILE);
}

function passwordPolicy(pw: string): { ok: boolean; reason?: string } {
  if (pw.length < 12) return { ok: false, reason: 'password must be at least 12 characters' };
  if (pw.length > 200) return { ok: false, reason: 'password too long' };
  const classes = [/[a-z]/, /[A-Z]/, /[0-9]/, /[^A-Za-z0-9]/].filter(re => re.test(pw)).length;
  if (classes < 2) return { ok: false, reason: 'need at least 2 character classes' };
  return { ok: true };
}

// Admin issues a reset; raw token returned ONCE. Stored hashed.
passwordResetRouter.post('/:id/reset', requireRole('admin'), requireSudo, (req: Request, res: Response) => {
  const u = getUserById(req.params.id);
  if (!u) { res.status(404).json({ error: 'not found' }); return; }
  const raw = 'rst_' + crypto.randomBytes(24).toString('hex');
  const hash = crypto.createHash('sha256').update(raw).digest('hex');
  const exp = new Date(Date.now() + 24 * 3600 * 1000).toISOString();
  const rs = loadResets();
  rs.push({ id: crypto.randomUUID(), userId: u.id, tokenHash: hash, expiresAt: exp, used: false });
  persistResets(rs);
  appendAudit({ actor: getSession(req)!.userId, action: 'user.password.reset.issue', target: u.id });
  res.status(201).json({ token: raw, expiresAt: exp, note: 'Hand this token to the user out-of-band. It is shown ONCE.' });
});

const redeemSchema = z.object({
  token: z.string().min(20).max(80),
  newPassword: z.string().min(12).max(200)
});

passwordResetRouter.post('/redeem', (req, res) => {
  const parsed = redeemSchema.safeParse(req.body);
  if (!parsed.success) { res.status(400).json({ error: 'invalid' }); return; }
  const pol = passwordPolicy(parsed.data.newPassword);
  if (!pol.ok) { res.status(400).json({ error: pol.reason }); return; }
  const wantHash = crypto.createHash('sha256').update(parsed.data.token).digest('hex');
  const wantBuf = Buffer.from(wantHash, 'hex');
  const rs = loadResets();
  // Timing-safe compare so we don't leak which prefix of the hash matched.
  const entry = rs.find(r => {
    const stored = Buffer.from(r.tokenHash, 'hex');
    return stored.length === wantBuf.length && crypto.timingSafeEqual(stored, wantBuf);
  });
  if (!entry || entry.used || Date.parse(entry.expiresAt) < Date.now()) {
    res.status(400).json({ error: 'invalid or expired token' });
    return;
  }
  bcrypt.hash(parsed.data.newPassword, 10).then(hash => {
    const u = getUserById(entry.userId);
    if (!u) { res.status(404).json({ error: 'user not found' }); return; }
    u.passwordHash = hash;
    saveUser(u);
    entry.used = true;
    persistResets(rs);
    appendAudit({ actor: u.id, action: 'user.password.reset.redeem', target: u.id });
    res.json({ ok: true });
  }).catch(err => res.status(500).json({ error: 'hash failed', detail: (err as Error).message }));
});
