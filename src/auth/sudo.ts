// "sudo mode" — short-lived re-authentication required for sensitive
// operations (approve, delete, rotate-secret, disable user, create
// API key). The user re-confirms their password (and TOTP if
// enabled); a HMAC-signed cookie marks them as sudo-elevated for the
// next N minutes. Routes call requireSudo(req, res) to gate.

import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import bcrypt from 'bcryptjs';
import { NextFunction, Request, Response, Router } from 'express';
import { z } from 'zod';
import { getSession, requireSession } from './auth';
import { getUserByUsername, getUserById } from '../store/userStore';
import { getUserSecurity } from '../store/userSecurityStore';
import { verifyTotpAndConsume } from './totp';
import { appendAudit } from '../store/auditStore';

const COOKIE = 'arb_sudo';
const TTL_SECONDS = 5 * 60;

// Dedicated HMAC key for sudo cookies — independent of the session
// secret so rotating the session secret does NOT silently invalidate
// active sudo elevations. Generated lazily on first use, 0600 mode.
let cachedSudoKey: Buffer | null = null;
function secret(): Buffer {
  if (cachedSudoKey) return cachedSudoKey;
  const dir = path.join(__dirname, '..', '..', '.data');
  const file = path.join(dir, 'sudo-secret');
  try {
    // Exclusive-create to avoid two startups racing on first generation.
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(file, crypto.randomBytes(32), { mode: 0o600, flag: 'wx' });
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code !== 'EEXIST') throw e;
  }
  const buf = fs.readFileSync(file);
  if (buf.length !== 32) {
    // File is corrupt or short — refuse to issue sudo tokens rather than
    // signing with an all-zeros or partial key.
    throw new Error('sudo: secret key file is malformed (expected 32 bytes)');
  }
  cachedSudoKey = buf;
  return cachedSudoKey;
}

function signSudo(userId: string): string {
  const payload = Buffer.from(JSON.stringify({ sub: userId, exp: Math.floor(Date.now() / 1000) + TTL_SECONDS })).toString('base64url');
  const sig = crypto.createHmac('sha256', secret()).update(payload).digest('base64url');
  return payload + '.' + sig;
}

function verifySudo(token: string, userId: string): boolean {
  const dot = token.indexOf('.');
  if (dot < 0) return false;
  const body = token.slice(0, dot);
  const sig = token.slice(dot + 1);
  const expected = crypto.createHmac('sha256', secret()).update(body).digest('base64url');
  if (sig.length !== expected.length) return false;
  if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) return false;
  try {
    const payload = JSON.parse(Buffer.from(body, 'base64url').toString('utf-8')) as { sub?: unknown; exp?: unknown };
    // Defence in depth — verify the fields we depend on are present
    // and of the expected type, even though HMAC already vouches for
    // the bytes.
    if (typeof payload.sub !== 'string' || payload.sub !== userId) return false;
    if (typeof payload.exp !== 'number' || !Number.isFinite(payload.exp)) return false;
    if (payload.exp < Math.floor(Date.now() / 1000)) return false;
    return true;
  } catch { return false; }
}

export function requireSudo(req: Request, res: Response, next: NextFunction): void {
  const s = getSession(req);
  if (!s) { res.status(401).json({ error: 'auth required' }); return; }
  const cookie = (req.headers.cookie || '').split(';').map(x => x.trim()).find(x => x.startsWith(COOKIE + '='));
  if (!cookie) { res.status(403).json({ error: 'sudo required', sudo: false }); return; }
  const token = cookie.split('=', 2)[1] ?? '';
  if (!verifySudo(token, s.userId)) { res.status(403).json({ error: 'sudo expired', sudo: false }); return; }
  next();
}

export const sudoRouter = Router();

const sudoSchema = z.object({
  password: z.string().min(1).max(200),
  totp: z.string().regex(/^\d{6}$/).optional()
});

sudoRouter.post('/sudo', requireSession, async (req, res) => {
  const s = getSession(req)!;
  const user = getUserById(s.userId);
  if (!user) { res.status(401).json({ error: 'unknown user' }); return; }
  const parsed = sudoSchema.safeParse(req.body);
  if (!parsed.success) { res.status(400).json({ error: 'invalid' }); return; }
  if (!await bcrypt.compare(parsed.data.password, user.passwordHash)) {
    appendAudit({ actor: user.id, action: 'auth.sudo.fail', target: user.id });
    res.status(401).json({ error: 'invalid credentials' });
    return;
  }
  const sec = getUserSecurity(user.id);
  if (sec.totpEnabled) {
    if (!parsed.data.totp || !verifyTotpAndConsume(user.id, sec.totpSecret!, parsed.data.totp)) {
      appendAudit({ actor: user.id, action: 'auth.sudo.totp.fail', target: user.id });
      res.status(401).json({ error: 'TOTP required' });
      return;
    }
  }
  const token = signSudo(user.id);
  // When REQUIRE_HTTPS=1 the operator is asserting that all client
  // traffic terminates TLS — mirror that on the cookie's Secure flag.
  res.cookie(COOKIE, token, { httpOnly: true, sameSite: 'strict', secure: process.env.REQUIRE_HTTPS === '1', maxAge: TTL_SECONDS * 1000, path: '/' });
  appendAudit({ actor: user.id, action: 'auth.sudo.ok', target: user.id });
  res.json({ sudo: true, ttlSeconds: TTL_SECONDS });
});

sudoRouter.post('/sudo/clear', requireSession, (req, res) => {
  res.clearCookie(COOKIE, { path: '/' });
  appendAudit({ actor: getSession(req)!.userId, action: 'auth.sudo.clear', target: getSession(req)!.userId });
  res.status(204).end();
});
