// User-account self-service routes: TOTP enrolment, TOTP login challenge,
// API key issuance / revocation. Mounted under /api/auth/.

import { Router } from 'express';
import { z } from 'zod';
import crypto from 'crypto';
import { randomUUID as uuid } from 'crypto';
import { getSession, requireSession } from './auth';
import { getUserSecurity, saveUserSecurity } from '../store/userSecurityStore';
import { generateSecret, verifyTotp, otpauthUri } from './totp';
import { appendAudit } from '../store/auditStore';

export const userAuthRouter = Router();

userAuthRouter.post('/totp/enroll', requireSession, (req, res) => {
  const s = getSession(req)!;
  const sec = getUserSecurity(s.userId);
  if (sec.totpEnabled) { res.status(409).json({ error: 'TOTP already enabled' }); return; }
  sec.totpSecret = generateSecret();
  saveUserSecurity(sec);
  res.json({
    secret: sec.totpSecret,
    otpauth: otpauthUri(sec.totpSecret, s.username, 'nist-express')
  });
});

userAuthRouter.post('/totp/verify', requireSession, (req, res) => {
  const s = getSession(req)!;
  const sec = getUserSecurity(s.userId);
  if (!sec.totpSecret) { res.status(409).json({ error: 'enroll first' }); return; }
  const parsed = z.object({ code: z.string().regex(/^\d{6}$/) }).safeParse(req.body);
  if (!parsed.success) { res.status(400).json({ error: 'invalid code' }); return; }
  if (!verifyTotp(sec.totpSecret, parsed.data.code)) { res.status(400).json({ error: 'code mismatch' }); return; }
  sec.totpEnabled = true;
  saveUserSecurity(sec);
  appendAudit({ actor: s.userId, action: 'totp.enable', target: s.userId });
  res.json({ ok: true });
});

userAuthRouter.post('/totp/disable', requireSession, (req, res) => {
  const s = getSession(req)!;
  const sec = getUserSecurity(s.userId);
  sec.totpEnabled = false; delete sec.totpSecret;
  saveUserSecurity(sec);
  appendAudit({ actor: s.userId, action: 'totp.disable', target: s.userId });
  res.json({ ok: true });
});

userAuthRouter.post('/api-keys', requireSession, (req, res) => {
  // Reject control characters (NUL, BEL, CR, LF, etc.) and DEL so the
  // user-supplied API-key label can't carry an audit-log injection
  // payload or an ANSI escape sequence into terminal-rendered audits.
  // Printable Unicode (emoji, accented letters) is still permitted.
  const parsed = z.object({
    name: z.string().min(1).max(120).regex(/^[^\x00-\x1f\x7f]+$/, 'name must not contain control characters')
  }).safeParse(req.body);
  if (!parsed.success) { res.status(400).json({ error: 'invalid' }); return; }
  const s = getSession(req)!;
  const raw = 'arb_' + crypto.randomBytes(28).toString('hex');
  const hash = crypto.createHash('sha256').update(raw).digest('hex');
  const sec = getUserSecurity(s.userId);
  const key = { id: uuid(), name: parsed.data.name, hash, prefix: raw.slice(0, 8), createdAt: new Date().toISOString() };
  sec.apiKeys.push(key);
  saveUserSecurity(sec);
  appendAudit({ actor: s.userId, action: 'apikey.create', target: key.id, details: { name: key.name } });
  // Return the raw key ONCE. It cannot be retrieved later.
  res.status(201).json({ id: key.id, name: key.name, key: raw, prefix: key.prefix });
});

userAuthRouter.get('/api-keys', requireSession, (req, res) => {
  const sec = getUserSecurity(getSession(req)!.userId);
  res.json({ apiKeys: sec.apiKeys.map(k => ({ id: k.id, name: k.name, prefix: k.prefix, createdAt: k.createdAt, lastUsedAt: k.lastUsedAt, revokedAt: k.revokedAt })) });
});

userAuthRouter.delete('/api-keys/:id', requireSession, (req, res) => {
  const sec = getUserSecurity(getSession(req)!.userId);
  const k = sec.apiKeys.find(x => x.id === req.params.id);
  if (!k) { res.status(404).end(); return; }
  k.revokedAt = new Date().toISOString();
  saveUserSecurity(sec);
  appendAudit({ actor: getSession(req)!.userId, action: 'apikey.revoke', target: k.id });
  res.status(204).end();
});
