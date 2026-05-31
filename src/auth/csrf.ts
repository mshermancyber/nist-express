// Double-submit CSRF protection. A random per-session token is written
// to a non-httponly cookie when the client calls /api/csrf. State-
// changing requests must echo the cookie value in X-CSRF-Token. API-
// key (Bearer) requests are exempt because they don't carry browser-
// managed cookies.
//
// /api/auth/login is always exempt (no cookies yet). /api/auth/users is
// exempt ONLY in open mode (first-admin bootstrap). After bootstrap
// every state-changing request — including subsequent user provisioning
// — must present a CSRF token.

import { NextFunction, Request, Response, Router } from 'express';
import crypto from 'crypto';
import { isOpenMode } from '../store/userStore';

const COOKIE = 'arb_csrf';
const HEADER = 'x-csrf-token';

function readCsrfCookie(req: Request): string | undefined {
  const c = (req.headers.cookie || '').split(';').map(s => s.trim()).find(s => s.startsWith(COOKIE + '='));
  return c?.split('=', 2)[1];
}

function timingSafeStrEq(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
}

export function csrfMiddleware(req: Request, res: Response, next: NextFunction) {
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return next();
  if ((req.headers.authorization || '').toLowerCase().startsWith('bearer ')) return next();
  if (req.path === '/healthz' || req.path === '/metrics') return next();
  if (req.path === '/api/auth/login') return next();
  if (req.path === '/api/auth/users' && isOpenMode()) return next();
  const cookie = readCsrfCookie(req);
  const header = req.headers[HEADER] as string | undefined;
  if (!cookie || !header || cookie.length < 16 || !timingSafeStrEq(cookie, header)) {
    res.status(403).json({ error: 'csrf token missing or mismatch' });
    return;
  }
  next();
}

export const csrfRouter = Router();
csrfRouter.get('/', (req, res) => {
  const token = crypto.randomBytes(24).toString('hex');
  // The app terminates TLS itself; off-loopback traffic is always
  // HTTPS. Mark Secure unless we can positively confirm the request
  // came from loopback (host-side admin curls in dev). A missing or
  // malformed Host header defaults to Secure — fail closed.
  const host = (req.headers.host || '').toLowerCase().split(':')[0];
  const isLocalhost = host === 'localhost' || host === '127.0.0.1' || host === '::1' || host === '[::1]';
  const flags = `Path=/; SameSite=Strict${isLocalhost ? '' : '; Secure'}`;
  res.setHeader('Set-Cookie', `${COOKIE}=${token}; ${flags}`);
  res.json({ token });
});
