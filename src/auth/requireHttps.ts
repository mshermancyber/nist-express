// HTTPS enforcement middleware. Always-on, no env escape hatch —
// matching the sechubdocker nginx posture (`return 301 https://...`
// unconditional for browser navigations) and the explicit operator
// policy "do not allow http anymore."
//
// Reverse proxies in front of the app (ALB, nginx, Cloudflare) MUST
// set X-Forwarded-Proto. Set TRUST_PROXY=1 so Express honours it.
// Loopback (127.0.0.1, ::1, localhost) still passes so the docker
// healthcheck and host-side admin curls keep working — the operator
// can reach the app over plain HTTP from the host itself but any
// off-box client gets redirected or refused.
//
// To prevent Host-header open-redirect attacks, the canonical
// hostname for the redirect target comes from the CANONICAL_HOST
// env var when set. If unset, we only redirect when the inbound
// Host matches the allow-list ALLOWED_HOSTS (comma-separated). With
// neither set, we refuse with 421 (Misdirected Request) on the
// suspicion that the redirect would be unsafe.

import { NextFunction, Request, Response } from 'express';

function isLocalhost(req: Request): boolean {
  const host = (req.hostname || '').toLowerCase();
  return host === 'localhost' || host === '127.0.0.1' || host === '::1' || host === '[::1]';
}

function allowList(): string[] {
  return (process.env.ALLOWED_HOSTS ?? '').split(',').map(s => s.trim().toLowerCase()).filter(Boolean);
}

function safeRedirectHost(req: Request): string | null {
  const canonical = (process.env.CANONICAL_HOST ?? '').trim();
  if (canonical) return canonical;
  const inbound = String(req.headers.host ?? '').toLowerCase().replace(/[\r\n]/g, '');
  if (!inbound) return null;
  // Strip everything but [a-z0-9.:-] to defeat header-smuggling that
  // would let an attacker break out of the URL via CR/LF or backslash.
  const cleaned = inbound.replace(/[^a-z0-9.:\-]/g, '');
  if (cleaned !== inbound) return null;
  const allowed = allowList();
  if (allowed.length === 0) return null;     // strict: no redirect without an allow-list
  if (!allowed.includes(cleaned.split(':')[0]!)) return null;
  return cleaned;
}

export function requireHttps(req: Request, res: Response, next: NextFunction): void {
  if (isLocalhost(req)) return next();
  const fwd = String(req.headers['x-forwarded-proto'] ?? '').toLowerCase();
  const isSecure = req.secure || fwd === 'https';
  if (isSecure) return next();
  if (req.method === 'GET' || req.method === 'HEAD') {
    const host = safeRedirectHost(req);
    if (!host) {
      res.status(421).json({ error: 'HTTPS required and no trusted host configured for redirect (set CANONICAL_HOST or ALLOWED_HOSTS)' });
      return;
    }
    res.redirect(301, `https://${host}${req.url}`);
    return;
  }
  res.status(400).json({ error: 'HTTPS required' });
}
