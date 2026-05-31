import type { Request, Response, NextFunction } from 'express';
import path from 'path';

// Static-page gate: HTML page requests are redirected to /login.html
// unless the requester has a *real* logged-in session. Open-mode
// (no users provisioned) does NOT count as logged-in for this gate —
// it would otherwise let anyone walk straight into /index.html and
// bypass the bootstrap-admin registration flow on the login page.
//
// API and SCIM routes are not gated here; they enforce their own auth
// and return JSON. Static assets (css/js/images/fonts) pass so that
// /login.html itself can render. Health/metrics endpoints pass so that
// orchestrators can probe the container while it's locked.

const PASSTHROUGH = new Set([
  '/login.html',
  '/healthz',
  '/livez',
  '/readyz',
  '/metrics'
]);

const ASSET_RE = /\.(css|js|mjs|map|jpg|jpeg|png|gif|svg|ico|webp|woff2?|ttf|otf|json|txt)$/i;

function isHtmlNavigation(p: string, accept: string): boolean {
  if (p === '/' || p.endsWith('.html')) return true;
  // Bare path with no extension and a browser Accept header — treat as HTML nav.
  return !p.includes('.') && accept.includes('text/html');
}

type WithSession = Request & { session?: { userId: string } };

// Normalise the path so trailing slashes (`/index.html/`), backtracks
// (`/foo/../index.html`), null bytes, and case variations all resolve
// to the same shape the gate evaluates. Defence against requesters
// trying to slip past `PASSTHROUGH` / `ASSET_RE` by appending bytes
// that Express's static handler will strip later.
function canonicalPath(raw: string): string {
  // Strip null bytes outright — POSIX paths cannot contain them and
  // any presence is an injection attempt.
  const noNul = raw.replace(/\x00/g, '');
  // path.posix.normalize collapses `..` and `//` segments.
  let p = path.posix.normalize(decodeURIComponent(noNul.split('?')[0]!.split('#')[0]!));
  // Strip a trailing slash (except for the literal root) so
  // `/login.html/` is treated as `/login.html`.
  if (p.length > 1 && p.endsWith('/')) p = p.slice(0, -1);
  return p.toLowerCase();
}

export function requirePageAuth(req: Request, res: Response, next: NextFunction): void {
  const p = canonicalPath(req.path);
  if (p.startsWith('/api/') || p.startsWith('/scim/')) return next();
  if (PASSTHROUGH.has(p)) return next();
  if (ASSET_RE.test(p)) return next();
  if (!isHtmlNavigation(p, req.headers.accept || '')) return next();

  const sess = (req as WithSession).session;
  const realLogin = !!sess && sess.userId !== 'open-mode';
  if (realLogin) return next();

  res.redirect(302, '/login.html');
}
