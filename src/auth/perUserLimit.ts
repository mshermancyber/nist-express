// Per-user sliding-window rate limiter. Per-IP limiting is already
// applied globally; this adds a second layer keyed to the authenticated
// user (or "anonymous" fallback). Default: 600 requests/min/user.

import { NextFunction, Request, Response } from 'express';
import { getSession } from './auth';

const WINDOW_MS = 60_000;
const LIMIT = Number(process.env.PER_USER_RATE_LIMIT ?? 600);
const buckets = new Map<string, number[]>();

export function perUserLimiter(req: Request, res: Response, next: NextFunction) {
  const s = getSession(req);
  const key = s?.userId ?? 'anonymous:' + (req.ip || 'unknown');
  const now = Date.now();
  const arr = (buckets.get(key) ?? []).filter(t => t > now - WINDOW_MS);
  if (arr.length >= LIMIT) {
    // Don't bother evicting here — we're about to record a fresh hit
    // below anyway. (The 429 path doesn't fall through to push.)
    res.status(429).json({ error: 'per-user rate limit exceeded' });
    return;
  }
  arr.push(now);
  buckets.set(key, arr);
  // Bounded-cardinality housekeeping. Without this, the Map
  // accumulates one entry per unique user+anonymous-IP ever seen;
  // unique anonymous IPs from scrapers can run that into the millions.
  // Once we know we're updating, do a cheap probabilistic sweep that
  // evicts entries whose entire window has cleared.
  if (Math.random() < 0.01) {
    for (const [k, v] of buckets) {
      const fresh = v.filter(t => t > now - WINDOW_MS);
      if (fresh.length === 0) buckets.delete(k);
      else if (fresh.length !== v.length) buckets.set(k, fresh);
    }
  }
  next();
}
