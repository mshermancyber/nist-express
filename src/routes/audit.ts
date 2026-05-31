// Audit log endpoint — read-only, restricted to admin or analyst roles.

import { Router } from 'express';
import { listAudit, verifyChain } from '../store/auditStore';
import { requireRole } from '../auth/auth';

export const auditRouter = Router();

auditRouter.get('/', requireRole('admin', 'analyst'), (req, res) => {
  // Clamp + reject non-finite (Number(undefined) is NaN). Math.max/min
  // with NaN propagate NaN through, which would slice(NaN) to [].
  const raw = Number(req.query.limit);
  const limit = Number.isFinite(raw) && raw >= 1 ? Math.min(2000, Math.floor(raw)) : 200;
  // Optional action filter. `?actions=a,b,c` returns only entries whose
  // `action` value is in the comma-separated list. Each token is
  // bounded and charset-constrained so a hostile query can't blow up
  // the comparison or smuggle exotic bytes through the audit surface.
  const raw_actions = String(req.query.actions ?? '').slice(0, 500);
  const requested = raw_actions ? raw_actions.split(',').map(s => s.trim()).filter(Boolean) : [];
  const wanted = requested.filter(s => /^[a-z][a-z0-9._-]{0,40}$/.test(s));
  // If the caller asked for a filter but ALL tokens were malformed,
  // reject with 400 rather than silently returning an empty list —
  // that just looks like "no events" to the operator.
  if (requested.length > 0 && wanted.length === 0) {
    res.status(400).json({ error: 'no valid action filters; expected lowercase tokens' });
    return;
  }
  // To respect the limit when filtering, oversample then filter, then
  // truncate. Audit volume is small (single-node, manual operations)
  // so the oversample factor of 10 is fine.
  const useFilter = wanted.length > 0;
  const fetchSize = useFilter ? Math.min(2000, limit * 10) : limit;
  let entries = listAudit(fetchSize);
  if (useFilter) {
    const wantedSet = new Set(wanted);
    entries = entries.filter(e => wantedSet.has(e.action)).slice(0, limit);
  }
  res.json({ entries });
});

auditRouter.get('/verify', requireRole('admin', 'analyst'), (_req, res) => {
  res.json(verifyChain());
});
