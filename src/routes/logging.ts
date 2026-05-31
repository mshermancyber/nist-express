// Introspection endpoint for the configured logging level. Helps
// operators verify a deployment without shell access. Read-only; the
// LOG_LEVEL env var is the authoritative source and is honoured at
// process-start time.

import { Router } from 'express';
import { levelInfo } from '../obs/logger';
import { requireRole } from '../auth/auth';

export const loggingRouter = Router();

loggingRouter.get('/', requireRole('admin', 'analyst'), (_req, res) => {
  res.json(levelInfo());
});
