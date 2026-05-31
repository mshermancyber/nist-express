import { Router } from 'express';
import { listJobs, getJob } from '../jobs/queue';
import { requireSession } from '../auth/auth';

export const jobsRouter = Router();

jobsRouter.get('/', requireSession, (_req, res) => {
  res.json({ jobs: listJobs() });
});

jobsRouter.get('/:id', requireSession, (req, res) => {
  const j = getJob(req.params.id);
  if (!j) { res.status(404).json({ error: 'not found' }); return; }
  res.json(j);
});
