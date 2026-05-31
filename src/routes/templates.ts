import { Router } from 'express';
import { randomUUID as uuid } from 'crypto';
import { TEMPLATES, getTemplate } from '../data/templates';
import { saveAssessment } from '../store/assessmentStore';
import { appendAudit } from '../store/auditStore';
import { getSession } from '../auth/auth';
import { Assessment } from '../types/assessment';

export const templatesRouter = Router();

templatesRouter.get('/', (_req, res) => {
  res.json({ templates: TEMPLATES.map(t => ({ id: t.id, name: t.name, description: t.description })) });
});

templatesRouter.post('/:id/instantiate', (req, res) => {
  const t = getTemplate(req.params.id);
  if (!t) { res.status(404).json({ error: 'template not found' }); return; }
  const now = new Date().toISOString();
  const session = getSession(req);
  const a: Assessment = {
    id: uuid(),
    createdAt: now,
    updatedAt: now,
    status: 'draft',
    ownerId: session?.userId,
    ...t.body
  };
  saveAssessment(a);
  appendAudit({ actor: session?.userId ?? 'anonymous', action: 'template.instantiate', target: a.id, details: { template: t.id } });
  res.status(201).json(a);
});
