import { Router } from 'express';
import { z } from 'zod';
import { randomUUID as uuid } from 'crypto';
import crypto from 'crypto';
import { listWebhooks, saveWebhook, deleteWebhook, getWebhook } from '../store/webhookStore';
import { requireRole, getSession } from '../auth/auth';
import { appendAudit } from '../store/auditStore';
import { deliverWebhook } from '../engine/webhooks';

export const webhookRouter = Router();

const eventEnum = z.enum(['package.generated', 'approval.requested', 'approval.signed', 'residual.critical', 'comment.created', 'risk.expiring']);

const createSchema = z.object({
  name: z.string().min(1).max(120),
  url: z.string().url(),
  events: z.array(eventEnum).min(1),
  adapter: z.enum(['generic', 'slack', 'teams']).default('generic'),
  enabled: z.boolean().default(true)
});

webhookRouter.get('/', requireRole('admin'), (_req, res) => {
  res.json({ webhooks: listWebhooks().map(w => ({ ...w, secret: w.secret.slice(0, 4) + '…' })) });
});

webhookRouter.post('/', requireRole('admin'), (req, res) => {
  const parsed = createSchema.safeParse(req.body);
  if (!parsed.success) { res.status(400).json({ error: 'invalid', issues: parsed.error.format() }); return; }
  const w = {
    id: uuid(),
    secret: crypto.randomBytes(24).toString('hex'),
    createdBy: getSession(req)!.userId,
    createdAt: new Date().toISOString(),
    ...parsed.data
  };
  saveWebhook(w);
  appendAudit({ actor: w.createdBy, action: 'webhook.create', target: w.id, details: { name: w.name, events: w.events } });
  res.status(201).json(w);
});

webhookRouter.delete('/:id', requireRole('admin'), (req, res) => {
  const ok = deleteWebhook(req.params.id);
  appendAudit({ actor: getSession(req)!.userId, action: 'webhook.delete', target: req.params.id });
  res.status(ok ? 204 : 404).end();
});

webhookRouter.post('/:id/test', requireRole('admin'), async (req, res) => {
  const w = getWebhook(req.params.id);
  if (!w) { res.status(404).json({ error: 'not found' }); return; }
  await deliverWebhook(w, 'package.generated', { test: true, ts: new Date().toISOString() });
  res.json({ ok: true });
});
