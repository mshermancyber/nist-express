import { Router } from 'express';
import { z } from 'zod';
import { getPackage } from '../store/assessmentStore';
import { answerQuestion } from '../engine/chat';
import { appendAudit } from '../store/auditStore';
import { getSession, requireSession } from '../auth/auth';
import { requireAccess } from '../auth/tenant';

export const chatRouter = Router();

chatRouter.post('/:id', requireSession, async (req, res) => {
  if (!requireAccess(req, res, req.params.id)) return;
  const pkg = getPackage(req.params.id);
  if (!pkg) { res.status(404).json({ error: 'not found' }); return; }
  const parsed = z.object({ question: z.string().min(1).max(2000) }).safeParse(req.body);
  if (!parsed.success) { res.status(400).json({ error: 'invalid', issues: parsed.error.format() }); return; }
  const out = await answerQuestion(pkg, parsed.data.question);
  appendAudit({ actor: getSession(req)?.userId ?? 'anonymous', action: 'chat.ask', target: req.params.id, details: { source: out.source } });
  res.json(out);
});
