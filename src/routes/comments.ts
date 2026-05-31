// Comment thread, watcher, and inbox routes. Adding a comment auto-
// watches the target for the author and fans-out notifications to
// existing watchers.

import { Router } from 'express';
import { z } from 'zod';
import { addComment, deleteComment, getCommentById, listComments, watch, unwatch, watchersFor, inbox, markAllRead } from '../store/commentStore';
import { appendAudit } from '../store/auditStore';
import { getSession, requireSession } from '../auth/auth';
import { CommentTarget } from '../types/assessment';
import { notify } from '../store/commentStore';
import { requireAccess } from '../auth/tenant';

export const commentRouter = Router();

const targetEnum = z.enum(['ssp-control', 'residual-risk', 'threat', 'package', 'flow-threat']);

commentRouter.get('/', (req, res) => {
  const assessmentId = String(req.query.assessmentId ?? '');
  if (!assessmentId) { res.status(400).json({ error: 'assessmentId required' }); return; }
  if (!requireAccess(req, res, assessmentId)) return;
  const t = req.query.targetType ? { type: req.query.targetType as CommentTarget, id: String(req.query.targetId ?? '') } : undefined;
  res.json({ comments: listComments(assessmentId, t) });
});

const createSchema = z.object({
  assessmentId: z.string().uuid(),
  targetType: targetEnum,
  targetId: z.string().min(1).max(120),
  body: z.string().min(1).max(4000),
  replyToId: z.string().uuid().optional()
});

commentRouter.post('/', requireSession, (req, res) => {
  const parsed = createSchema.safeParse(req.body);
  if (!parsed.success) { res.status(400).json({ error: 'invalid comment', issues: parsed.error.format() }); return; }
  if (!requireAccess(req, res, parsed.data.assessmentId)) return;
  const s = getSession(req)!;
  const c = addComment({
    assessmentId: parsed.data.assessmentId,
    targetType: parsed.data.targetType,
    targetId: parsed.data.targetId,
    author: s.userId,
    authorDisplay: s.displayName,
    body: parsed.data.body,
    replyToId: parsed.data.replyToId
  });
  // Auto-watch this target for the author.
  watch({ userId: s.userId, assessmentId: c.assessmentId, targetType: c.targetType, targetId: c.targetId });
  // Notify existing watchers (excluding the author themselves).
  const ws = watchersFor(c.assessmentId, { type: c.targetType, id: c.targetId });
  for (const w of ws) {
    if (w.userId === s.userId) continue;
    notify({ userId: w.userId, kind: 'comment', assessmentId: c.assessmentId, message: `${s.displayName} commented on ${c.targetType} ${c.targetId}` });
  }
  appendAudit({ actor: s.userId, action: 'comment.create', target: c.id, details: { assessmentId: c.assessmentId, targetType: c.targetType, targetId: c.targetId } });
  res.status(201).json(c);
});

commentRouter.delete('/:id', requireSession, (req, res) => {
  const c = getCommentById(req.params.id);
  if (!c) { res.status(404).end(); return; }
  // requireAccess enforces tenant/team isolation on the assessment the
  // comment belongs to; the author check below is the per-record rule.
  if (!requireAccess(req, res, c.assessmentId)) return;
  const s = getSession(req)!;
  const isAdmin = s.roles.includes('admin');
  if (c.author !== s.userId && !isAdmin) {
    res.status(403).json({ error: 'forbidden' });
    return;
  }
  const ok = deleteComment(req.params.id);
  appendAudit({ actor: s.userId, action: 'comment.delete', target: req.params.id });
  res.status(ok ? 204 : 404).end();
});

// ---- Watchers ----
const watchSchema = z.object({
  assessmentId: z.string().uuid(),
  targetType: targetEnum.optional(),
  targetId: z.string().max(120).optional()
});
commentRouter.post('/watch', requireSession, (req, res) => {
  const parsed = watchSchema.safeParse(req.body);
  if (!parsed.success) { res.status(400).json({ error: 'invalid', issues: parsed.error.format() }); return; }
  watch({ userId: getSession(req)!.userId, ...parsed.data });
  res.status(204).end();
});
commentRouter.delete('/watch', requireSession, (req, res) => {
  const parsed = watchSchema.safeParse(req.body);
  if (!parsed.success) { res.status(400).json({ error: 'invalid', issues: parsed.error.format() }); return; }
  const ok = unwatch({ userId: getSession(req)!.userId, ...parsed.data });
  res.status(ok ? 204 : 404).end();
});

// ---- Inbox ----
commentRouter.get('/inbox', requireSession, (req, res) => {
  const unread = req.query.unread === 'true';
  res.json({ notifications: inbox(getSession(req)!.userId, unread) });
});
commentRouter.post('/inbox/read', requireSession, (req, res) => {
  const n = markAllRead(getSession(req)!.userId);
  res.json({ marked: n });
});
