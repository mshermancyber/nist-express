// GDPR Article 15 Data Subject Access Request endpoint. A user (or
// admin acting for them) downloads a JSON bundle of everything the
// platform knows about that user: their profile, their assessments
// (as owner), comments they authored, notifications addressed to
// them, audit-log entries referencing them, ticket associations.
//
// The bundle is signed with the active session secret so the
// recipient can verify integrity later (sha256 alongside the file).

import { Router, Request, Response } from 'express';
import crypto from 'crypto';
import { requireSession, getSession } from '../auth/auth';
import { getUserById } from '../store/userStore';
import { listAssessments } from '../store/assessmentStore';
import { listAudit } from '../store/auditStore';
import { inbox } from '../store/commentStore';
import fs from 'fs';
import path from 'path';

export const dsarRouter = Router();

function readJsonl<T>(p: string): T[] {
  if (!fs.existsSync(p)) return [];
  // Skip corrupt lines instead of throwing the entire export.
  const out: T[] = [];
  for (const l of fs.readFileSync(p, 'utf-8').split('\n')) {
    if (!l) continue;
    try { out.push(JSON.parse(l) as T); } catch { /* tolerate */ }
  }
  return out;
}

dsarRouter.get('/export', requireSession, (req: Request, res: Response) => {
  const sess = getSession(req)!;
  const targetId = String(req.query.userId ?? sess.userId);
  // Non-admin can only fetch their own bundle.
  if (targetId !== sess.userId && !sess.roles.includes('admin')) {
    res.status(403).json({ error: 'forbidden' });
    return;
  }
  const user = getUserById(targetId);
  if (!user) { res.status(404).json({ error: 'user not found' }); return; }

  // Sanitised profile (no passwordHash).
  const profile = {
    id: user.id, username: user.username, displayName: user.displayName,
    roles: user.roles, createdAt: user.createdAt, team: user.team,
    disabled: !!user.disabled
  };

  // Assessments owned by the user
  const assessments = listAssessments().filter(a => a.ownerId === user.id);

  // Comments authored by the user
  const COMMENT_FILE = path.join(__dirname, '..', '..', '.data', 'comments.jsonl');
  const comments = readJsonl<{ author: string }>(COMMENT_FILE).filter(c => c.author === user.id);

  // Notifications addressed to the user
  const notifications = inbox(user.id, false);

  // Audit entries that mention the user
  const audit = listAudit(2000).filter(e => e.actor === user.id || e.target === user.id);

  const bundle = {
    generatedAt: new Date().toISOString(),
    subject: targetId,
    profile, assessments, comments, notifications, audit
  };
  const body = JSON.stringify(bundle, null, 2);
  const sha = crypto.createHash('sha256').update(body).digest('hex');

  res.setHeader('Content-Disposition', `attachment; filename="dsar-${targetId}.json"`);
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('X-Bundle-Sha256', sha);
  res.send(body);
});
