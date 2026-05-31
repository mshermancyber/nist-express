// Shared tenant-resolution helper used by every assessment-scoped
// route to enforce row-level visibility. Pairs with
// canAccessAssessment() in the store. Routes call requireAccess(req,
// assessmentId) which loads the assessment, applies the rule, and
// either returns the assessment or sends a 403.

import { Request, Response } from 'express';
import { getAssessment, canAccessAssessment } from '../store/assessmentStore';
import { getSession } from './auth';
import { getUserById } from '../store/userStore';
import { Assessment } from '../types/assessment';

export interface Tenancy {
  userId: string;
  roles: string[];
  team?: string;
}

export function tenancyFor(req: Request): Tenancy | undefined {
  const s = getSession(req);
  if (!s) return undefined;
  const user = getUserById(s.userId);
  return { userId: s.userId, roles: s.roles, team: user?.team };
}

export function requireAccess(req: Request, res: Response, assessmentId: string): Assessment | null {
  const a = getAssessment(assessmentId);
  if (!a) { res.status(404).json({ error: 'not found' }); return null; }
  const t = tenancyFor(req);
  if (!canAccessAssessment(a, t)) { res.status(403).json({ error: 'forbidden' }); return null; }
  return a;
}

export function isAdmin(req: Request): boolean {
  const t = tenancyFor(req);
  return !!t && t.roles.includes('admin');
}
