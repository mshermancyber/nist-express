// Residual-risk-level actions: create external tickets, accept/release
// risks, list ticket state, and surface accepted-risk register.

import { Router } from 'express';
import { z } from 'zod';
import { getAssessment, getPackage, saveAssessment } from '../store/assessmentStore';
import { getTicket, saveTicket, listTickets } from '../store/ticketStore';
import { createTicket } from '../engine/ticketing';
import { appendAudit } from '../store/auditStore';
import { getSession, requireSession, requireRole } from '../auth/auth';
import { requireAccess } from '../auth/tenant';
import { RiskAcceptance } from '../types/assessment';
import fs from 'fs';
import path from 'path';

const ACCEPT_FILE = path.join(__dirname, '..', '..', '.data', 'acceptances.json');
function loadAcceptances(): RiskAcceptance[] {
  if (!fs.existsSync(ACCEPT_FILE)) return [];
  try { return JSON.parse(fs.readFileSync(ACCEPT_FILE, 'utf-8')) as RiskAcceptance[]; } catch { return []; }
}
function persistAcceptances(list: RiskAcceptance[]): void {
  fs.writeFileSync(ACCEPT_FILE, JSON.stringify(list, null, 2));
}

export const riskRouter = Router();

riskRouter.post('/:assessmentId/:riskId/ticket', requireSession, async (req, res) => {
  const a = requireAccess(req, res, req.params.assessmentId);
  if (!a) return;
  const p = getPackage(req.params.assessmentId);
  if (!p) { res.status(404).json({ error: 'not found' }); return; }
  const risk = p.residualRisks.find(r => r.id === req.params.riskId);
  if (!risk) { res.status(404).json({ error: 'risk not found' }); return; }
  const parsed = z.object({ system: z.enum(['jira', 'servicenow']) }).safeParse(req.body);
  if (!parsed.success) { res.status(400).json({ error: 'invalid', issues: parsed.error.format() }); return; }
  try {
    const ticket = await createTicket(parsed.data.system, risk, a.business.applicationName);
    saveTicket(ticket);
    appendAudit({ actor: getSession(req)!.userId, action: 'ticket.create', target: risk.id, details: { system: ticket.system, externalId: ticket.externalId } });
    res.status(201).json(ticket);
  } catch (err) {
    res.status(500).json({ error: 'ticket creation failed', detail: (err as Error).message });
  }
});

// list-all ticket inventory is oversight-level; admins only.
riskRouter.get('/tickets', requireRole('admin'), (_req, res) => {
  res.json({ tickets: listTickets() });
});

riskRouter.get('/:assessmentId/:riskId/ticket', requireSession, (req, res) => {
  const a = requireAccess(req, res, req.params.assessmentId);
  if (!a) return;
  const t = getTicket(req.params.riskId);
  if (!t) { res.status(404).json({ error: 'no ticket' }); return; }
  res.json(t);
});

// Risk acceptance (M33)
const acceptSchema = z.object({
  expiresAt: z.string().refine(s => !isNaN(Date.parse(s)), 'must be ISO date'),
  rationale: z.string().min(1).max(2000)
});
riskRouter.post('/:assessmentId/:riskId/accept', requireSession, (req, res) => {
  const a = requireAccess(req, res, req.params.assessmentId);
  if (!a) return;
  const p = getPackage(req.params.assessmentId);
  if (!p) { res.status(404).json({ error: 'not found' }); return; }
  const risk = p.residualRisks.find(r => r.id === req.params.riskId);
  if (!risk) { res.status(404).json({ error: 'risk not found' }); return; }
  const parsed = acceptSchema.safeParse(req.body);
  if (!parsed.success) { res.status(400).json({ error: 'invalid', issues: parsed.error.format() }); return; }
  const all = loadAcceptances();
  const existing = all.findIndex(x => x.riskId === risk.id);
  const acc: RiskAcceptance = {
    riskId: risk.id,
    acceptedBy: getSession(req)!.userId,
    acceptedAt: new Date().toISOString(),
    expiresAt: parsed.data.expiresAt,
    rationale: parsed.data.rationale,
    status: 'active'
  };
  if (existing >= 0) all[existing] = acc; else all.push(acc);
  persistAcceptances(all);
  appendAudit({ actor: acc.acceptedBy, action: 'risk.accept', target: risk.id, details: { expiresAt: acc.expiresAt } });
  res.status(201).json(acc);
});

riskRouter.post('/:assessmentId/:riskId/release', requireSession, (req, res) => {
  const a = requireAccess(req, res, req.params.assessmentId);
  if (!a) return;
  const all = loadAcceptances();
  const i = all.findIndex(x => x.riskId === req.params.riskId);
  if (i < 0) { res.status(404).json({ error: 'not accepted' }); return; }
  all[i].status = 'released';
  persistAcceptances(all);
  appendAudit({ actor: getSession(req)!.userId, action: 'risk.release', target: req.params.riskId });
  res.json(all[i]);
});

// Global acceptance register: admins-only oversight surface.
riskRouter.get('/acceptances', requireRole('admin'), (_req, res) => {
  const all = loadAcceptances();
  const now = Date.now();
  for (const a of all) {
    if (a.status === 'active' && Date.parse(a.expiresAt) < now) a.status = 'expired';
  }
  res.json({ acceptances: all });
});
