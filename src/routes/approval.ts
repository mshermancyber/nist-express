// Approval workflow routes. The owner requests sign-off from the four
// approver roles; each approver signs against the SHA-256 of the
// package they reviewed. The signature ties the decision to an
// immutable artifact — re-generation invalidates open approvals.

import { Router } from 'express';
import { z } from 'zod';
import {
  getAssessment, saveAssessment, getPackage
} from '../store/assessmentStore';
import { appendAudit } from '../store/auditStore';
import { ApprovalRequest, ApprovalSignature, ApproverRole } from '../types/assessment';
import { getSession, requireSession } from '../auth/auth';
import { requireAccess } from '../auth/tenant';
import { requireSudo } from '../auth/sudo';

export const approvalRouter = Router();

const approverRoles: ApproverRole[] = ['security', 'risk', 'architecture', 'compliance'];

const requestSchema = z.object({
  requiredRoles: z.array(z.enum(['security', 'risk', 'architecture', 'compliance'])).min(1).default(approverRoles)
});

approvalRouter.post('/:id/request', requireSession, (req, res) => {
  const s = getSession(req)!;
  const a = requireAccess(req, res, req.params.id);
  if (!a) return;
  const pkg = getPackage(req.params.id);
  if (!pkg) { res.status(409).json({ error: 'generate the package before requesting approval' }); return; }
  const parsed = requestSchema.safeParse(req.body ?? {});
  if (!parsed.success) { res.status(400).json({ error: 'invalid request', issues: parsed.error.format() }); return; }
  const request: ApprovalRequest = {
    requestedAt: new Date().toISOString(),
    requestedBy: s.username,
    requiredRoles: parsed.data.requiredRoles,
    approvals: [],
    status: 'open',
    packageHash: pkg.packageHash
  };
  a.approvalRequest = request;
  a.status = 'reviewed';
  a.updatedAt = new Date().toISOString();
  saveAssessment(a);
  appendAudit({ actor: s.userId, action: 'approval.request', target: a.id, details: { requiredRoles: request.requiredRoles, packageHash: pkg.packageHash } });
  res.status(201).json(request);
});

const signSchema = z.object({
  role: z.enum(['security', 'risk', 'architecture', 'compliance']),
  decision: z.enum(['approve', 'reject']),
  comment: z.string().max(2000).optional()
});

approvalRouter.post('/:id/sign', requireSession, requireSudo, (req, res) => {
  const s = getSession(req)!;
  const a = requireAccess(req, res, req.params.id);
  if (!a) return;
  if (!a.approvalRequest) { res.status(404).json({ error: 'no open approval request' }); return; }
  if (a.approvalRequest.status !== 'open') { res.status(409).json({ error: `request is ${a.approvalRequest.status}` }); return; }
  const pkg = getPackage(req.params.id);
  if (!pkg) { res.status(409).json({ error: 'package missing' }); return; }
  if (pkg.packageHash !== a.approvalRequest.packageHash) {
    res.status(409).json({ error: 'package was regenerated since request — re-issue the approval request' });
    return;
  }
  const parsed = signSchema.safeParse(req.body);
  if (!parsed.success) { res.status(400).json({ error: 'invalid signature', issues: parsed.error.format() }); return; }
  const approverRole = `approver-${parsed.data.role}` as const;
  if (!s.roles.includes(approverRole) && !s.roles.includes('admin')) {
    res.status(403).json({ error: `requires role ${approverRole}` });
    return;
  }
  const sig: ApprovalSignature = {
    role: parsed.data.role,
    userId: s.userId,
    displayName: s.displayName,
    decision: parsed.data.decision,
    comment: parsed.data.comment,
    signedAt: new Date().toISOString()
  };
  // Each role signs at most once per request.
  const existing = a.approvalRequest.approvals.findIndex(x => x.role === sig.role);
  if (existing >= 0) a.approvalRequest.approvals[existing] = sig;
  else a.approvalRequest.approvals.push(sig);

  // Update overall status.
  const rejected = a.approvalRequest.approvals.some(s => s.decision === 'reject');
  const approved = a.approvalRequest.requiredRoles.every(r =>
    a.approvalRequest!.approvals.find(s => s.role === r && s.decision === 'approve')
  );
  if (rejected) { a.approvalRequest.status = 'rejected'; a.status = 'rejected'; }
  else if (approved) { a.approvalRequest.status = 'approved'; a.status = 'approved'; }
  a.updatedAt = new Date().toISOString();
  saveAssessment(a);
  appendAudit({ actor: s.userId, action: `approval.${parsed.data.decision}`, target: a.id, details: { role: sig.role, status: a.approvalRequest.status } });
  res.json(a.approvalRequest);
});

approvalRouter.post('/:id/cancel', requireSession, (req, res) => {
  const s = getSession(req)!;
  const a = requireAccess(req, res, req.params.id);
  if (!a) return;
  if (!a.approvalRequest) { res.status(404).json({ error: 'no approval request' }); return; }
  a.approvalRequest.status = 'cancelled';
  a.status = 'generated';
  a.updatedAt = new Date().toISOString();
  saveAssessment(a);
  appendAudit({ actor: s.userId, action: 'approval.cancel', target: a.id });
  res.json(a.approvalRequest);
});

approvalRouter.get('/:id', (req, res) => {
  const a = requireAccess(req, res, req.params.id);
  if (!a) return;
  res.json({ approvalRequest: a.approvalRequest ?? null });
});
