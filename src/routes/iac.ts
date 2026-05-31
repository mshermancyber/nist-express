// IaC ingestion route — accepts a Terraform plan JSON, CloudFormation
// template, or CDK synth JSON, parses it, and stores the reconciliation
// against the assessment.

import { Router } from 'express';
import multer from 'multer';
import { z } from 'zod';
import { getAssessment, saveAssessment } from '../store/assessmentStore';
import { appendAudit } from '../store/auditStore';
import { reconcileIac, detectFormat } from '../engine/iac';
import { buildArchitecture } from '../engine/architecture';
import { categorize } from '../engine/categorization';
import { getSession, requireRole } from '../auth/auth';
import { requireAccess } from '../auth/tenant';
import { IacAttachment } from '../types/assessment';

export const iacRouter = Router();

// 2 MB cap is generous for a plan/template but rejects accidental binaries.
import { uploadLimits, uploadDeadline, uploadHandler, SIZE_IAC_BYTES } from '../auth/uploadLimits';
const upload = uploadHandler(uploadLimits(SIZE_IAC_BYTES));

iacRouter.post('/:id/upload', requireRole('admin', 'architect', 'analyst'), uploadDeadline, upload, (req, res) => {
  const a = requireAccess(req, res, req.params.id);
  if (!a) return;
  const file = (req as unknown as { file?: { originalname: string; buffer: Buffer } }).file;
  if (!file) { res.status(400).json({ error: 'file field required' }); return; }
  const text = file.buffer.toString('utf-8');
  const format = detectFormat(text);
  if (format === 'unknown') { res.status(400).json({ error: 'unrecognised IaC format (expected Terraform plan JSON, CloudFormation, or CDK synth)' }); return; }

  // Build the expected architecture once so we can run a quick
  // reconcile and report counts to the caller. The full reconciliation
  // is regenerated as part of the next package generation.
  const cat = categorize(a);
  const arch = buildArchitecture(a, cat);
  const report = reconcileIac(text, arch);
  const session = getSession(req);
  const attachment: IacAttachment = {
    filename: file.originalname,
    format,
    uploadedAt: new Date().toISOString(),
    uploadedBy: session?.username,
    resourceCount: report.observedResources.length
  };
  a.iacAttachment = attachment;
  a.updatedAt = new Date().toISOString();
  // Persist the raw content alongside the assessment so a later
  // regeneration re-runs the reconciliation. We keep it on disk only.
  saveIacContent(a.id, text);
  saveAssessment(a);
  appendAudit({ actor: session?.userId ?? 'anonymous', action: 'iac.upload', target: a.id, details: { format, resources: report.observedResources.length } });
  res.status(201).json({ attachment, summary: report.summary, matched: report.matched.length, missing: report.missing.length, unexpected: report.unexpected.length });
});

iacRouter.delete('/:id', requireRole('admin', 'architect', 'analyst'), (req, res) => {
  const a = requireAccess(req, res, req.params.id);
  if (!a) return;
  delete a.iacAttachment;
  deleteIacContent(a.id);
  a.updatedAt = new Date().toISOString();
  saveAssessment(a);
  appendAudit({ actor: getSession(req)?.userId ?? 'anonymous', action: 'iac.delete', target: a.id });
  res.status(204).end();
});

// ---- Persistence helpers (kept in this file to localise the disk paths) ----
import fs from 'fs';
import path from 'path';

const IAC_DIR = path.join(__dirname, '..', '..', '.data', 'iac');
if (!fs.existsSync(IAC_DIR)) fs.mkdirSync(IAC_DIR, { recursive: true });

export function saveIacContent(assessmentId: string, content: string): void {
  fs.writeFileSync(path.join(IAC_DIR, `${assessmentId}.txt`), content);
}
export function loadIacContent(assessmentId: string): string | null {
  const p = path.join(IAC_DIR, `${assessmentId}.txt`);
  if (!fs.existsSync(p)) return null;
  return fs.readFileSync(p, 'utf-8');
}
export function deleteIacContent(assessmentId: string): void {
  const p = path.join(IAC_DIR, `${assessmentId}.txt`);
  if (fs.existsSync(p)) fs.unlinkSync(p);
}

// Schema sanity check (zod) for the path parameter
export const iacIdParam = z.string().uuid();
