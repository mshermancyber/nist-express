import { Router } from 'express';
import multer from 'multer';
import fs from 'fs';
import path from 'path';
import { getAssessment, saveAssessment } from '../store/assessmentStore';
import { appendAudit } from '../store/auditStore';
import { detectCloudFormat, reconcileCloud } from '../engine/cloudReconcile';
import { buildArchitecture } from '../engine/architecture';
import { categorize } from '../engine/categorization';
import { getSession, requireRole } from '../auth/auth';
import { requireAccess } from '../auth/tenant';

export const cloudRouter = Router();
import { uploadLimits, uploadDeadline, uploadHandler, SIZE_CLOUD_BYTES } from '../auth/uploadLimits';
const upload = uploadHandler(uploadLimits(SIZE_CLOUD_BYTES));
const DIR = path.join(__dirname, '..', '..', '.data', 'cloud');
if (!fs.existsSync(DIR)) fs.mkdirSync(DIR, { recursive: true });

export function saveCloudSnapshot(id: string, body: string): void { fs.writeFileSync(path.join(DIR, `${id}.json`), body); }
export function loadCloudSnapshot(id: string): string | null { const p = path.join(DIR, `${id}.json`); return fs.existsSync(p) ? fs.readFileSync(p, 'utf-8') : null; }
export function deleteCloudSnapshot(id: string): void { const p = path.join(DIR, `${id}.json`); if (fs.existsSync(p)) fs.unlinkSync(p); }

cloudRouter.post('/:id/upload', requireRole('admin', 'architect', 'analyst'), uploadDeadline, upload, (req, res) => {
  const a = requireAccess(req, res, req.params.id);
  if (!a) return;
  const file = (req as unknown as { file?: { originalname: string; buffer: Buffer } }).file;
  if (!file) { res.status(400).json({ error: 'file field required' }); return; }
  const text = file.buffer.toString('utf-8');
  const fmt = detectCloudFormat(text);
  if (fmt === 'unknown') { res.status(400).json({ error: 'unrecognised cloud snapshot format' }); return; }
  saveCloudSnapshot(a.id, text);
  const cat = categorize(a);
  const arch = buildArchitecture(a, cat);
  const report = reconcileCloud(text, arch);
  a.updatedAt = new Date().toISOString();
  saveAssessment(a);
  appendAudit({ actor: getSession(req)?.userId ?? 'anonymous', action: 'cloud.upload', target: a.id, details: { source: report.source, observed: report.observedResources.length, matched: report.matched.length, findings: report.findings.length } });
  res.status(201).json({ source: report.source, summary: report.summary });
});

cloudRouter.delete('/:id', requireRole('admin', 'architect', 'analyst'), (req, res) => {
  deleteCloudSnapshot(req.params.id);
  appendAudit({ actor: getSession(req)?.userId ?? 'anonymous', action: 'cloud.delete', target: req.params.id });
  res.status(204).end();
});
