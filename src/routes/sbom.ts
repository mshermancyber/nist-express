// SBOM ingestion route. Accepts a CycloneDX or SPDX JSON file.
// Persisted alongside the assessment so the next regeneration includes
// the SBOM analysis in the package.

import { Router } from 'express';
import multer from 'multer';
import fs from 'fs';
import path from 'path';
import { getAssessment, saveAssessment } from '../store/assessmentStore';
import { appendAudit } from '../store/auditStore';
import { analyzeSbom, detectSbomFormat } from '../engine/sbom';
import { buildArchitecture } from '../engine/architecture';
import { categorize } from '../engine/categorization';
import { getSession, requireRole } from '../auth/auth';
import { requireAccess } from '../auth/tenant';

export const sbomRouter = Router();
import { uploadLimits, uploadDeadline, uploadHandler, SIZE_SBOM_BYTES } from '../auth/uploadLimits';
const upload = uploadHandler(uploadLimits(SIZE_SBOM_BYTES));
const SBOM_DIR = path.join(__dirname, '..', '..', '.data', 'sbom');
if (!fs.existsSync(SBOM_DIR)) fs.mkdirSync(SBOM_DIR, { recursive: true });

export function saveSbomContent(id: string, body: string): void {
  fs.writeFileSync(path.join(SBOM_DIR, `${id}.json`), body);
}
export function loadSbomContent(id: string): string | null {
  const p = path.join(SBOM_DIR, `${id}.json`);
  if (!fs.existsSync(p)) return null;
  return fs.readFileSync(p, 'utf-8');
}
export function deleteSbomContent(id: string): void {
  const p = path.join(SBOM_DIR, `${id}.json`);
  if (fs.existsSync(p)) fs.unlinkSync(p);
}

sbomRouter.post('/:id/upload', requireRole('admin', 'architect', 'analyst'), uploadDeadline, upload, (req, res) => {
  const a = requireAccess(req, res, req.params.id);
  if (!a) return;
  const file = (req as unknown as { file?: { originalname: string; buffer: Buffer } }).file;
  if (!file) { res.status(400).json({ error: 'file field required' }); return; }
  const text = file.buffer.toString('utf-8');
  const format = detectSbomFormat(text);
  if (format === 'unknown') { res.status(400).json({ error: 'unrecognised SBOM format (expected CycloneDX or SPDX JSON)' }); return; }
  saveSbomContent(a.id, text);
  const cat = categorize(a);
  const arch = buildArchitecture(a, cat);
  const analysis = analyzeSbom(text, arch);
  a.updatedAt = new Date().toISOString();
  saveAssessment(a);
  appendAudit({ actor: getSession(req)?.userId ?? 'anonymous', action: 'sbom.upload', target: a.id, details: { format, components: analysis.componentCount, vulns: analysis.vulnerabilities.length, kev: analysis.kevHits.length } });
  res.status(201).json({ format, summary: analysis.summary, components: analysis.componentCount, vulnerabilities: analysis.vulnerabilities.length, kev: analysis.kevHits.length });
});

sbomRouter.delete('/:id', requireRole('admin', 'architect', 'analyst'), (req, res) => {
  const a = requireAccess(req, res, req.params.id);
  if (!a) return;
  deleteSbomContent(a.id);
  appendAudit({ actor: getSession(req)?.userId ?? 'anonymous', action: 'sbom.delete', target: a.id });
  res.status(204).end();
});
