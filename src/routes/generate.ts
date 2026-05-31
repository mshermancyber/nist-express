import { Router } from 'express';
import { generatePackage } from '../engine/package';
import { getAssessment, savePackage, getPackage, listPackages, listPackageVersions, getPackageVersion, canAccessAssessment } from '../store/assessmentStore';
import { aiStatus } from '../engine/ai';
import { loadIacContent } from './iac';
import { loadSbomContent } from './sbom';
import { loadCloudSnapshot } from './cloud';
import { fanOut } from '../engine/webhooks';
import { appendAudit } from '../store/auditStore';
import { getSession } from '../auth/auth';
import { diffPackages } from '../engine/diff';
import { requireAccess, tenancyFor } from '../auth/tenant';

export const generateRouter = Router();

generateRouter.get('/ai-status', (_req, res) => {
  const s = aiStatus();
  res.json({
    configured: s.configured,
    baseUrl: s.baseUrl,
    model: s.model,
    note: s.configured ? 'AI augmentation will be applied to executive narrative and clarifications.' : s.reason
  });
});

// Portfolio packages list is filtered per tenant.
generateRouter.get('/', (req, res) => {
  const t = tenancyFor(req);
  const isAdmin = !!t && t.roles.includes('admin');
  const all = listPackages();
  if (isAdmin) { res.json({ packages: all }); return; }
  const visible = all.filter(p => {
    const a = getAssessment(p.assessmentId);
    return a && canAccessAssessment(a, t);
  });
  res.json({ packages: visible });
});

generateRouter.post('/:id', async (req, res) => {
  const a = requireAccess(req, res, req.params.id);
  if (!a) return;
  try {
    const previous = getPackage(a.id) ?? null;
    const iacContent = a.iacAttachment ? loadIacContent(a.id) : null;
    const sbomContent = loadSbomContent(a.id);
    const cloudSnapshot = loadCloudSnapshot(a.id);
    const pkg = await generatePackage(a, { previousPackage: previous, iacContent, sbomContent, cloudSnapshot });
    savePackage(pkg);
    a.status = 'generated';
    a.updatedAt = new Date().toISOString();
    appendAudit({ actor: getSession(req)?.userId ?? 'anonymous', action: 'package.generate', target: a.id, details: { version: pkg.packageVersion, hash: pkg.packageHash } });
    fanOut('package.generated', { assessmentId: a.id, version: pkg.packageVersion, posture: pkg.executiveSummary.riskPosture }).catch(() => undefined);
    if (pkg.residualRisks.some(r => r.residualRisk === 'Critical')) {
      fanOut('residual.critical', { assessmentId: a.id, count: pkg.residualRisks.filter(r => r.residualRisk === 'Critical').length }).catch(() => undefined);
    }
    res.json(pkg);
  } catch (err) {
    res.status(500).json({ error: 'generation failed', detail: (err as Error).message });
  }
});

generateRouter.get('/:id', (req, res) => {
  if (!requireAccess(req, res, req.params.id)) return;
  const pkg = getPackage(req.params.id);
  if (!pkg) { res.status(404).json({ error: 'package not found' }); return; }
  res.json(pkg);
});

generateRouter.get('/:id/versions', (req, res) => {
  if (!requireAccess(req, res, req.params.id)) return;
  res.json({ versions: listPackageVersions(req.params.id) });
});

function parsePositiveInt(raw: string | undefined): number | null {
  const n = Number(raw);
  return Number.isInteger(n) && n >= 1 ? n : null;
}

generateRouter.get('/:id/v/:version', (req, res) => {
  if (!requireAccess(req, res, req.params.id)) return;
  const v = parsePositiveInt(req.params.version);
  if (v === null) { res.status(400).json({ error: 'version must be a positive integer' }); return; }
  const pkg = getPackageVersion(req.params.id, v);
  if (!pkg) { res.status(404).json({ error: 'version not found' }); return; }
  res.json(pkg);
});

generateRouter.get('/:id/diff/:from/:to', (req, res) => {
  if (!requireAccess(req, res, req.params.id)) return;
  const from = parsePositiveInt(req.params.from);
  const to = parsePositiveInt(req.params.to);
  if (from === null || to === null) { res.status(400).json({ error: 'from/to must be positive integers' }); return; }
  const a = getPackageVersion(req.params.id, from);
  const b = getPackageVersion(req.params.id, to);
  if (!a || !b) { res.status(404).json({ error: 'version not found' }); return; }
  res.json(diffPackages(a, b));
});
