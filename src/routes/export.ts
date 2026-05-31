// Export routes — JSON, Markdown, HTML, CSV (multiple flavors), OSCAL,
// and PDF. Every export goes through requireAccess() to enforce tenant
// isolation. NOTE: Express's path-to-regexp v0.1 treats dots inside
// `:param` as ordinary characters, so a route like `/:id.json` will
// match `xxx.oscal.json` with `:id="xxx.oscal"`. Register the more
// specific suffix routes BEFORE the bare `/:id.json` route.

import { Router } from 'express';
import { getPackage, getAssessment } from '../store/assessmentStore';
import { renderHtml } from '../export/html';
import { renderMarkdown } from '../export/markdown';
import { renderCsv, CsvKind } from '../export/csv';
import { renderPdf } from '../export/pdf';
import { requireAccess } from '../auth/tenant';

export const exportRouter = Router();

// --- Specific patterns first ---

exportRouter.get('/:id.oscal.json', (req, res) => {
  if (!requireAccess(req, res, req.params.id)) return;
  const pkg = getPackage(req.params.id);
  if (!pkg) { res.status(404).json({ error: 'not found' }); return; }
  res.setHeader('Content-Disposition', `attachment; filename="arb-${pkg.assessmentId}.oscal.json"`);
  res.setHeader('Content-Type', 'application/json');
  res.send(JSON.stringify({ 'system-security-plan': pkg.oscalSsp }, null, 2));
});

const CSV_KINDS: CsvKind[] = ['ssp', 'evidence', 'residual-risk', 'audit-events', 'stride', 'cost', 'compliance', 'diff', 'fair', 'sbom'];
exportRouter.get('/:id.:kind.csv', (req, res) => {
  if (!requireAccess(req, res, req.params.id)) return;
  const kind = req.params.kind as CsvKind;
  if (!CSV_KINDS.includes(kind)) { res.status(400).send(`unknown csv kind; expected one of ${CSV_KINDS.join(', ')}`); return; }
  const pkg = getPackage(req.params.id);
  if (!pkg) { res.status(404).send('not found'); return; }
  res.setHeader('Content-Disposition', `attachment; filename="arb-${pkg.assessmentId}.${kind}.csv"`);
  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.send(renderCsv(kind, pkg));
});

// --- Bare-suffix patterns ---

exportRouter.get('/:id.json', (req, res) => {
  if (!requireAccess(req, res, req.params.id)) return;
  const pkg = getPackage(req.params.id);
  if (!pkg) { res.status(404).json({ error: 'not found' }); return; }
  res.setHeader('Content-Disposition', `attachment; filename="arb-${pkg.assessmentId}.json"`);
  res.setHeader('Content-Type', 'application/json');
  res.send(JSON.stringify(pkg, null, 2));
});

exportRouter.get('/:id.md', (req, res) => {
  if (!requireAccess(req, res, req.params.id)) return;
  const pkg = getPackage(req.params.id);
  const a = getAssessment(req.params.id);
  if (!pkg || !a) { res.status(404).send('not found'); return; }
  res.setHeader('Content-Disposition', `attachment; filename="arb-${pkg.assessmentId}.md"`);
  res.setHeader('Content-Type', 'text/markdown; charset=utf-8');
  res.send(renderMarkdown(a, pkg));
});

exportRouter.get('/:id.html', (req, res) => {
  if (!requireAccess(req, res, req.params.id)) return;
  const pkg = getPackage(req.params.id);
  const a = getAssessment(req.params.id);
  if (!pkg || !a) { res.status(404).send('not found'); return; }
  res.setHeader('Content-Disposition', `attachment; filename="arb-${pkg.assessmentId}.html"`);
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.send(renderHtml(a, pkg));
});

exportRouter.get('/:id.pdf', (req, res) => {
  if (!requireAccess(req, res, req.params.id)) return;
  const pkg = getPackage(req.params.id);
  const a = getAssessment(req.params.id);
  if (!pkg || !a) { res.status(404).send('not found'); return; }
  res.setHeader('Content-Disposition', `attachment; filename="arb-${pkg.assessmentId}.pdf"`);
  res.setHeader('Content-Type', 'application/pdf');
  renderPdf(a, pkg, res);
});
