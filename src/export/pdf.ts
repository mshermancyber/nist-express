// PDF renderer for the ARB package. Uses pdfkit (vs. headless
// Chromium) so the install footprint stays small and the renderer is
// pure JS. Output is a single multi-section PDF with a title page,
// executive summary, categorization, architecture (text + DFD list),
// STRIDE / operational tables, SSP, recovery, residuals, and a
// signature block.

import PDFDocument from 'pdfkit';
import { Writable } from 'stream';
import { Assessment, ArbPackage } from '../types/assessment';

const COLORS = {
  ink: '#0f172a',
  accent: '#1e40af',
  muted: '#475569',
  warn: '#b45309',
  danger: '#b91c1c',
  ok: '#15803d',
  rule: '#cbd5e1'
};

function riskColor(r: string): string {
  switch (r) {
    case 'Critical': return COLORS.danger;
    case 'High':     return COLORS.danger;
    case 'Medium':   return COLORS.warn;
    case 'Low':      return COLORS.ok;
    default:         return COLORS.muted;
  }
}

function h1(doc: PDFKit.PDFDocument, text: string) {
  doc.moveDown(0.6).fillColor(COLORS.accent).fontSize(20).font('Helvetica-Bold').text(text);
  doc.fillColor(COLORS.ink).fontSize(11).font('Helvetica');
}

function h2(doc: PDFKit.PDFDocument, text: string) {
  doc.moveDown(0.8).fillColor(COLORS.accent).fontSize(14).font('Helvetica-Bold').text(text);
  doc.moveTo(doc.x, doc.y + 2).lineTo(doc.page.width - doc.page.margins.right, doc.y + 2).strokeColor(COLORS.rule).lineWidth(0.5).stroke();
  doc.moveDown(0.2);
  doc.fillColor(COLORS.ink).fontSize(10).font('Helvetica');
}

function kv(doc: PDFKit.PDFDocument, k: string, v: string) {
  doc.font('Helvetica-Bold').fillColor(COLORS.muted).text(k, { continued: true });
  doc.font('Helvetica').fillColor(COLORS.ink).text('  ' + v);
}

function bullets(doc: PDFKit.PDFDocument, items: string[]) {
  if (!items.length) {
    doc.fillColor(COLORS.muted).text('— none —'); doc.fillColor(COLORS.ink);
    return;
  }
  for (const it of items) doc.text('• ' + it, { indent: 10 });
}

function table(doc: PDFKit.PDFDocument, headers: string[], rows: string[][], widths?: number[]) {
  const startX = doc.x;
  const usable = doc.page.width - doc.page.margins.left - doc.page.margins.right;
  const colWidths = widths ?? headers.map(() => usable / headers.length);

  const drawRow = (cells: string[], opts: { bold?: boolean; fill?: string } = {}) => {
    if (doc.y > doc.page.height - doc.page.margins.bottom - 50) doc.addPage();
    const y = doc.y;
    let x = startX;
    let maxLines = 1;
    // Pre-measure for row height by drawing into a phantom column width.
    for (let i = 0; i < cells.length; i++) {
      const w = colWidths[i] - 4;
      const h = doc.heightOfString(cells[i] || '', { width: w });
      const lines = Math.max(1, Math.round(h / doc.currentLineHeight()));
      maxLines = Math.max(maxLines, lines);
    }
    const rowH = Math.max(16, maxLines * doc.currentLineHeight() + 4);
    if (opts.fill) {
      doc.save().rect(startX, y, colWidths.reduce((a, b) => a + b, 0), rowH).fillColor(opts.fill).fill().restore();
    }
    doc.font(opts.bold ? 'Helvetica-Bold' : 'Helvetica').fillColor(opts.bold ? COLORS.accent : COLORS.ink);
    x = startX;
    for (let i = 0; i < cells.length; i++) {
      doc.text(cells[i] || '', x + 2, y + 2, { width: colWidths[i] - 4 });
      x += colWidths[i];
    }
    doc.strokeColor(COLORS.rule).lineWidth(0.3).rect(startX, y, colWidths.reduce((a, b) => a + b, 0), rowH).stroke();
    doc.x = startX;
    doc.y = y + rowH;
  };

  drawRow(headers, { bold: true, fill: '#f1f5f9' });
  for (const r of rows) drawRow(r);
  doc.moveDown(0.5);
  doc.font('Helvetica').fillColor(COLORS.ink);
}

export function renderPdf(a: Assessment, p: ArbPackage, sink: Writable): void {
  const doc = new PDFDocument({ size: 'LETTER', margins: { top: 50, bottom: 60, left: 50, right: 50 } });
  doc.pipe(sink);

  // Title page
  doc.fillColor(COLORS.accent).fontSize(28).font('Helvetica-Bold').text('Architecture Review Board Package', { align: 'left' });
  doc.moveDown(0.5).fillColor(COLORS.ink).fontSize(20).text(a.business.applicationName);
  doc.moveDown(0.5).fillColor(COLORS.muted).fontSize(11).font('Helvetica');
  doc.text(`Generated: ${p.generatedAt}`);
  doc.text(`Package version: ${p.packageVersion}`);
  doc.text(`Package hash: ${p.packageHash.slice(0, 16)}…`);

  doc.moveDown(1);
  kv(doc, 'FIPS 199 Category', p.categorization.overallCategorization);
  kv(doc, 'Risk Posture', p.executiveSummary.riskPosture);
  kv(doc, 'ARB Recommendation', p.executiveSummary.goNoGoAdvice);
  kv(doc, 'Recovery Tier', p.recovery.availabilityTier);
  kv(doc, 'Cost Tier', `${p.costEstimate.tier} ($${p.costEstimate.monthlyLowUsd.toLocaleString()}–$${p.costEstimate.monthlyHighUsd.toLocaleString()}/mo)`);

  // Executive Summary
  h1(doc, 'Executive Summary');
  doc.font('Helvetica-Bold').text(p.executiveSummary.oneLiner);
  doc.moveDown(0.3).font('Helvetica').text(p.executiveSummary.businessContext);
  doc.moveDown(0.3);
  doc.font('Helvetica-Bold').text('Conditions:').font('Helvetica');
  bullets(doc, p.executiveSummary.conditions);
  doc.moveDown(0.2);
  doc.font('Helvetica-Bold').text('Top residual risks:').font('Helvetica');
  bullets(doc, p.executiveSummary.topRisks);
  doc.moveDown(0.2);
  doc.font('Helvetica-Bold').text('Key recommendations:').font('Helvetica');
  bullets(doc, p.executiveSummary.keyRecommendations);

  // Categorization
  h1(doc, 'FIPS 199 Categorization');
  kv(doc, 'Confidentiality', p.categorization.confidentialityImpact);
  kv(doc, 'Integrity', p.categorization.integrityImpact);
  kv(doc, 'Availability', p.categorization.availabilityImpact);
  doc.moveDown(0.3);
  doc.font('Helvetica-Bold').text('Rationale:').font('Helvetica');
  bullets(doc, p.categorization.rationale);
  doc.moveDown(0.3);
  h2(doc, 'Matched Information Types (NIST 800-60)');
  table(doc,
    ['Code', 'Name', 'C', 'I', 'A'],
    p.categorization.informationTypes.map(i => [i.code, i.name, i.confidentiality, i.integrity, i.availability]),
    [70, 250, 50, 50, 50]
  );

  // Architecture (textual — Mermaid is not rendered in PDF)
  h1(doc, 'Architecture');
  doc.fillColor(COLORS.muted).text('Diagrams (architecture, security overlay, DFD) are rendered in the HTML export and viewer.');
  doc.fillColor(COLORS.ink);
  doc.moveDown(0.3);
  table(doc,
    ['Component', 'Layer', 'AWS Service', 'Trust Zone', 'Sensitive'],
    p.architecture.components.map(c => [c.name, c.layer, c.awsService ?? '—', c.trustZone, c.containsSensitiveData ? 'yes' : 'no']),
    [180, 70, 110, 95, 55]
  );

  // STRIDE
  doc.addPage();
  h1(doc, 'STRIDE Threat Model');
  table(doc,
    ['Component', 'Category', 'L', 'I', 'Inherent', 'Residual'],
    p.threatModel.map(t => [t.componentName, t.category, t.likelihood, t.impact, t.inherentRisk, t.residualRisk]),
    [150, 110, 30, 30, 70, 70]
  );

  // Operational threats
  h1(doc, 'Operational Threats');
  table(doc,
    ['Category', 'L', 'I', 'Recommendation'],
    p.operationalThreatModel.map(o => [o.category, o.likelihood, o.impact, o.recommendation]),
    [120, 30, 30, 270]
  );

  // SSP
  doc.addPage();
  h1(doc, `System Security Plan — ${p.ssp.length} controls`);
  for (const c of p.ssp) {
    doc.font('Helvetica-Bold').fillColor(COLORS.accent).text(`${c.id} — ${c.name}`);
    doc.font('Helvetica').fillColor(COLORS.muted).text(`${c.family} · ${c.inheritance} · ${c.implementationStatus} · ${c.responsibleParty}`);
    doc.font('Helvetica').fillColor(COLORS.ink).text(c.implementationStatement);
    doc.fillColor(COLORS.muted).text(`Evidence: ${c.evidence.join('; ')}`);
    doc.text(`Rationale: ${c.rationale}`);
    doc.fillColor(COLORS.ink).moveDown(0.3);
  }

  // Recovery
  doc.addPage();
  h1(doc, 'Recovery Assessment');
  kv(doc, 'RTO / RPO', `${p.recovery.rto} / ${p.recovery.rpo}`);
  kv(doc, 'Availability tier', p.recovery.availabilityTier);
  kv(doc, 'Multi-AZ / Multi-Region', `${p.recovery.multiAz} / ${p.recovery.multiRegion}`);
  kv(doc, 'Backup', p.recovery.backupStrategy);
  kv(doc, 'Restore testing', p.recovery.restoreTestingCadence);
  kv(doc, 'Failover', p.recovery.failoverApproach);
  doc.moveDown(0.3);
  doc.font('Helvetica-Bold').text('Gaps:').font('Helvetica');
  bullets(doc, p.recovery.gaps);

  // Compliance
  h1(doc, 'Compliance Mapping');
  table(doc,
    ['Framework', 'Control', 'Description', 'Coverage'],
    p.complianceMappings.map(m => [m.framework, m.controlId, m.description, m.coverage]),
    [90, 80, 280, 60]
  );

  // Residual Risk Register
  doc.addPage();
  h1(doc, 'Residual Risk Register');
  table(doc,
    ['ID', 'Source', 'Inherent', 'Residual', 'Description'],
    p.residualRisks.map(r => [r.id, r.source, r.inherentRisk, r.residualRisk, r.description]),
    [60, 70, 70, 70, 240]
  );

  // Cost
  h1(doc, 'Cost Estimate');
  kv(doc, 'Tier', p.costEstimate.tier);
  kv(doc, 'Monthly band', `$${p.costEstimate.monthlyLowUsd.toLocaleString()} – $${p.costEstimate.monthlyHighUsd.toLocaleString()} USD`);
  doc.moveDown(0.3);
  table(doc,
    ['Driver', 'Low', 'High', 'Rationale'],
    p.costEstimate.drivers.map(d => [d.item, '$' + d.lowUsd.toLocaleString(), '$' + d.highUsd.toLocaleString(), d.rationale]),
    [180, 60, 60, 200]
  );

  // Signature block
  doc.addPage();
  h1(doc, 'Approval / Signature Block');
  if (a.approvalRequest && a.approvalRequest.approvals.length > 0) {
    for (const s of a.approvalRequest.approvals) {
      doc.font('Helvetica-Bold').fillColor(s.decision === 'approve' ? COLORS.ok : COLORS.danger).text(`${s.role.toUpperCase()} — ${s.decision.toUpperCase()}`);
      doc.font('Helvetica').fillColor(COLORS.ink).text(`Signed by ${s.displayName} at ${s.signedAt}`);
      if (s.comment) doc.fillColor(COLORS.muted).text(`Comment: ${s.comment}`).fillColor(COLORS.ink);
      doc.moveDown(0.3);
    }
    doc.font('Helvetica-Bold').text(`Package hash signed: ${a.approvalRequest.packageHash}`);
  } else {
    for (const role of ['Security', 'Risk', 'Architecture', 'Compliance']) {
      doc.font('Helvetica-Bold').text(`${role} reviewer:`);
      doc.font('Helvetica').fillColor(COLORS.muted).text('Name: ____________________________   Date: __________');
      doc.text('Signature: ________________________________________');
      doc.moveDown(0.5).fillColor(COLORS.ink);
    }
  }

  doc.end();
}
