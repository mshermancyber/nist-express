// CSV exports for the artifacts auditors most often request as
// spreadsheets: SSP control inventory, evidence requests, residual risk
// register, auditable events, threat findings, and the cost breakdown.
// We hand-roll the CSV encoding (no dependency) — it's RFC-4180 with
// commas as separator, double-quotes for quoting, and "" for embedded
// double-quotes.

import { ArbPackage } from '../types/assessment';

function csvCell(v: unknown): string {
  let s = v === null || v === undefined ? '' : String(v);
  // CSV-injection neutralization: cells beginning with =,+,-,@,\t,\r
  // get a leading apostrophe so Excel / Google Sheets / LibreOffice
  // refuse to interpret them as formulas.
  if (s.length > 0 && /^[=+\-@\t\r]/.test(s)) {
    s = "'" + s;
  }
  if (/[",\n\r]/.test(s)) {
    return '"' + s.replace(/"/g, '""') + '"';
  }
  return s;
}

function csvRow(cells: unknown[]): string {
  return cells.map(csvCell).join(',') + '\r\n';
}

export function sspCsv(p: ArbPackage): string {
  let out = csvRow(['Control', 'Family', 'Name', 'Inheritance', 'Status', 'Responsible Party', 'Implementation', 'Evidence', 'CIS v8', 'Rationale', 'Assessment Guidance']);
  for (const c of p.ssp) {
    out += csvRow([c.id, c.family, c.name, c.inheritance, c.implementationStatus, c.responsibleParty, c.implementationStatement, c.evidence.join('; '), c.cisMappings.join(', '), c.rationale, c.assessmentGuidance]);
  }
  return out;
}

export function evidenceCsv(p: ArbPackage): string {
  let out = csvRow(['Control', 'Artifact', 'Collection Method', 'Responsible Party', 'Acceptance Criteria']);
  for (const e of p.evidenceRequests) {
    out += csvRow([e.controlId, e.artifact, e.collectionMethod, e.responsibleParty, e.acceptanceCriteria]);
  }
  return out;
}

export function residualRiskCsv(p: ArbPackage): string {
  let out = csvRow(['ID', 'Source', 'Inherent', 'Residual', 'Treatment', 'Owner', 'Description', 'Rationale']);
  for (const r of p.residualRisks) {
    out += csvRow([r.id, r.source, r.inherentRisk, r.residualRisk, r.treatment, r.owner, r.description, r.rationale]);
  }
  return out;
}

export function auditEventsCsv(p: ArbPackage): string {
  let out = csvRow(['Event', 'Source', 'CIA', 'Retention (days)', 'Alerting', 'Severity', 'Controls', 'Rationale']);
  for (const e of p.auditableEvents) {
    out += csvRow([e.name, e.source, e.ciaMapping.join('/'), e.retentionDays, e.alerting, e.severityOnAlert, e.controlReferences.join(', '), e.rationale]);
  }
  return out;
}

export function strideCsv(p: ArbPackage): string {
  let out = csvRow(['Component', 'Category', 'Description', 'Attack Path', 'Likelihood', 'Impact', 'Inherent Risk', 'Residual Risk', 'Mitigations']);
  for (const t of p.threatModel) {
    out += csvRow([t.componentName, t.category, t.description, t.attackPath, t.likelihood, t.impact, t.inherentRisk, t.residualRisk, t.mitigations.join(', ')]);
  }
  return out;
}

export function costCsv(p: ArbPackage): string {
  let out = csvRow(['Driver', 'Low USD/mo', 'High USD/mo', 'Rationale']);
  for (const d of p.costEstimate.drivers) {
    out += csvRow([d.item, d.lowUsd, d.highUsd, d.rationale]);
  }
  out += csvRow(['TOTAL', p.costEstimate.monthlyLowUsd, p.costEstimate.monthlyHighUsd, `Tier ${p.costEstimate.tier}`]);
  return out;
}

export function complianceCsv(p: ArbPackage): string {
  let out = csvRow(['Framework', 'Control', 'Description', 'Coverage', 'Satisfied By']);
  for (const m of p.complianceMappings) {
    out += csvRow([m.framework, m.controlId, m.description, m.coverage, m.satisfiedByControlIds.join(', ')]);
  }
  return out;
}

export function diffCsv(p: ArbPackage): string {
  let out = csvRow(['Category', 'Change', 'Detail']);
  if (!p.diff) { out += csvRow(['n/a', 'first version', 'no diff to render']); return out; }
  const d = p.diff;
  if (d.postureChange) out += csvRow(['posture', 'change', `${d.postureChange.from} → ${d.postureChange.to}`]);
  if (d.goNoGoChange) out += csvRow(['recommendation', 'change', `${d.goNoGoChange.from} → ${d.goNoGoChange.to}`]);
  if (d.categoryChange) out += csvRow(['category', 'change', `${d.categoryChange.from} → ${d.categoryChange.to}`]);
  if (d.recoveryTierChange) out += csvRow(['recovery-tier', 'change', `${d.recoveryTierChange.from} → ${d.recoveryTierChange.to}`]);
  for (const c of d.controlsAdded) out += csvRow(['control', 'added', c]);
  for (const c of d.controlsRemoved) out += csvRow(['control', 'removed', c]);
  for (const c of d.componentsAdded) out += csvRow(['component', 'added', c]);
  for (const c of d.componentsRemoved) out += csvRow(['component', 'removed', c]);
  out += csvRow(['risk-score', 'inherent-delta', String(d.threatCountDelta.inherent)]);
  out += csvRow(['risk-score', 'residual-delta', String(d.threatCountDelta.residual)]);
  out += csvRow(['compliance', 'full-delta', String(d.complianceCoverageDelta.full)]);
  out += csvRow(['compliance', 'partial-delta', String(d.complianceCoverageDelta.partial)]);
  out += csvRow(['compliance', 'gap-delta', String(d.complianceCoverageDelta.gap)]);
  return out;
}

export function fairCsv(p: ArbPackage): string {
  let out = csvRow(['Risk ID', 'Description', 'TEF Low', 'TEF High', 'Vuln Low', 'Vuln High', 'LM Low (USD)', 'LM High (USD)', 'ALE p10', 'ALE p50', 'ALE p90', 'ALE mean']);
  for (const f of p.fair.perRisk) {
    out += csvRow([f.riskId, f.description, f.tefLow, f.tefHigh, f.vulnLow, f.vulnHigh, f.lmLow, f.lmHigh, f.aleP10, f.aleP50, f.aleP90, f.aleMean]);
  }
  out += csvRow(['PORTFOLIO', '—', '', '', '', '', '', '', p.fair.portfolio.aleP10, p.fair.portfolio.aleP50, p.fair.portfolio.aleP90, p.fair.portfolio.aleMean]);
  return out;
}

export function sbomCsv(p: ArbPackage): string {
  let out = csvRow(['CVE/Advisory', 'Severity', 'CVSS', 'KEV', 'Affects', 'Description']);
  if (!p.sbomAnalysis) return out;
  for (const v of p.sbomAnalysis.vulnerabilities) {
    out += csvRow([v.id, v.severity, v.cvssScore ?? '', v.kev ? 'yes' : 'no', v.affectsComponents.join('; '), v.description ?? '']);
  }
  return out;
}

export type CsvKind = 'ssp' | 'evidence' | 'residual-risk' | 'audit-events' | 'stride' | 'cost' | 'compliance' | 'diff' | 'fair' | 'sbom';

export function renderCsv(kind: CsvKind, p: ArbPackage): string {
  switch (kind) {
    case 'ssp': return sspCsv(p);
    case 'evidence': return evidenceCsv(p);
    case 'residual-risk': return residualRiskCsv(p);
    case 'audit-events': return auditEventsCsv(p);
    case 'stride': return strideCsv(p);
    case 'cost': return costCsv(p);
    case 'compliance': return complianceCsv(p);
    case 'diff': return diffCsv(p);
    case 'fair': return fairCsv(p);
    case 'sbom': return sbomCsv(p);
  }
}
