// FedRAMP-specific export routes. Produces the full FedRAMP package
// (SSP + supporting documents + POA&M + OSCAL) as either individual
// downloads or a single tar archive — preserving the FedRAMP package
// naming convention so an Authorizing Official can drop it straight
// into their review pipeline.

import { Router } from 'express';
import { getPackage, getAssessment } from '../store/assessmentStore';
import { fipsStatus } from '../engine/fips';
import { ArbPackage, Assessment, FedrampPackage } from '../types/assessment';
import { renderMarkdown } from '../export/markdown';
import { Readable } from 'stream';
import { requireAccess } from '../auth/tenant';

export const fedrampRouter = Router();

fedrampRouter.get('/status', (_req, res) => {
  res.json({ fips: fipsStatus() });
});

fedrampRouter.get('/:id', (req, res) => {
  if (!requireAccess(req, res, req.params.id)) return;
  const pkg = getPackage(req.params.id);
  if (!pkg?.fedramp) { res.status(404).json({ error: 'FedRAMP not in scope for this assessment' }); return; }
  res.json(pkg.fedramp);
});

fedrampRouter.get('/:id/poam.csv', (req, res) => {
  if (!requireAccess(req, res, req.params.id)) return;
  const pkg = getPackage(req.params.id);
  if (!pkg?.fedramp) { res.status(404).send('FedRAMP not in scope'); return; }
  res.setHeader('Content-Disposition', `attachment; filename="POAM-${pkg.assessmentId}.csv"`);
  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.send(renderPoamCsv(pkg.fedramp));
});

fedrampRouter.get('/:id/poam.oscal.json', (req, res) => {
  if (!requireAccess(req, res, req.params.id)) return;
  const pkg = getPackage(req.params.id);
  const a = getAssessment(req.params.id);
  if (!pkg?.fedramp || !a) { res.status(404).json({ error: 'FedRAMP not in scope' }); return; }
  res.setHeader('Content-Disposition', `attachment; filename="POAM-${pkg.assessmentId}.oscal.json"`);
  res.setHeader('Content-Type', 'application/json');
  res.send(JSON.stringify(renderPoamOscal(a, pkg), null, 2));
});

fedrampRouter.get('/:id/pack.tar', (req, res) => {
  if (!requireAccess(req, res, req.params.id)) return;
  const pkg = getPackage(req.params.id);
  const a = getAssessment(req.params.id);
  if (!pkg?.fedramp || !a) { res.status(404).send('FedRAMP not in scope'); return; }
  res.setHeader('Content-Disposition', `attachment; filename="FedRAMP-Package-${pkg.assessmentId}.tar"`);
  res.setHeader('Content-Type', 'application/x-tar');
  buildTar(a, pkg).pipe(res);
});

// ---- CSV ----
function csvCell(v: unknown): string {
  let s = v == null ? '' : String(v);
  // Same CSV-injection guard as src/export/csv.ts
  if (s.length > 0 && /^[=+\-@\t\r]/.test(s)) s = "'" + s;
  return /[",\n\r]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
}
function csvRow(cells: unknown[]): string { return cells.map(csvCell).join(',') + '\r\n'; }

function renderPoamCsv(fr: FedrampPackage): string {
  let out = csvRow(['POA&M ID', 'Weakness', 'Source', 'Severity', 'Status', 'Identified', 'Scheduled Completion', 'Point of Contact', 'Controls Impacted', 'Resources Required']);
  for (const it of fr.poam) {
    out += csvRow([it.poamId, it.weakness, it.source, it.severity, it.status, it.identifiedAt, it.scheduledCompletion, it.pointOfContact, it.controlsImpacted.join('; '), it.resourcesRequired]);
  }
  return out;
}

// ---- OSCAL POA&M ----
function renderPoamOscal(a: Assessment, pkg: ArbPackage): unknown {
  return {
    'plan-of-action-and-milestones': {
      uuid: randomUuid(),
      metadata: {
        title: `Plan of Action and Milestones — ${a.business.applicationName}`,
        'last-modified': new Date().toISOString(),
        version: String(pkg.packageVersion),
        'oscal-version': '1.1.2'
      },
      'system-id': { id: pkg.assessmentId, 'identifier-type': 'http://fedramp.gov/ns/oscal/system' },
      'poam-items': pkg.fedramp!.poam.map(p => ({
        uuid: randomUuid(),
        title: p.weakness.slice(0, 120),
        description: p.weakness,
        props: [
          { name: 'severity', value: p.severity.toLowerCase() },
          { name: 'status', value: p.status.toLowerCase().replace(/ /g, '-') },
          { name: 'scheduled-completion-date', value: p.scheduledCompletion },
          { name: 'point-of-contact', value: p.pointOfContact },
          { name: 'source', value: p.source }
        ],
        'related-findings': p.controlsImpacted.map(c => ({ 'finding-uuid': c }))
      }))
    }
  };
}

function randomUuid(): string {
  return [4, 2, 2, 2, 6].map(n => Math.random().toString(16).slice(2, 2 + 2 * n).padEnd(2 * n, '0')).join('-');
}

// ---- Minimal tar writer (POSIX ustar) — avoids extra dep ----
function tarHeader(name: string, size: number): Buffer {
  const header = Buffer.alloc(512);
  header.write(name.slice(0, 100), 0);
  header.write('0000644', 100, 'ascii');
  header.write('0000000', 108, 'ascii');
  header.write('0000000', 116, 'ascii');
  header.write(size.toString(8).padStart(11, '0') + ' ', 124, 'ascii');
  header.write(Math.floor(Date.now() / 1000).toString(8).padStart(11, '0') + ' ', 136, 'ascii');
  header.write('        ', 148, 'ascii'); // checksum placeholder
  header.write('0', 156, 'ascii');         // typeflag
  header.write('ustar', 257, 'ascii');
  header.write('00', 263, 'ascii');
  // Compute checksum
  let sum = 0;
  for (let i = 0; i < 512; i++) sum += header[i]!;
  header.write(sum.toString(8).padStart(6, '0'), 148, 'ascii');
  header.write('\0 ', 154, 'ascii');
  return header;
}

function tarFile(name: string, content: string | Buffer): Buffer[] {
  const buf = Buffer.isBuffer(content) ? content : Buffer.from(content, 'utf-8');
  const padLen = (512 - (buf.length % 512)) % 512;
  return [tarHeader(name, buf.length), buf, Buffer.alloc(padLen)];
}

function buildTar(a: Assessment, pkg: ArbPackage): Readable {
  const fr = pkg.fedramp!;
  const base = `FedRAMP-Package-${pkg.assessmentId.slice(0, 8)}`;
  const files: { name: string; content: string }[] = [
    { name: `${base}/README.txt`, content: `FedRAMP package for ${a.business.applicationName}\nGenerated: ${pkg.generatedAt}\nBaseline: ${fr.baseline}\nPackage hash: ${pkg.packageHash}\n` },
    { name: `${base}/SSP.md`, content: renderMarkdown(a, pkg) },
    { name: `${base}/SSP.oscal.json`, content: JSON.stringify({ 'system-security-plan': pkg.oscalSsp }, null, 2) },
    { name: `${base}/POAM.csv`, content: renderPoamCsv(fr) },
    { name: `${base}/POAM.oscal.json`, content: JSON.stringify(renderPoamOscal(a, pkg), null, 2) },
    { name: `${base}/PTA.md`, content: ptaMd(fr) },
    { name: `${base}/PIA.md`, content: piaMd(fr) },
    { name: `${base}/ISCP.md`, content: iscpMd(fr) },
    { name: `${base}/IRP.md`, content: irpMd(fr) },
    { name: `${base}/Rules-of-Behavior.md`, content: robMd(fr) },
    { name: `${base}/CMP.md`, content: cmpMd(fr) },
    { name: `${base}/ConMon-Strategy.md`, content: conmonMd(fr) },
    { name: `${base}/E-Auth-Worksheet.md`, content: eauthMd(fr) },
    { name: `${base}/Authorization-Boundary.md`, content: boundaryMd(fr) },
    { name: `${base}/Agency-Overlays.md`, content: overlaysMd(fr) },
    { name: `${base}/FIPS-Attestation.json`, content: JSON.stringify(fr.fipsAttestation, null, 2) },
    { name: `${base}/Baseline-Parameters.csv`, content: paramsCsv(fr) }
  ];

  const chunks: Buffer[] = [];
  for (const f of files) for (const part of tarFile(f.name, f.content)) chunks.push(part);
  // Two zero blocks to mark end of archive
  chunks.push(Buffer.alloc(1024));

  return Readable.from(Buffer.concat(chunks));
}

function paramsCsv(fr: FedrampPackage): string {
  let out = csvRow(['Control', 'Parameter', 'FedRAMP Value']);
  for (const p of fr.parameterValues) out += csvRow([p.controlId, p.paramId, p.value]);
  return out;
}
function ptaMd(fr: FedrampPackage): string {
  return [
    '# Privacy Threshold Analysis',
    `**PIA required:** ${fr.pta.piaRequired ? 'Yes' : 'No'}`,
    `**Sensitive categories present:** ${fr.pta.containsSensitiveCategories ? 'Yes' : 'No'}`,
    `**Privacy categories:** ${fr.pta.piiCategoriesPresent.join(', ') || 'none'}`,
    `**Rationale:** ${fr.pta.rationale}`,
    `**System of Records Notice applicable:** ${fr.pta.systemOfRecordsApplicable ? 'Yes' : 'No'}`
  ].join('\n');
}
function piaMd(fr: FedrampPackage): string {
  if (!fr.pia) return '# Privacy Impact Assessment\n_PIA not required per PTA._';
  return [
    '# Privacy Impact Assessment',
    fr.pia.introduction,
    '## Information collected', fr.pia.informationCollected,
    '## Lawful basis', ...fr.pia.lawfulBasis.map(l => `- ${l}`),
    '## Retention & disposition', fr.pia.retentionAndDisposition,
    '## Individual participation', fr.pia.individualParticipation,
    '## Data sharing',
    ...fr.pia.dataSharing.map(d => `- **${d.partner}** — ${d.purpose} (${d.safeguards})`),
    '## Privacy risks',
    ...fr.pia.privacyRisks.map(r => `- ${r.description}\n  - Mitigation: ${r.mitigation}`),
    `_Drafted by ${fr.pia.approval.drafter}; reviewed by ${fr.pia.approval.reviewer}._`
  ].join('\n\n');
}
function iscpMd(fr: FedrampPackage): string {
  return [
    `# Information System Contingency Plan — ${fr.iscp.systemName}`,
    `**RTO:** ${fr.iscp.rto}   **RPO:** ${fr.iscp.rpo}`,
    '## Recovery priorities', ...fr.iscp.recoveryPriorities.map(s => `- ${s}`),
    '## Alternate processing', fr.iscp.alternateProcessing,
    '## Alternate storage', fr.iscp.alternateStorage,
    '## Notification procedures', ...fr.iscp.notificationProcedures.map(s => `- ${s}`),
    '## Testing cadence', fr.iscp.testingCadence,
    '## Recovery procedures', ...fr.iscp.recoveryProcedures.map(s => `1. ${s}`)
  ].join('\n');
}
function irpMd(fr: FedrampPackage): string {
  return [
    '# Incident Response Plan',
    `**Scope:** ${fr.irp.scope}`,
    `**Reporting timeline:** ${fr.irp.reportingTimeline}`,
    '## Categories', ...fr.irp.categories.map(c => `- ${c}`),
    '## Declaration criteria', fr.irp.declarationCriteria,
    '## Roles', ...fr.irp.rolesAndResponsibilities.map(r => `- **${r.role}** — ${r.responsibility}`),
    '## Notification contacts', ...fr.irp.notificationContacts.map(c => `- ${c}`),
    '## Containment', ...fr.irp.containmentSteps.map(s => `- ${s}`),
    '## Eradication', ...fr.irp.eradicationSteps.map(s => `- ${s}`),
    '## Recovery', ...fr.irp.recoverySteps.map(s => `- ${s}`),
    `## Lessons learned\n${fr.irp.lessonsLearned}`
  ].join('\n');
}
function robMd(fr: FedrampPackage): string {
  return '# Rules of Behavior\n\n' + fr.rulesOfBehavior.map((r, i) => `${i + 1}. ${r}`).join('\n');
}
function cmpMd(fr: FedrampPackage): string {
  return [
    '# Configuration Management Plan',
    `**Baseline source:** ${fr.cmp.baselineSource}`,
    `**Change control:** ${fr.cmp.changeControlProcess}`,
    `**Approval authority:** ${fr.cmp.approvalAuthority}`,
    `**Drift detection:** ${fr.cmp.driftDetection}`,
    `**Review cadence:** ${fr.cmp.reviewCadence}`
  ].join('\n');
}
function conmonMd(fr: FedrampPackage): string {
  return [
    '# Continuous Monitoring Strategy',
    `## Vulnerability scans\n- Scope: ${fr.conmon.vulnScans.scope}\n- Cadence: ${fr.conmon.vulnScans.cadence}`,
    `## Penetration testing\n- Scope: ${fr.conmon.pentest.scope}\n- Cadence: ${fr.conmon.pentest.cadence}`,
    `## Configuration compliance\n- Scope: ${fr.conmon.configCompliance.scope}\n- Cadence: ${fr.conmon.configCompliance.cadence}`,
    '## Quarterly control reviews',
    ...fr.conmon.controlSubsetReviews.quarterly.map(c => `- ${c}`),
    '## Annual control reviews',
    ...fr.conmon.controlSubsetReviews.annual.map(c => `- ${c}`),
    `## Reporting cadence\n${fr.conmon.reportingCadence}`,
    '## Metrics', ...fr.conmon.metrics.map(m => `- ${m}`)
  ].join('\n');
}
function eauthMd(fr: FedrampPackage): string {
  return [
    '# E-Authentication Worksheet',
    `**Identity Assurance Level (IAL):** ${fr.eAuthWorksheet.assuranceLevel}`,
    `**Authenticator Assurance Level (AAL):** ${fr.eAuthWorksheet.authenticatorAssuranceLevel}`,
    `**Federation Assurance Level (FAL):** ${fr.eAuthWorksheet.federationAssuranceLevel}`,
    `**MFA required:** ${fr.eAuthWorksheet.mfaRequired ? 'Yes' : 'No'}`,
    `**Phishing-resistant MFA required:** ${fr.eAuthWorksheet.phishingResistantRequired ? 'Yes' : 'No'}`,
    `**Rationale:** ${fr.eAuthWorksheet.rationale}`
  ].join('\n');
}
function boundaryMd(fr: FedrampPackage): string {
  return [
    '# Authorization Boundary',
    fr.authorizationBoundary.description,
    `\n## In-scope components (${fr.authorizationBoundary.inScopeComponents.length})`,
    ...fr.authorizationBoundary.inScopeComponents.map(c => `- ${c.name} (${c.trustZone})`),
    `\n## External connections (${fr.authorizationBoundary.externalConnections.length})`,
    ...fr.authorizationBoundary.externalConnections.map(e => `- ${e.source} → ${e.destination} via ${e.protocol} — ${e.safeguards}`),
    '\n## Out-of-scope assertions',
    ...fr.authorizationBoundary.outOfScopeAssertions.map(s => `- ${s}`)
  ].join('\n');
}
function overlaysMd(fr: FedrampPackage): string {
  if (!fr.agencyOverlays.length) return '# Agency Overlays\n\n_No agency-specific overlays apply._';
  return ['# Agency Overlays',
    ...fr.agencyOverlays.flatMap(o => [
      `\n## ${o.name}`,
      `- Additional controls: ${o.additionalControls.join(', ') || 'none'}`,
      `- Citizenship requirement: ${o.citizenshipRequirement || 'none'}`,
      `- Data location: ${o.dataLocation || 'as primary'}`,
      o.parameterOverrides.length ? '- Parameter overrides:' : '',
      ...o.parameterOverrides.map(p => `  - ${p.controlId}: ${p.value}`)
    ])
  ].join('\n');
}
