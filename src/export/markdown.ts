// Markdown renderer for the ARB package. Layout mirrors the on-screen
// viewer so reviewers can move freely between formats.

import { Assessment, ArbPackage } from '../types/assessment';

function bullets(items: string[]): string {
  if (!items.length) return '_(none)_';
  return items.map(i => `- ${i}`).join('\n');
}

export function renderMarkdown(a: Assessment, p: ArbPackage): string {
  const sections: string[] = [];
  sections.push(`# Architecture Review Board Package`);
  sections.push(`**${a.business.applicationName}** — generated ${p.generatedAt}`);
  sections.push('');
  sections.push(`## Executive Summary`);
  sections.push(`> ${p.executiveSummary.oneLiner}`);
  sections.push('');
  sections.push(p.executiveSummary.businessContext);
  sections.push('');
  sections.push(`**Risk Posture:** ${p.executiveSummary.riskPosture}  `);
  sections.push(`**ARB Recommendation:** ${p.executiveSummary.goNoGoAdvice}`);
  if (p.executiveSummary.conditions.length) {
    sections.push(`**Conditions:**`);
    sections.push(bullets(p.executiveSummary.conditions));
  }
  sections.push('');
  sections.push(`## FIPS 199 Security Categorization`);
  sections.push(`- Confidentiality: **${p.categorization.confidentialityImpact}**`);
  sections.push(`- Integrity: **${p.categorization.integrityImpact}**`);
  sections.push(`- Availability: **${p.categorization.availabilityImpact}**`);
  sections.push(`- Overall (high-water mark): **${p.categorization.overallCategorization}**`);
  sections.push('');
  sections.push(`### Information Types (NIST 800-60)`);
  sections.push('| Code | Name | C | I | A | Basis |');
  sections.push('|---|---|---|---|---|---|');
  for (const it of p.categorization.informationTypes) {
    sections.push(`| ${it.code} | ${it.name} | ${it.confidentiality} | ${it.integrity} | ${it.availability} | ${it.basisInAssessment} |`);
  }
  sections.push('');
  sections.push(`### Categorisation Rationale`);
  sections.push(bullets(p.categorization.rationale));
  sections.push('');
  sections.push(`## Data Classification`);
  sections.push(`**Primary classification:** ${p.dataClassification.primaryClassification}`);
  sections.push(`**Handling:**`);
  sections.push(bullets(p.dataClassification.handlingRequirements));
  sections.push(`**Retention:** ${p.dataClassification.retentionGuidance}`);
  sections.push(`**Disposition:** ${p.dataClassification.dispositionGuidance}`);
  sections.push('');
  sections.push(`## Architecture`);
  sections.push('### Architecture Diagram');
  sections.push('```mermaid');
  sections.push(p.architectureDiagramMermaid);
  sections.push('```');
  sections.push('');
  sections.push('### Security Overlay');
  sections.push('```mermaid');
  sections.push(p.securityOverlayDiagramMermaid);
  sections.push('```');
  sections.push('');
  sections.push('### Data Flow Diagram');
  sections.push('```mermaid');
  sections.push(p.dataFlowDiagramMermaid);
  sections.push('```');
  sections.push('');
  sections.push('### Components');
  sections.push('| Component | Layer | AWS Service | Trust Zone | Sensitive | Rationale |');
  sections.push('|---|---|---|---|---|---|');
  for (const c of p.architecture.components) {
    sections.push(`| ${c.name} | ${c.layer} | ${c.awsService ?? '—'} | ${c.trustZone} | ${c.containsSensitiveData ? 'yes' : 'no'} | ${c.rationale} |`);
  }
  sections.push('');
  sections.push('### Architecture Rationale');
  sections.push(bullets(p.architecture.rationale));
  sections.push('');
  sections.push(`## STRIDE Threat Model`);
  sections.push('| Component | Category | Likelihood | Impact | Inherent | Residual | Mitigations |');
  sections.push('|---|---|---|---|---|---|---|');
  for (const t of p.threatModel) {
    sections.push(`| ${t.componentName} | ${t.category} | ${t.likelihood} | ${t.impact} | ${t.inherentRisk} | ${t.residualRisk} | ${t.mitigations.join(', ')} |`);
  }
  sections.push('');
  sections.push(`## Operational Threats`);
  sections.push('| Category | Likelihood | Impact | Recommendation | Controls |');
  sections.push('|---|---|---|---|---|');
  for (const o of p.operationalThreatModel) {
    sections.push(`| ${o.category} | ${o.likelihood} | ${o.impact} | ${o.recommendation} | ${o.controlReferences.join(', ')} |`);
  }
  sections.push('');
  sections.push(`## System Security Plan (NIST 800-53 Rev 5)`);
  for (const c of p.ssp) {
    sections.push(`### ${c.id} — ${c.name} (${c.family})`);
    sections.push(`**Inheritance:** ${c.inheritance} | **Status:** ${c.implementationStatus} | **Responsible Party:** ${c.responsibleParty}`);
    sections.push('');
    sections.push(`**Implementation:** ${c.implementationStatement}`);
    sections.push('');
    sections.push(`**Evidence:** ${c.evidence.join('; ')}`);
    sections.push(`**CIS v8 Mapping:** ${c.cisMappings.join(', ') || '—'}`);
    sections.push(`**Rationale:** ${c.rationale}`);
    sections.push(`**Assessment Guidance:** ${c.assessmentGuidance}`);
    sections.push('');
  }
  sections.push(`## Auditable Events`);
  sections.push('| Event | Source | CIA | Retention | Alerting | Severity | Controls |');
  sections.push('|---|---|---|---|---|---|---|');
  for (const e of p.auditableEvents) {
    sections.push(`| ${e.name} | ${e.source} | ${e.ciaMapping.join('/')} | ${e.retentionDays}d | ${e.alerting} | ${e.severityOnAlert} | ${e.controlReferences.join(', ')} |`);
  }
  sections.push('');
  sections.push(`## Recovery Assessment`);
  sections.push(`- RTO: ${p.recovery.rto}  RPO: ${p.recovery.rpo}`);
  sections.push(`- Availability Tier: ${p.recovery.availabilityTier}`);
  sections.push(`- Multi-AZ: ${p.recovery.multiAz}  Multi-Region: ${p.recovery.multiRegion}`);
  sections.push(`- Backup Strategy: ${p.recovery.backupStrategy}`);
  sections.push(`- Restore Testing: ${p.recovery.restoreTestingCadence}`);
  sections.push(`- Failover: ${p.recovery.failoverApproach}`);
  sections.push(`- Gaps:`);
  sections.push(bullets(p.recovery.gaps));
  sections.push(`- Recommendations:`);
  sections.push(bullets(p.recovery.recommendations));
  sections.push('');
  sections.push(`## Compliance Mapping`);
  sections.push('| Framework | Control | Description | Coverage | NIST Controls |');
  sections.push('|---|---|---|---|---|');
  for (const m of p.complianceMappings) {
    sections.push(`| ${m.framework} | ${m.controlId} | ${m.description} | ${m.coverage} | ${m.satisfiedByControlIds.join(', ') || '—'} |`);
  }
  sections.push('');
  sections.push(`## AWS Well-Architected Scoring`);
  for (const w of p.wellArchitected) {
    sections.push(`### ${w.pillar}: ${w.score}/100`);
    sections.push('**Findings:**');
    sections.push(bullets(w.findings));
    sections.push('**Recommendations:**');
    sections.push(bullets(w.recommendations));
  }
  sections.push('');
  sections.push(`## Evidence Requests`);
  sections.push('| Control | Artifact | Method | Responsible | Acceptance |');
  sections.push('|---|---|---|---|---|');
  for (const e of p.evidenceRequests) {
    sections.push(`| ${e.controlId} | ${e.artifact} | ${e.collectionMethod} | ${e.responsibleParty} | ${e.acceptanceCriteria} |`);
  }
  sections.push('');
  sections.push(`## Residual Risk Register`);
  sections.push('| ID | Source | Inherent | Residual | Treatment | Owner | Description |');
  sections.push('|---|---|---|---|---|---|---|');
  for (const r of p.residualRisks) {
    sections.push(`| ${r.id} | ${r.source} | ${r.inherentRisk} | ${r.residualRisk} | ${r.treatment} | ${r.owner} | ${r.description} |`);
  }
  sections.push('');
  sections.push(`## Security Assumptions`);
  for (const s of p.assumptions) sections.push(`- ${s.text}  \n  _Basis: ${s.basis}_`);
  sections.push('');
  if (p.clarifications.length) {
    sections.push(`## Clarification Questions`);
    for (const c of p.clarifications) sections.push(`- **${c.field}:** ${c.question}  \n  _${c.reason}_`);
    sections.push('');
  }
  return sections.join('\n');
}
