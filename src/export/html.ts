// Self-contained HTML renderer for the ARB package. Includes the
// stylesheet inline and renders Mermaid client-side from a CDN — when
// the user opens the file offline, the diagrams degrade to plain code
// blocks but every other section is readable.

import { Assessment, ArbPackage } from '../types/assessment';

function escape(s: string): string {
  return s.replace(/[&<>"']/g, c => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  }[c]!));
}

function row(...cells: (string | number)[]): string {
  return `<tr>${cells.map(c => `<td>${escape(String(c))}</td>`).join('')}</tr>`;
}

function bullets(items: string[]): string {
  if (!items.length) return '<p><em>None</em></p>';
  return '<ul>' + items.map(i => `<li>${escape(i)}</li>`).join('') + '</ul>';
}

const STYLE = `
:root { color-scheme: dark; }
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
  background: #0b1220; color: #e2e8f0; margin: 0; padding: 2rem; line-height: 1.5; }
h1, h2, h3 { color: #93c5fd; }
h1 { border-bottom: 2px solid #1e293b; padding-bottom: .5rem; }
h2 { margin-top: 2.5rem; border-bottom: 1px solid #1e293b; padding-bottom: .25rem; }
section { background: #0f172a; border: 1px solid #1e293b; border-radius: 8px; padding: 1rem 1.5rem; margin-bottom: 1.5rem; }
table { width: 100%; border-collapse: collapse; margin: .5rem 0; font-size: .9rem; }
th, td { border: 1px solid #1e293b; padding: .5rem; text-align: left; vertical-align: top; }
th { background: #1e293b; color: #93c5fd; }
.badge { display: inline-block; padding: .15rem .5rem; border-radius: 4px; font-size: .8rem; }
.badge.low { background: #064e3b; color: #d1fae5; }
.badge.med { background: #78350f; color: #fed7aa; }
.badge.high { background: #7f1d1d; color: #fecaca; }
.badge.crit { background: #450a0a; color: #fca5a5; }
.posture { font-size: 1.1rem; font-weight: bold; }
pre.mermaid { background: #020617; padding: 1rem; border-radius: 6px; overflow: auto; }
.muted { color: #94a3b8; font-size: .9rem; }
.kv { display: grid; grid-template-columns: 200px 1fr; gap: .25rem 1rem; margin: .5rem 0; }
.kv dt { color: #93c5fd; font-weight: 600; }
.kv dd { margin: 0; }
@media print { body { background: white; color: black; } section { background: white; border-color: #ccc; } h1,h2,h3 { color: #1e3a8a; } th { background: #e0e7ff; color: #1e3a8a; } }
`;

function riskBadge(r: string): string {
  const cls = r === 'Critical' ? 'crit' : r === 'High' ? 'high' : r === 'Medium' ? 'med' : 'low';
  return `<span class="badge ${cls}">${escape(r)}</span>`;
}

export function renderHtml(a: Assessment, p: ArbPackage): string {
  const inh = p.threatModel.reduce((acc, t) => { acc[t.inherentRisk] = (acc[t.inherentRisk] ?? 0) + 1; return acc; }, {} as Record<string, number>);
  const res = p.threatModel.reduce((acc, t) => { acc[t.residualRisk] = (acc[t.residualRisk] ?? 0) + 1; return acc; }, {} as Record<string, number>);

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<title>${escape(a.business.applicationName)} — ARB Package</title>
<style>${STYLE}</style>
<script src="/lib/mermaid.min.js"></script>
<script>
  window.mermaid && window.mermaid.initialize({ startOnLoad: true, theme: 'dark' });
</script>
</head>
<body>
<h1>${escape(a.business.applicationName)}</h1>
<p class="muted">Architecture Review Board package — generated ${escape(p.generatedAt)}</p>

<section>
  <h2>Executive Summary</h2>
  <p class="posture">${escape(p.executiveSummary.oneLiner)}</p>
  <p>${escape(p.executiveSummary.businessContext)}</p>
  <dl class="kv">
    <dt>Risk posture</dt><dd>${escape(p.executiveSummary.riskPosture)}</dd>
    <dt>Recommendation</dt><dd>${escape(p.executiveSummary.goNoGoAdvice)}</dd>
  </dl>
  <h3>Conditions</h3>${bullets(p.executiveSummary.conditions)}
  <h3>Top Residual Risks</h3>${bullets(p.executiveSummary.topRisks)}
  <h3>Key Recommendations</h3>${bullets(p.executiveSummary.keyRecommendations)}
</section>

<section>
  <h2>FIPS 199 Categorization</h2>
  <dl class="kv">
    <dt>Confidentiality</dt><dd>${escape(p.categorization.confidentialityImpact)}</dd>
    <dt>Integrity</dt><dd>${escape(p.categorization.integrityImpact)}</dd>
    <dt>Availability</dt><dd>${escape(p.categorization.availabilityImpact)}</dd>
    <dt>Overall</dt><dd><strong>${escape(p.categorization.overallCategorization)}</strong> (high-water mark)</dd>
  </dl>
  <h3>Rationale</h3>${bullets(p.categorization.rationale)}
  <h3>Information Types (NIST 800-60)</h3>
  <table><thead><tr><th>Code</th><th>Name</th><th>C</th><th>I</th><th>A</th><th>Basis</th></tr></thead><tbody>
  ${p.categorization.informationTypes.map(i => row(i.code, i.name, i.confidentiality, i.integrity, i.availability, i.basisInAssessment)).join('')}
  </tbody></table>
</section>

<section>
  <h2>Data Classification</h2>
  <p><strong>Primary classification:</strong> ${escape(p.dataClassification.primaryClassification)}</p>
  <h3>Handling Requirements</h3>${bullets(p.dataClassification.handlingRequirements)}
  <p><strong>Retention:</strong> ${escape(p.dataClassification.retentionGuidance)}</p>
  <p><strong>Disposition:</strong> ${escape(p.dataClassification.dispositionGuidance)}</p>
</section>

<section>
  <h2>Architecture Diagram</h2>
  <pre class="mermaid">${escape(p.architectureDiagramMermaid)}</pre>
  <h2>Security Overlay</h2>
  <pre class="mermaid">${escape(p.securityOverlayDiagramMermaid)}</pre>
  <h2>Data Flow Diagram</h2>
  <pre class="mermaid">${escape(p.dataFlowDiagramMermaid)}</pre>
  <h3>Components</h3>
  <table><thead><tr><th>Component</th><th>Layer</th><th>AWS Service</th><th>Trust Zone</th><th>Sensitive</th><th>Rationale</th></tr></thead><tbody>
  ${p.architecture.components.map(c => row(c.name, c.layer, c.awsService ?? '—', c.trustZone, c.containsSensitiveData ? 'yes' : 'no', c.rationale)).join('')}
  </tbody></table>
  <h3>Architecture Rationale</h3>${bullets(p.architecture.rationale)}
</section>

<section>
  <h2>STRIDE Threat Model</h2>
  <p>Inherent: ${Object.entries(inh).map(([k, v]) => `${riskBadge(k)} ${v}`).join(' · ')} &nbsp;|&nbsp;
     Residual: ${Object.entries(res).map(([k, v]) => `${riskBadge(k)} ${v}`).join(' · ')}</p>
  <table><thead><tr><th>Component</th><th>Category</th><th>Likelihood</th><th>Impact</th><th>Inherent</th><th>Residual</th><th>Mitigations</th></tr></thead><tbody>
  ${p.threatModel.map(t => `<tr><td>${escape(t.componentName)}</td><td>${escape(t.category)}</td><td>${escape(t.likelihood)}</td><td>${escape(t.impact)}</td><td>${riskBadge(t.inherentRisk)}</td><td>${riskBadge(t.residualRisk)}</td><td>${escape(t.mitigations.join(', '))}</td></tr>`).join('')}
  </tbody></table>
</section>

<section>
  <h2>Operational Threat Model</h2>
  <table><thead><tr><th>Category</th><th>Likelihood</th><th>Impact</th><th>Description</th><th>Recommendation</th><th>Controls</th></tr></thead><tbody>
  ${p.operationalThreatModel.map(o => row(o.category, o.likelihood, o.impact, o.description, o.recommendation, o.controlReferences.join(', '))).join('')}
  </tbody></table>
</section>

<section>
  <h2>System Security Plan (NIST 800-53 Rev 5)</h2>
  ${p.ssp.map(c => `
    <details open>
      <summary><strong>${escape(c.id)} — ${escape(c.name)}</strong> <span class="muted">(${escape(c.family)}) ${escape(c.inheritance)} · ${escape(c.implementationStatus)}</span></summary>
      <p><strong>Implementation:</strong> ${escape(c.implementationStatement)}</p>
      <p><strong>Evidence:</strong> ${escape(c.evidence.join('; '))}</p>
      <p><strong>CIS v8:</strong> ${escape(c.cisMappings.join(', ') || '—')} &nbsp;|&nbsp;
         <strong>Responsible:</strong> ${escape(c.responsibleParty)}</p>
      <p class="muted"><strong>Rationale:</strong> ${escape(c.rationale)}</p>
      <p class="muted"><strong>Assessment Guidance:</strong> ${escape(c.assessmentGuidance)}</p>
    </details>`).join('')}
</section>

<section>
  <h2>Auditable Events</h2>
  <table><thead><tr><th>Event</th><th>Source</th><th>CIA</th><th>Retention</th><th>Alerting</th><th>Severity</th><th>Controls</th></tr></thead><tbody>
  ${p.auditableEvents.map(e => row(e.name, e.source, e.ciaMapping.join('/'), `${e.retentionDays}d`, e.alerting, e.severityOnAlert, e.controlReferences.join(', '))).join('')}
  </tbody></table>
</section>

<section>
  <h2>Recovery Assessment</h2>
  <dl class="kv">
    <dt>RTO / RPO</dt><dd>${escape(p.recovery.rto)} / ${escape(p.recovery.rpo)}</dd>
    <dt>Availability Tier</dt><dd>${escape(p.recovery.availabilityTier)}</dd>
    <dt>Multi-AZ / Multi-Region</dt><dd>${p.recovery.multiAz ? 'yes' : 'no'} / ${p.recovery.multiRegion ? 'yes' : 'no'}</dd>
    <dt>Backup Strategy</dt><dd>${escape(p.recovery.backupStrategy)}</dd>
    <dt>Restore Testing</dt><dd>${escape(p.recovery.restoreTestingCadence)}</dd>
    <dt>Failover Approach</dt><dd>${escape(p.recovery.failoverApproach)}</dd>
  </dl>
  <h3>Gaps</h3>${bullets(p.recovery.gaps)}
  <h3>Recommendations</h3>${bullets(p.recovery.recommendations)}
</section>

<section>
  <h2>Compliance Mapping</h2>
  <table><thead><tr><th>Framework</th><th>Control</th><th>Description</th><th>Coverage</th><th>NIST Controls</th></tr></thead><tbody>
  ${p.complianceMappings.map(m => row(m.framework, m.controlId, m.description, m.coverage, m.satisfiedByControlIds.join(', ') || '—')).join('')}
  </tbody></table>
</section>

<section>
  <h2>AWS Well-Architected Scoring</h2>
  ${p.wellArchitected.map(w => `
    <h3>${escape(w.pillar)}: ${w.score}/100</h3>
    <p><strong>Findings:</strong></p>${bullets(w.findings)}
    <p><strong>Recommendations:</strong></p>${bullets(w.recommendations)}`).join('')}
</section>

<section>
  <h2>Evidence Requests</h2>
  <table><thead><tr><th>Control</th><th>Artifact</th><th>Method</th><th>Responsible</th><th>Acceptance</th></tr></thead><tbody>
  ${p.evidenceRequests.map(e => row(e.controlId, e.artifact, e.collectionMethod, e.responsibleParty, e.acceptanceCriteria)).join('')}
  </tbody></table>
</section>

<section>
  <h2>Residual Risk Register</h2>
  <table><thead><tr><th>ID</th><th>Source</th><th>Inherent</th><th>Residual</th><th>Treatment</th><th>Owner</th><th>Description</th></tr></thead><tbody>
  ${p.residualRisks.map(r => `<tr><td>${escape(r.id)}</td><td>${escape(r.source)}</td><td>${riskBadge(r.inherentRisk)}</td><td>${riskBadge(r.residualRisk)}</td><td>${escape(r.treatment)}</td><td>${escape(r.owner)}</td><td>${escape(r.description)}</td></tr>`).join('')}
  </tbody></table>
</section>

<section>
  <h2>Security Assumptions</h2>
  <ul>${p.assumptions.map(s => `<li>${escape(s.text)}<br/><span class="muted">Basis: ${escape(s.basis)}</span></li>`).join('')}</ul>
</section>

${p.clarifications.length ? `
<section>
  <h2>Clarification Questions</h2>
  <ul>${p.clarifications.map(c => `<li><strong>${escape(c.field)}:</strong> ${escape(c.question)}<br/><span class="muted">${escape(c.reason)}</span></li>`).join('')}</ul>
</section>` : ''}

${!p.validationReport.passed ? `
<section>
  <h2>Validation Issues</h2>
  <ul>${p.validationReport.issues.map(i => `<li><strong>[${escape(i.severity)}]</strong> ${escape(i.field)}: ${escape(i.message)}</li>`).join('')}</ul>
</section>` : ''}

</body></html>`;
}
