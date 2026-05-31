// LINDDUN privacy threat model. Only emits findings when there is
// personal data in scope (PII / PHI / PCI / customer-information).
// Categories: Linkability, Identifiability, Non-repudiation,
// Detectability, Disclosure of information, Unawareness, Non-compliance.

import { Architecture, Assessment, LinddunFinding } from '../types/assessment';

function hasPersonalData(a: Assessment): boolean {
  return (
    a.data.sensitiveDataTags.some(t => t === 'PII' || t === 'PHI' || t === 'PCI') ||
    a.data.dataCategories.some(c => c === 'Customer Information' || c === 'Employee Information')
  );
}

export function buildLinddun(a: Assessment, arch: Architecture): LinddunFinding[] {
  if (!hasPersonalData(a)) return [];

  const findings: LinddunFinding[] = [];
  const tags = a.data.sensitiveDataTags;
  const affected = tags.length
    ? tags
    : (a.data.dataCategories.includes('Customer Information')
        ? ['Customer PII']
        : ['Employee PII']);

  const dataStores = arch.components.filter(c => c.layer === 'data');
  const logs = arch.components.filter(c => c.layer === 'logging');
  const apps = arch.components.filter(c => c.layer === 'app');
  const integrations = arch.components.filter(c => c.layer === 'integration');

  // Linkability — same individual visible across multiple records/services.
  for (const store of dataStores) {
    findings.push({
      componentId: store.id,
      componentName: store.name,
      category: 'Linkability',
      description: `Records in ${store.name} can be linked across processes or sessions, allowing re-identification by correlation of quasi-identifiers.`,
      affectedData: affected,
      recommendation: 'Use opaque per-session identifiers, separate analytics IDs from operational IDs, and minimise cross-table joins on PII.',
      mitigationControls: ['AC-3', 'AC-6', 'SC-28'],
      severity: tags.includes('PHI') || tags.includes('PCI') ? 'High' : 'Medium'
    });
  }

  // Identifiability — possible to identify a specific subject from data alone.
  findings.push({
    componentId: dataStores[0]?.id ?? 'data_rds',
    componentName: dataStores[0]?.name ?? 'Primary Database',
    category: 'Identifiability',
    description: 'Direct identifiers (name, email, ID number) are stored; combined with quasi-identifiers they re-identify individuals.',
    affectedData: affected,
    recommendation: 'Apply pseudonymisation for analytical workloads; mask direct identifiers in non-production.',
    mitigationControls: ['SC-28', 'AC-6'],
    severity: tags.includes('PHI') ? 'High' : 'Medium'
  });

  // Non-repudiation — privacy view: subject cannot deny actions that
  // were actually attributable to them.
  for (const app of apps) {
    findings.push({
      componentId: app.id,
      componentName: app.name,
      category: 'Non-repudiation',
      description: 'Audit logs in this tier permanently attribute actions to a data subject, even where the subject has a right to repudiation under privacy law.',
      affectedData: affected,
      recommendation: 'Distinguish security-relevant audit (must keep) from action logs (subject-deletable). Respect erasure requests for non-essential traces.',
      mitigationControls: ['AU-2', 'AU-3'],
      severity: 'Medium'
    });
  }

  // Detectability — observable presence of personal records.
  for (const log of logs) {
    findings.push({
      componentId: log.id,
      componentName: log.name,
      category: 'Detectability',
      description: 'Log metadata (timestamps, request paths) reveals that a subject is present in the system even without payload access.',
      affectedData: affected,
      recommendation: 'Avoid emitting raw user identifiers in log paths; use hashed correlation IDs and minimum-necessary metadata.',
      mitigationControls: ['AU-3', 'SC-28'],
      severity: 'Medium'
    });
  }

  // Disclosure of information — unauthorised observation.
  for (const integ of integrations) {
    findings.push({
      componentId: integ.id,
      componentName: integ.name,
      category: 'Disclosure of information',
      description: 'Integration carries personal data outside the trust boundary; downstream processors observe the payload.',
      affectedData: affected,
      recommendation: 'Apply data minimisation at egress, vendor DPAs (data processing agreements), and field-level encryption for sensitive elements.',
      mitigationControls: ['SC-7', 'SC-8', 'SC-28'],
      severity: tags.includes('PHI') || tags.includes('PCI') ? 'High' : 'Medium'
    });
  }

  // Unawareness — subject lacks visibility/control.
  findings.push({
    componentId: 'users',
    componentName: 'End Users',
    category: 'Unawareness',
    description: 'Data subjects may be unaware of the categories of data collected, the lawful basis, or third-party recipients.',
    affectedData: affected,
    recommendation: 'Publish a layered privacy notice; expose a self-service dashboard for access, rectification, and erasure requests.',
    mitigationControls: ['PL-2'],
    severity: 'Medium'
  });

  // Non-compliance — risk of failing a regulator's standard.
  if (a.compliance.frameworks.includes('GDPR') || a.compliance.frameworks.includes('CCPA') || tags.includes('PHI')) {
    findings.push({
      componentId: 'system',
      componentName: a.business.applicationName,
      category: 'Non-compliance',
      description: 'Regulator scope (GDPR/CCPA/HIPAA) requires demonstrable records of processing, lawful basis, and subject-rights handling.',
      affectedData: affected,
      recommendation: 'Maintain a Record of Processing Activities (RoPA), DPIA, and a documented rights-handling workflow with SLAs.',
      mitigationControls: ['PL-2', 'CA-2', 'PM-9'],
      severity: 'High'
    });
  }

  return findings;
}
