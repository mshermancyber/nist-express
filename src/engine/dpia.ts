// GDPR Article 35 Data Protection Impact Assessment generator.
// Produces a structured DPIA when GDPR is in scope (or the system
// processes PHI/PCI at scale). Output mirrors the WP29 / EDPB DPIA
// reference template.

import { Assessment, Dpia, Categorization } from '../types/assessment';

export function buildDpia(a: Assessment, cat: Categorization): Dpia | null {
  const gdpr = a.compliance.frameworks.includes('GDPR');
  const phi = a.data.sensitiveDataTags.includes('PHI');
  const pci = a.data.sensitiveDataTags.includes('PCI');
  const pii = a.data.sensitiveDataTags.includes('PII');

  // Only emit when there is a privacy mandate. ccpa is similar but
  // California law doesn't require a DPIA per se; we still emit if
  // CCPA is in scope and there is PII.
  if (!gdpr && !phi && !pci && !pii && !a.compliance.frameworks.includes('CCPA')) return null;

  const lawfulBases: string[] = [];
  if (a.business.userTypes.includes('Customers') || a.business.userTypes.includes('Public Users')) {
    lawfulBases.push('Art. 6(1)(b) — performance of a contract with the data subject');
    lawfulBases.push('Art. 6(1)(a) — consent (for optional features and marketing)');
  }
  if (a.business.userTypes.includes('Employees')) {
    lawfulBases.push('Art. 6(1)(b) — performance of the employment contract');
    lawfulBases.push('Art. 6(1)(c) — compliance with a legal obligation (payroll, tax)');
  }
  lawfulBases.push('Art. 6(1)(f) — legitimate interests (security monitoring, fraud prevention)');

  const specialCategoryBases: string[] = [];
  if (phi) {
    specialCategoryBases.push('Art. 9(2)(h) — provision of health or social care');
    specialCategoryBases.push('Art. 9(2)(a) — explicit consent (where treatment alternatives exist)');
  }

  const dataSubjectCategories: string[] = [];
  if (a.business.userTypes.includes('Customers')) dataSubjectCategories.push('Customers');
  if (a.business.userTypes.includes('Public Users')) dataSubjectCategories.push('Members of the public');
  if (a.business.userTypes.includes('Employees')) dataSubjectCategories.push('Employees and contractors');
  if (a.business.userTypes.includes('Vendors') || a.business.userTypes.includes('Partners')) dataSubjectCategories.push('Vendor/partner contacts');
  if (phi) dataSubjectCategories.push('Patients');

  const processingActivities = [
    { activity: `${a.business.applicationName} core processing`, purpose: a.business.businessProblem || 'See system description', lawfulBasis: lawfulBases[0] ?? 'Art. 6(1)(f)' },
    { activity: 'Authentication and access control', purpose: 'Identify users and enforce least-privilege access', lawfulBasis: 'Art. 6(1)(f) — legitimate interests' },
    { activity: 'Security logging and monitoring', purpose: 'Detect and respond to security incidents', lawfulBasis: 'Art. 6(1)(c) — legal obligation (security)' },
    { activity: 'Backup and disaster recovery', purpose: `Meet RTO ${a.recovery.rto} / RPO ${a.recovery.rpo}`, lawfulBasis: 'Art. 6(1)(f) — legitimate interests' }
  ];

  const dataTransfers = a.integrations.map(i => ({
    destination: i.destination,
    mechanism: `${i.protocol} (${i.authentication})`,
    safeguards: i.destination.toLowerCase().includes('us')
      ? 'EU–US Data Privacy Framework (where certified) or SCCs with Transfer Impact Assessment'
      : 'Standard Contractual Clauses (SCCs) or adequacy decision'
  }));
  if (dataTransfers.length === 0) {
    dataTransfers.push({ destination: 'No declared third-country transfers', mechanism: 'n/a', safeguards: 'n/a' });
  }

  const risks: Dpia['risks'] = [
    {
      description: 'Re-identification of data subjects from analytics workloads.',
      likelihood: 'Medium',
      severity: cat.confidentialityImpact === 'High' ? 'High' : 'Medium',
      mitigation: 'Pseudonymisation, k-anonymity for analytics, separation of operational and analytical identifiers.'
    },
    {
      description: 'Unauthorised access from over-broad employee or service principal permissions.',
      likelihood: 'Medium',
      severity: 'High',
      mitigation: 'Least privilege (AC-6), entitlement reviews, just-in-time elevation, MFA (IA-2).'
    },
    {
      description: 'Inability to satisfy data-subject rights (access, erasure, portability) within statutory deadlines.',
      likelihood: 'Medium',
      severity: 'High',
      mitigation: 'Self-service rights portal, documented rights-handling workflow with SLA, downstream-vendor coordination.'
    },
    {
      description: 'Data breach involving personal data, triggering Art. 33/34 notification.',
      likelihood: 'Low',
      severity: 'High',
      mitigation: 'Encryption at rest and in transit; incident response runbooks; rehearsed notification procedure.'
    }
  ];

  const rightsHandling = [
    { right: 'Art. 15 — Right of access', mechanism: 'Self-service data export plus controlled fulfilment for non-self-service fields.' },
    { right: 'Art. 16 — Right to rectification', mechanism: 'In-app profile editing with audit trail.' },
    { right: 'Art. 17 — Right to erasure', mechanism: 'Soft-delete with TTL; cryptographic erasure via KMS key deletion for tombstoned records.' },
    { right: 'Art. 18 — Right to restriction', mechanism: 'Flag-based suppression of further processing pending review.' },
    { right: 'Art. 20 — Right to data portability', mechanism: 'Structured machine-readable export (JSON).' },
    { right: 'Art. 21 — Right to object', mechanism: 'Honoured at the marketing/analytics boundary; legitimate-interest balancing test on file.' }
  ];

  const consultations: Dpia['consultations'] = [
    { stakeholder: 'Data Protection Officer (DPO)', concern: 'DPO must review the DPIA before production go-live.' },
    { stakeholder: 'Information Security Office', concern: 'Confirms security controls are appropriate to the impact.' }
  ];

  const conclusion: Dpia['conclusion'] =
    cat.confidentialityImpact === 'High' || phi || pci
      ? 'Acceptable with mitigations'
      : 'Acceptable';

  return {
    lawfulBases,
    specialCategoryBases,
    dataSubjectCategories,
    processingActivities,
    dataTransfers,
    risks,
    rightsHandling,
    consultations,
    conclusion
  };
}
