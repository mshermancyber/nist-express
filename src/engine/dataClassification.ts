// Data classification assessment — maps inputs to the standard
// enterprise four-tier model (Public / Internal / Confidential /
// Restricted) and emits handling, retention, and disposition guidance.

import { Assessment, DataClassificationAssessment, Categorization } from '../types/assessment';

export function buildDataClassification(a: Assessment, cat: Categorization): DataClassificationAssessment {
  const tags = a.data.sensitiveDataTags;
  let primary: DataClassificationAssessment['primaryClassification'] = 'Internal';
  const rationale: string[] = [];

  if (tags.length > 0 || cat.confidentialityImpact === 'High') {
    primary = 'Restricted';
    rationale.push(`Sensitive data tags present (${tags.join(', ') || 'derived from impact'}).`);
  } else if (a.data.confidentialToCompany || cat.confidentialityImpact === 'Moderate') {
    primary = 'Confidential';
    rationale.push('Information must remain confidential to the company.');
  } else if (a.data.dataCategories.includes('Public Information') && a.data.dataCategories.length === 1) {
    primary = 'Public';
    rationale.push('Only public information categories selected.');
  }

  const handling: string[] = [
    'Encrypt in transit (TLS 1.2+) and at rest (KMS CMK).',
    'Apply least privilege at IAM and resource policy layers.',
    'Log all access to audit trail with retention aligned to compliance scope.'
  ];
  if (primary === 'Restricted') {
    handling.push('Require MFA and just-in-time access for all human reads.');
    handling.push('Use dedicated CMKs and key grants per data store.');
    handling.push('No copies outside production; redact or tokenise in non-prod.');
  } else if (primary === 'Confidential') {
    handling.push('Limit non-prod copies; synthesize or mask data for development.');
  }

  const retention = a.compliance.frameworks.includes('HIPAA')
    ? '6 years minimum (HIPAA accounting of disclosures).'
    : a.compliance.frameworks.includes('PCI DSS')
    ? '1 year of immediately accessible logs; longer per record-class policy.'
    : 'Per enterprise records retention schedule.';

  const disposition = primary === 'Restricted' || primary === 'Confidential'
    ? 'Cryptographic erasure via KMS key deletion + S3 lifecycle expiry; record deletion in disposition log.'
    : 'Standard S3 lifecycle expiry; deletion logged in CloudTrail.';

  return {
    primaryClassification: primary,
    handlingRequirements: handling,
    retentionGuidance: retention,
    dispositionGuidance: disposition,
    rationale
  };
}
