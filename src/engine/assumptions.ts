// Security Assumptions and Constraints. Each assumption cites the
// basis (specific input in the assessment). The ARB reviews these to
// confirm they hold; if any fails, the SSP and threat model may
// require revision.

import { Assessment, SecurityAssumption, Categorization } from '../types/assessment';

export function buildAssumptions(a: Assessment, cat: Categorization): SecurityAssumption[] {
  const out: SecurityAssumption[] = [];

  out.push({
    text: 'Okta is the authoritative IdP and is operated under its own SOC2 attestation.',
    basis: 'Standard enterprise identity model; questionnaire confirms confidentiality intent.'
  });
  out.push({
    text: 'AWS shared-responsibility model applies — provider responsibilities (physical, hypervisor, AWS-managed services) are inherited.',
    basis: `Hosting model: ${a.hosting.model}.`
  });
  out.push({
    text: 'No customer data leaves the declared AWS region(s) except via explicitly declared integrations.',
    basis: 'Architecture engine omits cross-region replication unless availability or recovery requires it.'
  });
  out.push({
    text: 'All cryptographic operations use FIPS 140-validated modules via AWS KMS.',
    basis: 'KMS CMKs are the default crypto provider in the generated architecture.'
  });
  if (a.data.confidentialToCompany) {
    out.push({
      text: 'MFA is enforced for every human authentication path.',
      basis: 'Confidentiality requirement = Yes.'
    });
  }
  if (cat.availabilityImpact === 'High') {
    out.push({
      text: 'Recovery objectives (RTO/RPO) are supported by tested runbooks and automation.',
      basis: 'Availability impact = High; assumption requires evidence to confirm.'
    });
  }
  if (a.integrations.length > 0) {
    out.push({
      text: 'Declared integrations apply equivalent or stronger security controls on their side.',
      basis: 'Vendor risk review is a separate process; this assessment trusts attestation.'
    });
  }
  out.push({
    text: 'Personnel with access have completed required role-based training and background screening.',
    basis: 'Common controls inherited from PS-3 and AT-2/AT-3.'
  });
  return out;
}
