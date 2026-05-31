import { Assessment } from '../src/types/assessment';

export function sampleAssessment(overrides: Partial<Assessment> = {}): Assessment {
  const now = new Date().toISOString();
  return {
    id: 'test-asmt-001',
    createdAt: now,
    updatedAt: now,
    status: 'draft',
    business: {
      applicationName: 'Customer Onboarding Portal',
      businessProblem: 'Speeds up onboarding for new retail customers and reduces manual data entry errors.',
      userTypes: ['Customers', 'Employees'],
      userInteractionDescription: 'Customers fill out a web form; reviewers approve in a back-office app.'
    },
    data: {
      dataCategories: ['Customer Information', 'Financial Data'],
      confidentialToCompany: true,
      sensitiveDataTags: ['PII', 'PCI']
    },
    impact: {
      confidentialityWorstCase: 'Regulatory fines, breach notification, and customer trust loss.',
      integrityWorstCase: 'Approval decisions made on corrupted data could create financial loss.',
      availabilityWorstCase: 'Revenue loss and customer drop-off.'
    },
    recovery: { rto: '1 Hour', rpo: '15 Minutes' },
    population: { userCount: '10000+', expectedGrowth: '20% YoY' },
    integrations: [
      { source: 'Onboarding Portal', destination: 'Salesforce', protocol: 'HTTPS', authentication: 'OAuth2', dataDirection: 'bidirectional' }
    ],
    compliance: { frameworks: ['SOC2', 'PCI DSS', 'NIST 800-53'] },
    hosting: { model: 'AWS' },
    ...overrides
  };
}
