// NIST SP 800-60 Volume II — representative information types with
// provisional CIA impacts. We use these to derive FIPS 199 high-water-
// mark categorization from the questionnaire inputs.

import { ImpactLevel, DataCategory, SensitiveDataTag } from '../types/assessment';

export interface InfoType {
  code: string;
  name: string;
  confidentiality: ImpactLevel;
  integrity: ImpactLevel;
  availability: ImpactLevel;
  // Predicates over the assessment input that trigger inclusion
  triggers: {
    dataCategories?: DataCategory[];
    sensitiveTags?: SensitiveDataTag[];
    userTypes?: ('Public Users' | 'Customers' | 'System-to-System')[];
    requiresConfidential?: boolean;
  };
}

export const INFORMATION_TYPES: InfoType[] = [
  // C.3.5.x — Customer-facing service information types (illustrative coding)
  {
    code: 'C.3.5.1', name: 'Personal Identity and Authentication Information',
    confidentiality: 'Moderate', integrity: 'Moderate', availability: 'Moderate',
    triggers: { sensitiveTags: ['PII'] }
  },
  {
    code: 'C.3.5.2', name: 'Customer Account Records',
    confidentiality: 'Moderate', integrity: 'Moderate', availability: 'Low',
    triggers: { dataCategories: ['Customer Information'] }
  },
  {
    code: 'C.3.5.3', name: 'Customer Tax and Financial Records',
    confidentiality: 'High', integrity: 'High', availability: 'Moderate',
    triggers: { sensitiveTags: ['PCI'], dataCategories: ['Financial Data'] }
  },
  {
    code: 'C.3.5.4', name: 'Employee Personnel Records',
    confidentiality: 'Moderate', integrity: 'Moderate', availability: 'Low',
    triggers: { dataCategories: ['Employee Information'] }
  },
  {
    code: 'C.3.5.5', name: 'Protected Health Information (PHI)',
    confidentiality: 'High', integrity: 'High', availability: 'Moderate',
    triggers: { sensitiveTags: ['PHI'] }
  },
  {
    code: 'C.3.5.6', name: 'Payment Card Industry Data',
    confidentiality: 'High', integrity: 'High', availability: 'Moderate',
    triggers: { sensitiveTags: ['PCI'] }
  },
  {
    code: 'C.3.5.7', name: 'Trade Secrets and Proprietary R&D',
    confidentiality: 'High', integrity: 'High', availability: 'Moderate',
    triggers: { sensitiveTags: ['Trade Secrets'], dataCategories: ['Intellectual Property'] }
  },
  {
    code: 'C.3.5.8', name: 'Export Controlled Information',
    confidentiality: 'High', integrity: 'High', availability: 'Moderate',
    triggers: { sensitiveTags: ['Export Controlled Data'] }
  },
  {
    code: 'C.3.5.9', name: 'General Regulated Records',
    confidentiality: 'Moderate', integrity: 'High', availability: 'Moderate',
    triggers: { sensitiveTags: ['Regulated Data'] }
  },
  {
    code: 'C.2.1.1', name: 'General Operational Information',
    confidentiality: 'Low', integrity: 'Moderate', availability: 'Moderate',
    triggers: { dataCategories: ['Operational Data'] }
  },
  {
    code: 'C.2.1.2', name: 'Public Information / Public-Facing Content',
    confidentiality: 'Low', integrity: 'Moderate', availability: 'Moderate',
    triggers: { dataCategories: ['Public Information'] }
  },
  {
    code: 'C.2.1.3', name: 'Source Code and Build Artifacts',
    confidentiality: 'Moderate', integrity: 'High', availability: 'Moderate',
    triggers: { dataCategories: ['Source Code'] }
  },
  // System support / cross-cutting. These default to Moderate so they
  // don't unilaterally push moderate systems to a HIGH categorisation;
  // they raise the floor only relative to the system's own sensitivity.
  {
    code: 'D.1.1.1', name: 'System Audit and Accountability Logs',
    confidentiality: 'Moderate', integrity: 'Moderate', availability: 'Moderate',
    triggers: { requiresConfidential: true }
  },
  {
    code: 'D.1.1.2', name: 'System Configuration Data',
    confidentiality: 'Moderate', integrity: 'Moderate', availability: 'Moderate',
    triggers: { requiresConfidential: true }
  },
  {
    code: 'D.1.1.3', name: 'Cryptographic Key Material',
    confidentiality: 'Moderate', integrity: 'Moderate', availability: 'Moderate',
    triggers: { requiresConfidential: true }
  },
  // Customer / consumer touch points
  {
    code: 'C.2.2.1', name: 'Consumer Inquiry and Support Records',
    confidentiality: 'Moderate', integrity: 'Moderate', availability: 'Low',
    triggers: { userTypes: ['Customers', 'Public Users'] }
  },
  {
    code: 'C.2.2.2', name: 'Vendor and Partner Records',
    confidentiality: 'Moderate', integrity: 'Moderate', availability: 'Low',
    triggers: {}
  },
  {
    code: 'C.2.3.1', name: 'Service-to-Service Integration Data',
    confidentiality: 'Moderate', integrity: 'Moderate', availability: 'Moderate',
    triggers: { userTypes: ['System-to-System'] }
  },
  {
    code: 'C.3.4.1', name: 'Contract and Procurement Records',
    confidentiality: 'Moderate', integrity: 'Moderate', availability: 'Low',
    triggers: {}
  },
  {
    code: 'C.3.4.2', name: 'Legal and Compliance Records',
    confidentiality: 'Moderate', integrity: 'High', availability: 'Moderate',
    triggers: { sensitiveTags: ['Regulated Data'] }
  }
];

export function impactRank(level: ImpactLevel): number {
  return level === 'High' ? 3 : level === 'Moderate' ? 2 : 1;
}
export function maxImpact(a: ImpactLevel, b: ImpactLevel): ImpactLevel {
  return impactRank(a) >= impactRank(b) ? a : b;
}
