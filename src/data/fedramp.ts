// FedRAMP Rev 5 baseline definitions. Defines the LOW, MODERATE, and
// HIGH control selections + the FedRAMP-defined organizational
// parameters that override generic 800-53 defaults. This is what
// distinguishes a FedRAMP baseline from a vanilla 800-53 baseline:
// FedRAMP pins parameter values (retention windows, MFA strengths,
// recovery objectives, etc.) so every authorization is comparable.

import { ImpactLevel } from '../types/assessment';

export type FedrampBaseline = 'LOW' | 'MODERATE' | 'HIGH' | 'LI-SaaS';

export interface FedrampParameter {
  controlId: string;
  paramId: string;         // e.g. AC-2(j)[1]
  value: string;           // FedRAMP-defined value or selection
  appliesTo: FedrampBaseline[];
}

// FedRAMP-defined parameter values. These are the values FedRAMP
// mandates regardless of the customer's local preference (where
// customer-defined is permitted FedRAMP still publishes a minimum).
export const FEDRAMP_PARAMETERS: FedrampParameter[] = [
  // Audit retention
  { controlId: 'AU-11', paramId: 'AU-11', value: 'at least 3 years online + 12 years archived (FedRAMP minimum)', appliesTo: ['LOW', 'MODERATE', 'HIGH', 'LI-SaaS'] },
  // Authenticator lifetime / MFA
  { controlId: 'IA-2', paramId: 'IA-2(1)', value: 'MFA required for all privileged accounts (FedRAMP)', appliesTo: ['LOW', 'MODERATE', 'HIGH', 'LI-SaaS'] },
  { controlId: 'IA-2', paramId: 'IA-2(2)', value: 'MFA required for all non-privileged accounts (FedRAMP)', appliesTo: ['MODERATE', 'HIGH'] },
  { controlId: 'IA-2', paramId: 'IA-2(6)', value: 'Phishing-resistant MFA required for privileged accounts at HIGH', appliesTo: ['HIGH'] },
  // Session timeouts
  { controlId: 'AC-11', paramId: 'AC-11(a)', value: '15 minutes (FedRAMP)', appliesTo: ['LOW', 'MODERATE', 'HIGH', 'LI-SaaS'] },
  { controlId: 'AC-12', paramId: 'AC-12', value: '15 minutes inactivity (FedRAMP)', appliesTo: ['MODERATE', 'HIGH'] },
  // Password
  { controlId: 'IA-5', paramId: 'IA-5(1)(a)', value: 'NIST SP 800-63B Memorized Secret Verifier', appliesTo: ['LOW', 'MODERATE', 'HIGH'] },
  // Unsuccessful logon
  { controlId: 'AC-7', paramId: 'AC-7(a)', value: 'Lock after 3 consecutive invalid attempts (FedRAMP)', appliesTo: ['LOW', 'MODERATE', 'HIGH'] },
  { controlId: 'AC-7', paramId: 'AC-7(b)', value: 'Lock for 30 minutes (FedRAMP)', appliesTo: ['LOW', 'MODERATE', 'HIGH'] },
  // Patching
  { controlId: 'SI-2', paramId: 'SI-2(c)', value: 'High-severity flaws within 30 days; moderate within 90 days (FedRAMP)', appliesTo: ['LOW', 'MODERATE', 'HIGH'] },
  // Backup
  { controlId: 'CP-9', paramId: 'CP-9', value: 'Backups encrypted with FIPS 140-validated crypto', appliesTo: ['LOW', 'MODERATE', 'HIGH'] },
  // Contingency plan testing
  { controlId: 'CP-4', paramId: 'CP-4(a)', value: 'Test at least annually (FedRAMP)', appliesTo: ['LOW', 'MODERATE', 'HIGH'] },
  // Continuous Monitoring frequencies
  { controlId: 'CA-7', paramId: 'CA-7', value: 'Vulnerability scanning monthly (operating system, web, database)', appliesTo: ['LOW', 'MODERATE', 'HIGH'] },
  { controlId: 'RA-5', paramId: 'RA-5(a)', value: 'Authenticated OS scans monthly; web/db monthly', appliesTo: ['LOW', 'MODERATE', 'HIGH'] },
  // Cryptography
  { controlId: 'SC-13', paramId: 'SC-13', value: 'FIPS-validated cryptographic modules required', appliesTo: ['LOW', 'MODERATE', 'HIGH'] },
  // Account management
  { controlId: 'AC-2', paramId: 'AC-2(j)', value: 'Review accounts at least annually; privileged at least quarterly', appliesTo: ['LOW', 'MODERATE', 'HIGH'] },
  // Incident response
  { controlId: 'IR-6', paramId: 'IR-6(a)', value: 'Report to US-CERT within 1 hour of discovery', appliesTo: ['LOW', 'MODERATE', 'HIGH'] },
  // Security training
  { controlId: 'AT-2', paramId: 'AT-2(c)', value: 'Awareness training annually + on significant change', appliesTo: ['LOW', 'MODERATE', 'HIGH'] }
];

// FedRAMP Rev 5 baseline membership. This is the curated minimum
// each baseline requires beyond the 800-53 baselines.
// Source: FedRAMP Baselines (Rev 5, May 2023).
const FEDRAMP_LOW = new Set<string>([
  'AC-1', 'AC-2', 'AC-3', 'AC-7', 'AC-8', 'AC-14', 'AC-17', 'AC-18', 'AC-19', 'AC-20', 'AC-22',
  'AT-1', 'AT-2', 'AT-3', 'AT-4',
  'AU-1', 'AU-2', 'AU-3', 'AU-4', 'AU-5', 'AU-6', 'AU-8', 'AU-9', 'AU-11', 'AU-12',
  'CA-1', 'CA-2', 'CA-3', 'CA-5', 'CA-6', 'CA-7', 'CA-9',
  'CM-1', 'CM-2', 'CM-4', 'CM-5', 'CM-6', 'CM-7', 'CM-8', 'CM-10', 'CM-11',
  'CP-1', 'CP-2', 'CP-3', 'CP-4', 'CP-9', 'CP-10',
  'IA-1', 'IA-2', 'IA-4', 'IA-5', 'IA-6', 'IA-7', 'IA-8', 'IA-11',
  'IR-1', 'IR-2', 'IR-4', 'IR-5', 'IR-6', 'IR-7', 'IR-8',
  'MA-1', 'MA-2', 'MA-4', 'MA-5',
  'MP-1', 'MP-2', 'MP-6', 'MP-7',
  'PE-1', 'PE-2', 'PE-3', 'PE-6', 'PE-12', 'PE-13', 'PE-14',
  'PL-1', 'PL-2', 'PL-4', 'PL-10', 'PL-11',
  'PM-1', 'PM-2', 'PM-5', 'PM-7', 'PM-9', 'PM-11', 'PM-14',
  'PS-1', 'PS-2', 'PS-3', 'PS-4', 'PS-5', 'PS-6', 'PS-7', 'PS-8',
  'PT-1', 'PT-2', 'PT-3', 'PT-5',
  'RA-1', 'RA-2', 'RA-3', 'RA-5', 'RA-7',
  'SA-1', 'SA-2', 'SA-3', 'SA-4', 'SA-9', 'SA-22',
  'SC-1', 'SC-5', 'SC-7', 'SC-12', 'SC-13', 'SC-15', 'SC-20', 'SC-21', 'SC-22', 'SC-39',
  'SI-1', 'SI-2', 'SI-3', 'SI-4', 'SI-5', 'SI-12',
  'SR-1', 'SR-2', 'SR-3', 'SR-5', 'SR-8', 'SR-10', 'SR-11', 'SR-12'
]);

const FEDRAMP_MODERATE = new Set<string>([
  ...Array.from(FEDRAMP_LOW),
  'AC-4', 'AC-5', 'AC-6', 'AC-11', 'AC-12', 'AC-21',
  'AU-7', 'AU-13', 'AU-14',
  'CM-3', 'CM-9', 'CM-12',
  'CP-6', 'CP-7', 'CP-8',
  'IA-3', 'IA-12',
  'IR-3',
  'MA-3',
  'MP-4', 'MP-5',
  'PL-8',
  'PT-4', 'PT-7',
  'RA-9',
  'SA-8', 'SA-10', 'SA-11',
  'SC-2', 'SC-4', 'SC-8', 'SC-10', 'SC-17', 'SC-18', 'SC-23', 'SC-28',
  'SI-6', 'SI-7', 'SI-8', 'SI-10', 'SI-11', 'SI-16',
  'SR-4', 'SR-6'
]);

const FEDRAMP_HIGH = new Set<string>([
  ...Array.from(FEDRAMP_MODERATE),
  'AU-10',
  'PT-8',
  'RA-10',
  'SA-15', 'SA-17',
  'SI-13'
]);

// LI-SaaS (Low Impact SaaS) — FedRAMP's small-footprint SaaS profile.
// Requires a curated subset of LOW with tighter parameters.
const FEDRAMP_LI_SAAS = new Set<string>([
  'AC-1', 'AC-2', 'AC-3', 'AC-7', 'AC-8', 'AC-14', 'AC-17', 'AC-20', 'AC-22',
  'AT-2', 'AT-3',
  'AU-2', 'AU-3', 'AU-5', 'AU-6', 'AU-8', 'AU-9', 'AU-11', 'AU-12',
  'CA-2', 'CA-3', 'CA-5', 'CA-6', 'CA-7',
  'CM-2', 'CM-6', 'CM-7', 'CM-8',
  'CP-2', 'CP-9', 'CP-10',
  'IA-2', 'IA-4', 'IA-5', 'IA-6', 'IA-8',
  'IR-4', 'IR-6', 'IR-8',
  'MP-2', 'MP-6',
  'PL-2',
  'PS-3',
  'RA-3', 'RA-5',
  'SA-4', 'SA-9',
  'SC-7', 'SC-12', 'SC-13',
  'SI-2', 'SI-3', 'SI-4', 'SI-5'
]);

export function fedrampBaselineControls(baseline: FedrampBaseline): Set<string> {
  switch (baseline) {
    case 'LOW': return FEDRAMP_LOW;
    case 'MODERATE': return FEDRAMP_MODERATE;
    case 'HIGH': return FEDRAMP_HIGH;
    case 'LI-SaaS': return FEDRAMP_LI_SAAS;
  }
}

export function fedrampBaselineForImpact(level: ImpactLevel): FedrampBaseline {
  if (level === 'High') return 'HIGH';
  if (level === 'Moderate') return 'MODERATE';
  return 'LOW';
}

export function fedrampParametersFor(controlId: string, baseline: FedrampBaseline): FedrampParameter[] {
  return FEDRAMP_PARAMETERS.filter(p => p.controlId === controlId && p.appliesTo.includes(baseline));
}
