// Auditable-event catalog. Builds the recommended logging events for
// this system, tailored by data sensitivity and compliance scope.
// Every event is mapped to CIA, the source emitting it, retention,
// alerting cadence, and the controls it satisfies.

import {
  Assessment, AuditableEvent, Categorization, Architecture
} from '../types/assessment';

const RETENTION_DEFAULT_DAYS = 365;

function retentionDays(a: Assessment): number {
  if (a.advanced?.loggingRetentionDays) return a.advanced.loggingRetentionDays;
  if (a.compliance.frameworks.includes('PCI DSS')) return 365;            // 1y
  if (a.compliance.frameworks.includes('HIPAA')) return 365 * 6;          // 6y
  if (a.compliance.frameworks.includes('FedRAMP')) return 365 * 3;        // 3y
  return RETENTION_DEFAULT_DAYS;
}

export function buildAuditableEvents(a: Assessment, cat: Categorization, _arch: Architecture): AuditableEvent[] {
  const days = retentionDays(a);
  const containsSensitive = a.data.sensitiveDataTags.length > 0 || a.data.confidentialToCompany;

  const events: AuditableEvent[] = [
    {
      name: 'Successful Authentication',
      source: 'Okta + AWS IAM Identity Center',
      ciaMapping: ['C', 'I'],
      rationale: 'Establishes who accessed the system and when; foundational for non-repudiation.',
      retentionDays: days, alerting: 'On Demand', severityOnAlert: 'Info',
      controlReferences: ['AU-2', 'AU-3', 'IA-2']
    },
    {
      name: 'Failed Authentication',
      source: 'Okta + AWS IAM Identity Center',
      ciaMapping: ['C'],
      rationale: 'Threshold-based bursts indicate credential stuffing or password spray.',
      retentionDays: days, alerting: 'Real-time', severityOnAlert: 'High',
      controlReferences: ['AU-2', 'AU-6', 'IA-2', 'SI-4']
    },
    {
      name: 'MFA Enrollment / Reset',
      source: 'Okta',
      ciaMapping: ['C', 'I'],
      rationale: 'Self-service MFA changes are an attacker waypoint after credential theft.',
      retentionDays: days, alerting: 'Real-time', severityOnAlert: 'High',
      controlReferences: ['IA-5', 'AU-2']
    },
    {
      name: 'Privilege Escalation / Role Assumption',
      source: 'AWS CloudTrail',
      ciaMapping: ['C', 'I'],
      rationale: 'Detects assume-role chains, sudo events, and console role switching.',
      retentionDays: days, alerting: 'Real-time', severityOnAlert: 'High',
      controlReferences: ['AC-6', 'AU-2', 'SI-4']
    },
    {
      name: 'Administrative Login',
      source: 'AWS Systems Manager + IAM Identity Center',
      ciaMapping: ['C', 'I'],
      rationale: 'Privileged session start is high-value for forensics.',
      retentionDays: days, alerting: 'Real-time', severityOnAlert: 'High',
      controlReferences: ['AC-17', 'AU-2']
    },
    {
      name: 'IAM Policy Change',
      source: 'AWS CloudTrail',
      ciaMapping: ['C', 'I'],
      rationale: 'IAM changes are the most consequential configuration changes in AWS.',
      retentionDays: days, alerting: 'Real-time', severityOnAlert: 'Critical',
      controlReferences: ['AC-3', 'AC-6', 'CM-6']
    },
    {
      name: 'KMS Key Change / Key Usage Anomaly',
      source: 'AWS CloudTrail',
      ciaMapping: ['C', 'I'],
      rationale: 'KMS deletion, policy change, or anomalous decrypt volume is a tampering / exfiltration indicator.',
      retentionDays: days, alerting: 'Real-time', severityOnAlert: 'Critical',
      controlReferences: ['SC-12', 'SC-28', 'AU-2']
    },
    {
      name: 'Security Group / NACL Change',
      source: 'AWS Config + CloudTrail',
      ciaMapping: ['C', 'I'],
      rationale: 'Boundary changes can silently expose private resources.',
      retentionDays: days, alerting: 'Real-time', severityOnAlert: 'High',
      controlReferences: ['SC-7', 'CM-6']
    },
    {
      name: 'Configuration Change (IaC Drift)',
      source: 'AWS Config',
      ciaMapping: ['I'],
      rationale: 'Detects drift from approved IaC baseline.',
      retentionDays: days, alerting: 'Hourly', severityOnAlert: 'Warning',
      controlReferences: ['CM-2', 'CM-6']
    },
    {
      name: 'Application Errors (5xx burst)',
      source: 'CloudWatch Logs Metric Filter',
      ciaMapping: ['A'],
      rationale: 'Sustained 5xx is an availability or attack signal.',
      retentionDays: days, alerting: 'Real-time', severityOnAlert: 'High',
      controlReferences: ['SI-4', 'AU-2']
    },
    {
      name: 'Database Schema or Privilege Change',
      source: 'RDS Audit / DB Triggers',
      ciaMapping: ['I'],
      rationale: 'DDL and GRANT activity on the data tier requires explicit audit.',
      retentionDays: days, alerting: 'Real-time', severityOnAlert: 'High',
      controlReferences: ['AU-2', 'SI-7']
    },
    {
      name: 'Data Export Event',
      source: 'Application Logs',
      ciaMapping: ['C'],
      rationale: 'Bulk download or report export can indicate data exfiltration.',
      retentionDays: days, alerting: 'Real-time', severityOnAlert: containsSensitive ? 'Critical' : 'High',
      controlReferences: ['AU-2', 'AC-6', 'SI-4']
    },
    {
      name: 'Backup Failure',
      source: 'AWS Backup',
      ciaMapping: ['A'],
      rationale: 'Silent backup failure defeats the recovery plan.',
      retentionDays: days, alerting: 'Real-time', severityOnAlert: 'High',
      controlReferences: ['CP-9', 'CP-10']
    },
    {
      name: 'Restore Operation',
      source: 'AWS Backup',
      ciaMapping: ['I', 'A'],
      rationale: 'Restore events are forensically significant.',
      retentionDays: days, alerting: 'Real-time', severityOnAlert: 'High',
      controlReferences: ['CP-10', 'AU-2']
    },
    {
      name: 'WAF Block / Rate-Based Trip',
      source: 'AWS WAF',
      ciaMapping: ['C', 'A'],
      rationale: 'Indicates attempted attack patterns reaching the edge.',
      retentionDays: days, alerting: 'Hourly', severityOnAlert: 'Warning',
      controlReferences: ['SC-7', 'SI-10', 'SI-4']
    },
    {
      name: 'API Abuse / Throttling',
      source: 'API Gateway',
      ciaMapping: ['A'],
      rationale: 'Sustained throttle activity is a DoS or abuse indicator.',
      retentionDays: days, alerting: 'Hourly', severityOnAlert: 'Warning',
      controlReferences: ['SC-7', 'SI-4']
    },
    {
      name: 'CloudTrail Tampering / Disablement',
      source: 'AWS CloudTrail',
      ciaMapping: ['I'],
      rationale: 'Attackers attempt to disable trails before/while operating.',
      retentionDays: days, alerting: 'Real-time', severityOnAlert: 'Critical',
      controlReferences: ['AU-9', 'SI-4']
    },
    {
      name: 'GuardDuty Finding (any severity ≥ Medium)',
      source: 'Amazon GuardDuty',
      ciaMapping: ['C', 'I', 'A'],
      rationale: 'Native threat detection across CloudTrail / VPC Flow / DNS / EKS.',
      retentionDays: days, alerting: 'Real-time', severityOnAlert: 'High',
      controlReferences: ['SI-4', 'AU-6']
    },
    {
      name: 'Secrets Manager Access (non-application principal)',
      source: 'AWS CloudTrail',
      ciaMapping: ['C'],
      rationale: 'Human or unexpected role reading secrets is high-signal.',
      retentionDays: days, alerting: 'Real-time', severityOnAlert: 'High',
      controlReferences: ['IA-5', 'AC-6']
    },
    {
      name: 'S3 Public Access Granted',
      source: 'AWS Config + CloudTrail',
      ciaMapping: ['C'],
      rationale: 'Single most common AWS data-exposure misconfiguration.',
      retentionDays: days, alerting: 'Real-time', severityOnAlert: 'Critical',
      controlReferences: ['SC-7', 'AC-3', 'CM-6']
    }
  ];

  // Sensitivity-driven additions
  if (a.data.sensitiveDataTags.includes('PCI')) {
    events.push({
      name: 'Cardholder Data Element Access',
      source: 'Application Logs',
      ciaMapping: ['C'],
      rationale: 'PCI DSS req 10 — track all individual access to cardholder data.',
      retentionDays: 365, alerting: 'Real-time', severityOnAlert: 'High',
      controlReferences: ['AU-2', 'AU-3', 'SC-28']
    });
  }
  if (a.data.sensitiveDataTags.includes('PHI')) {
    events.push({
      name: 'PHI Record Access / Disclosure',
      source: 'Application Logs',
      ciaMapping: ['C'],
      rationale: 'HIPAA accounting-of-disclosures requirement.',
      retentionDays: 365 * 6, alerting: 'On Demand', severityOnAlert: 'Info',
      controlReferences: ['AU-2', 'AU-3', 'AC-3']
    });
  }
  if (cat.availabilityImpact === 'High') {
    events.push({
      name: 'Multi-Region Failover Triggered',
      source: 'Route 53 + Custom Application Health',
      ciaMapping: ['A'],
      rationale: 'High-availability tier requires explicit failover audit.',
      retentionDays: days, alerting: 'Real-time', severityOnAlert: 'Critical',
      controlReferences: ['CP-2', 'CP-10']
    });
  }

  return events;
}
