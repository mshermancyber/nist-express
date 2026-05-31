// Evidence request generator — for every SSP control, produces a
// concrete artifact the assessor will ask for, the collection method,
// the responsible party, and acceptance criteria. Auditors typically
// receive these as a pre-assessment evidence request list.

import { EvidenceRequest, SspControl } from '../types/assessment';

interface Template {
  artifact: string;
  collectionMethod: string;
  acceptanceCriteria: string;
}

const TEMPLATES: Record<string, Template> = {
  'AC-2': {
    artifact: 'Account inventory with privilege type, owner, and last review date',
    collectionMethod: 'Export from Okta + AWS IAM Identity Center',
    acceptanceCriteria: 'All in-scope accounts present; review date within 90 days; orphaned accounts annotated.'
  },
  'AC-3': {
    artifact: 'Sample authorization decision logs for 10 privileged operations',
    collectionMethod: 'CloudTrail + application authorizer logs',
    acceptanceCriteria: 'Every sample shows explicit allow/deny with principal, resource, action.'
  },
  'AC-6': {
    artifact: 'IAM policy export and unused-permission scan',
    collectionMethod: 'IAM Access Analyzer + IAM CSV export',
    acceptanceCriteria: 'No wildcard actions on sensitive resources; <5% unused permissions; documented exceptions only.'
  },
  'AC-17': {
    artifact: 'Bastion-free remote-access configuration',
    collectionMethod: 'AWS Systems Manager Session Manager logs + permission set definitions',
    acceptanceCriteria: 'No SSH inbound; all remote sessions logged; MFA verified at IdP.'
  },
  'AU-2': {
    artifact: 'Logged-events catalog with source and retention',
    collectionMethod: 'Export from logging architecture documentation',
    acceptanceCriteria: 'All required event types from the auditable-events catalog are present.'
  },
  'AU-3': {
    artifact: 'Sample log records (CloudTrail + application)',
    collectionMethod: 'CloudWatch Logs Insights query export',
    acceptanceCriteria: 'Each sample contains who, what, when, where, outcome.'
  },
  'AU-6': {
    artifact: 'Detection rule inventory + SLA evidence',
    collectionMethod: 'Security Hub + SOAR export',
    acceptanceCriteria: 'Detection rules cover catalog events; triage SLAs met for sample period.'
  },
  'AU-9': {
    artifact: 'Log-archive bucket policy and Object Lock configuration',
    collectionMethod: 'aws s3api get-bucket-policy + get-object-lock-configuration',
    acceptanceCriteria: 'Compliance mode object lock; key deletion denied; KMS key policy restricts access.'
  },
  'AU-12': {
    artifact: 'Coverage report mapping components → log destination',
    collectionMethod: 'Architecture map + CloudWatch Logs groups inventory',
    acceptanceCriteria: 'No component is unlogged unless documented exception with compensating control.'
  },
  'CA-7': {
    artifact: 'Continuous monitoring strategy + most recent monthly report',
    collectionMethod: 'Compliance program export',
    acceptanceCriteria: 'Metrics defined; reporting cadence followed for last 3 cycles.'
  },
  'CM-2': {
    artifact: 'IaC repository link + drift detection report',
    collectionMethod: 'Git URL + AWS Config drift detection',
    acceptanceCriteria: 'IaC is authoritative; drift triggers alert within 24h.'
  },
  'CM-6': {
    artifact: 'AWS Config conformance pack compliance summary',
    collectionMethod: 'AWS Config console export',
    acceptanceCriteria: '≥95% compliance on CIS AWS Foundations; remediation plan for the rest.'
  },
  'CM-7': {
    artifact: 'Open ports and exposed services inventory',
    collectionMethod: 'Security Group + ALB listener export',
    acceptanceCriteria: 'No port open without business justification.'
  },
  'CM-8': {
    artifact: 'System component inventory with versions',
    collectionMethod: 'AWS Config inventory + container image manifest',
    acceptanceCriteria: 'Inventory updated within 24h of change; reconciled against IaC.'
  },
  'CP-2': {
    artifact: 'Contingency plan document with named owner and revision history',
    collectionMethod: 'Document repository link',
    acceptanceCriteria: 'Reviewed/approved within last 12 months; aligns with RTO/RPO.'
  },
  'CP-9': {
    artifact: 'Backup schedule + most recent successful-backup report',
    collectionMethod: 'AWS Backup audit manager export',
    acceptanceCriteria: 'Backup success ≥99%; backup encryption verified.'
  },
  'CP-10': {
    artifact: 'Restore drill report with measured RTO/RPO',
    collectionMethod: 'Game-day notes + monitoring screenshots',
    acceptanceCriteria: 'Measured values ≤ stated RTO/RPO; gaps tracked to closure.'
  },
  'IA-2': {
    artifact: 'MFA enforcement evidence for all human access paths',
    collectionMethod: 'Okta MFA report + AWS IAM Identity Center session policy',
    acceptanceCriteria: 'All human users enrolled in phishing-resistant MFA.'
  },
  'IA-5': {
    artifact: 'Secrets inventory with rotation history',
    collectionMethod: 'AWS Secrets Manager + Okta admin export',
    acceptanceCriteria: 'No secrets older than rotation policy; no static secrets in source.'
  },
  'IA-8': {
    artifact: 'Non-org user authentication design (Cognito/B2B SSO)',
    collectionMethod: 'Architecture document + Cognito user pool export',
    acceptanceCriteria: 'Identity proofing aligned to NIST 800-63 IAL/AAL.'
  },
  'IR-4': {
    artifact: 'Incident response runbook + last incident lessons-learned',
    collectionMethod: 'IR repository',
    acceptanceCriteria: 'Runbook current; action items tracked; tabletop in last 12 months.'
  },
  'IR-6': {
    artifact: 'Escalation matrix with regulatory notification timelines',
    collectionMethod: 'IR plan section',
    acceptanceCriteria: 'Timelines match jurisdictional requirements; legal/PR contacts current.'
  },
  'RA-5': {
    artifact: 'Vulnerability scan results + remediation SLA evidence',
    collectionMethod: 'Inspector + CI pipeline scanner export',
    acceptanceCriteria: 'Critical patched within 7 days; High within 30 days.'
  },
  'SA-11': {
    artifact: 'SAST/DAST/SCA results for the last quarter',
    collectionMethod: 'CI pipeline artifact store',
    acceptanceCriteria: 'Gating criteria documented; no exceptions without compensating controls.'
  },
  'SC-7': {
    artifact: 'Edge architecture + WAF rule set',
    collectionMethod: 'AWS WAF rule group export + architecture diagram',
    acceptanceCriteria: 'Managed rules enabled; rate-based rules in place; egress controlled.'
  },
  'SC-8': {
    artifact: 'TLS posture report (cipher suites, versions)',
    collectionMethod: 'SSL Labs / internal scan + ALB listener config',
    acceptanceCriteria: 'No protocol < TLS 1.2; no weak ciphers; HSTS for public endpoints.'
  },
  'SC-12': {
    artifact: 'KMS key inventory + rotation policy',
    collectionMethod: 'KMS list-keys + describe-key + key policy',
    acceptanceCriteria: 'Customer-managed keys for sensitive data; annual rotation; key admin/user separation.'
  },
  'SC-13': {
    artifact: 'FIPS endpoint usage attestation',
    collectionMethod: 'Configuration of AWS SDK FIPS endpoints + AWS attestation pack',
    acceptanceCriteria: 'FIPS endpoints in use where required.'
  },
  'SC-28': {
    artifact: 'Encryption-at-rest evidence for every data store',
    collectionMethod: 'aws rds describe-db-instances + s3api get-bucket-encryption + ebs describe-volumes',
    acceptanceCriteria: 'No unencrypted resources in scope.'
  },
  'SI-2': {
    artifact: 'Patch cadence report',
    collectionMethod: 'SSM Patch Manager + image-rebuild logs',
    acceptanceCriteria: 'SLA adherence demonstrated; exceptions documented.'
  },
  'SI-4': {
    artifact: 'Detection coverage matrix',
    collectionMethod: 'GuardDuty findings + Security Hub standards',
    acceptanceCriteria: 'Detections for MITRE ATT&CK techniques relevant to the system.'
  },
  'SI-7': {
    artifact: 'Artifact signing + CloudTrail integrity validation',
    collectionMethod: 'Image-signing logs + CloudTrail validate-logs output',
    acceptanceCriteria: 'All artifacts signed; CloudTrail validation green.'
  },
  'SI-10': {
    artifact: 'Input validation design + WAF rule coverage',
    collectionMethod: 'Code review + WAF rule export',
    acceptanceCriteria: 'Server-side validation present at every API; WAF blocks observed in logs.'
  }
};

const DEFAULT_TEMPLATE: Template = {
  artifact: 'Control implementation evidence',
  collectionMethod: 'See SSP Implementation Statement',
  acceptanceCriteria: 'Evidence reflects what is stated in the SSP and matches architecture.'
};

export function buildEvidenceRequests(ssp: SspControl[]): EvidenceRequest[] {
  return ssp.map(c => {
    const t = TEMPLATES[c.id] ?? DEFAULT_TEMPLATE;
    return {
      controlId: c.id,
      artifact: t.artifact,
      collectionMethod: t.collectionMethod,
      responsibleParty: c.responsibleParty,
      acceptanceCriteria: t.acceptanceCriteria
    };
  });
}
