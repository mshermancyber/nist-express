// Representative NIST SP 800-53 Rev 5 controls covering all required
// families. The catalog is curated rather than exhaustive (the full
// catalog contains over a thousand controls and enhancements); each
// entry retains the official family code, identifier, and a faithful
// short-form description usable for SSP authoring.

import { ImpactLevel } from '../types/assessment';

export interface NistControlDefinition {
  id: string;
  family: string;
  name: string;
  shortDescription: string;
  baselines: ImpactLevel[];
  defaultInheritance: 'Customer' | 'AWS (Provider)' | 'Hybrid' | 'Common Control';
  defaultResponsibleParty: string;
  assessmentGuidance: string;
  cisMappings: string[];
}

export const NIST_CONTROL_FAMILIES: Record<string, string> = {
  AC: 'Access Control',
  AT: 'Awareness and Training',
  AU: 'Audit and Accountability',
  CA: 'Assessment, Authorization, and Monitoring',
  CM: 'Configuration Management',
  CP: 'Contingency Planning',
  IA: 'Identification and Authentication',
  IR: 'Incident Response',
  MA: 'Maintenance',
  MP: 'Media Protection',
  PE: 'Physical and Environmental Protection',
  PL: 'Planning',
  PM: 'Program Management',
  PS: 'Personnel Security',
  PT: 'Personally Identifiable Information Processing and Transparency',
  RA: 'Risk Assessment',
  SA: 'System and Services Acquisition',
  SC: 'System and Communications Protection',
  SI: 'System and Information Integrity',
  SR: 'Supply Chain Risk Management'
};

export const NIST_CONTROLS: NistControlDefinition[] = [
  // ---- Access Control ----
  {
    id: 'AC-2', family: 'AC', name: 'Account Management',
    shortDescription: 'Establish processes to identify, create, manage, audit, and remove information system accounts.',
    baselines: ['Low', 'Moderate', 'High'],
    defaultInheritance: 'Customer',
    defaultResponsibleParty: 'Identity & Access Management Team',
    assessmentGuidance: 'Validate that account types are defined and authorized; lifecycle events are logged and reviewed at least quarterly.',
    cisMappings: ['5.1', '5.3', '6.1', '6.2']
  },
  {
    id: 'AC-3', family: 'AC', name: 'Access Enforcement',
    shortDescription: 'Enforce approved authorizations for logical access to information and system resources.',
    baselines: ['Low', 'Moderate', 'High'],
    defaultInheritance: 'Hybrid',
    defaultResponsibleParty: 'Application Owner',
    assessmentGuidance: 'Inspect role/permission model and confirm enforcement at every entry point.',
    cisMappings: ['3.3', '6.7']
  },
  {
    id: 'AC-6', family: 'AC', name: 'Least Privilege',
    shortDescription: 'Employ the principle of least privilege, granting only access necessary for assigned tasks.',
    baselines: ['Moderate', 'High'],
    defaultInheritance: 'Customer',
    defaultResponsibleParty: 'IAM Team & Application Owner',
    assessmentGuidance: 'Review IAM policies for wildcard actions/resources and validate periodic entitlement review.',
    cisMappings: ['6.8', '5.4']
  },
  {
    id: 'AC-17', family: 'AC', name: 'Remote Access',
    shortDescription: 'Establish and enforce usage restrictions for each type of remote access.',
    baselines: ['Low', 'Moderate', 'High'],
    defaultInheritance: 'Customer',
    defaultResponsibleParty: 'Network & IAM Teams',
    assessmentGuidance: 'Confirm only approved remote-access methods are allowed; MFA enforced.',
    cisMappings: ['12.7']
  },
  // ---- Awareness & Training ----
  {
    id: 'AT-2', family: 'AT', name: 'Literacy Training and Awareness',
    shortDescription: 'Provide security and privacy literacy training to all system users.',
    baselines: ['Low', 'Moderate', 'High'],
    defaultInheritance: 'Common Control',
    defaultResponsibleParty: 'Security Awareness Program',
    assessmentGuidance: 'Review completion records for all in-scope users for the current cycle.',
    cisMappings: ['14.1']
  },
  {
    id: 'AT-3', family: 'AT', name: 'Role-Based Training',
    shortDescription: 'Provide role-based security training before granting access and on a defined schedule.',
    baselines: ['Moderate', 'High'],
    defaultInheritance: 'Common Control',
    defaultResponsibleParty: 'Security Awareness Program',
    assessmentGuidance: 'Confirm privileged roles receive specialized training within onboarding window.',
    cisMappings: ['14.9']
  },
  // ---- Audit & Accountability ----
  {
    id: 'AU-2', family: 'AU', name: 'Event Logging',
    shortDescription: 'Identify the events that the system is capable of logging in support of the audit function.',
    baselines: ['Low', 'Moderate', 'High'],
    defaultInheritance: 'Customer',
    defaultResponsibleParty: 'Application Owner & SecOps',
    assessmentGuidance: 'Cross-check logged events list against approved auditable events catalog.',
    cisMappings: ['8.2']
  },
  {
    id: 'AU-3', family: 'AU', name: 'Content of Audit Records',
    shortDescription: 'Ensure audit records contain information sufficient to establish what, when, where, who, and outcome.',
    baselines: ['Low', 'Moderate', 'High'],
    defaultInheritance: 'Customer',
    defaultResponsibleParty: 'Application Owner',
    assessmentGuidance: 'Inspect sample CloudTrail and application records for required fields.',
    cisMappings: ['8.5']
  },
  {
    id: 'AU-6', family: 'AU', name: 'Audit Record Review, Analysis, and Reporting',
    shortDescription: 'Review and analyze audit records for indications of inappropriate or unusual activity.',
    baselines: ['Low', 'Moderate', 'High'],
    defaultInheritance: 'Customer',
    defaultResponsibleParty: 'SecOps',
    assessmentGuidance: 'Confirm detection rules exist and on-call response runbooks are documented.',
    cisMappings: ['8.11']
  },
  {
    id: 'AU-9', family: 'AU', name: 'Protection of Audit Information',
    shortDescription: 'Protect audit information and tools from unauthorized access, modification, and deletion.',
    baselines: ['Low', 'Moderate', 'High'],
    defaultInheritance: 'Hybrid',
    defaultResponsibleParty: 'SecOps',
    assessmentGuidance: 'Verify log destination buckets enforce object-lock or equivalent immutability.',
    cisMappings: ['8.10']
  },
  {
    id: 'AU-12', family: 'AU', name: 'Audit Record Generation',
    shortDescription: 'Provide audit record generation capability for the events defined in AU-2 at all relevant components.',
    baselines: ['Low', 'Moderate', 'High'],
    defaultInheritance: 'Customer',
    defaultResponsibleParty: 'Application Owner',
    assessmentGuidance: 'Inspect coverage across all components; identify gaps.',
    cisMappings: ['8.2']
  },
  // ---- Assessment, Authorization & Monitoring ----
  {
    id: 'CA-2', family: 'CA', name: 'Control Assessments',
    shortDescription: 'Develop, document, and periodically assess control effectiveness.',
    baselines: ['Low', 'Moderate', 'High'],
    defaultInheritance: 'Common Control',
    defaultResponsibleParty: 'Compliance Office',
    assessmentGuidance: 'Review assessment cadence and most recent results.',
    cisMappings: ['17.1']
  },
  {
    id: 'CA-7', family: 'CA', name: 'Continuous Monitoring',
    shortDescription: 'Develop a system-level continuous monitoring strategy.',
    baselines: ['Low', 'Moderate', 'High'],
    defaultInheritance: 'Hybrid',
    defaultResponsibleParty: 'SecOps & Compliance',
    assessmentGuidance: 'Confirm metrics, frequency, and reporting paths are defined and operational.',
    cisMappings: ['8.11']
  },
  // ---- Configuration Management ----
  {
    id: 'CM-2', family: 'CM', name: 'Baseline Configuration',
    shortDescription: 'Develop and maintain a current baseline configuration of the system.',
    baselines: ['Low', 'Moderate', 'High'],
    defaultInheritance: 'Customer',
    defaultResponsibleParty: 'Platform / DevOps',
    assessmentGuidance: 'Verify IaC repository is authoritative; drift detection is operational.',
    cisMappings: ['4.1']
  },
  {
    id: 'CM-6', family: 'CM', name: 'Configuration Settings',
    shortDescription: 'Establish, document, and enforce mandatory configuration settings.',
    baselines: ['Low', 'Moderate', 'High'],
    defaultInheritance: 'Customer',
    defaultResponsibleParty: 'Platform / DevOps',
    assessmentGuidance: 'Validate hardening baselines via AWS Config conformance packs.',
    cisMappings: ['4.2']
  },
  {
    id: 'CM-7', family: 'CM', name: 'Least Functionality',
    shortDescription: 'Configure the system to provide only essential capabilities.',
    baselines: ['Low', 'Moderate', 'High'],
    defaultInheritance: 'Customer',
    defaultResponsibleParty: 'Application Owner',
    assessmentGuidance: 'Review enabled ports, services, and unused IAM permissions.',
    cisMappings: ['4.8']
  },
  {
    id: 'CM-8', family: 'CM', name: 'System Component Inventory',
    shortDescription: 'Develop and maintain an inventory of system components.',
    baselines: ['Low', 'Moderate', 'High'],
    defaultInheritance: 'Hybrid',
    defaultResponsibleParty: 'Platform / DevOps',
    assessmentGuidance: 'Cross-reference Config inventory against architecture diagram.',
    cisMappings: ['1.1', '2.1']
  },
  // ---- Contingency Planning ----
  {
    id: 'CP-2', family: 'CP', name: 'Contingency Plan',
    shortDescription: 'Develop a contingency plan for the system.',
    baselines: ['Low', 'Moderate', 'High'],
    defaultInheritance: 'Customer',
    defaultResponsibleParty: 'Application Owner & BCDR Team',
    assessmentGuidance: 'Plan must address RTO/RPO and align with categorization.',
    cisMappings: ['11.1']
  },
  {
    id: 'CP-9', family: 'CP', name: 'System Backup',
    shortDescription: 'Conduct backups of user-level and system-level information.',
    baselines: ['Low', 'Moderate', 'High'],
    defaultInheritance: 'Customer',
    defaultResponsibleParty: 'Platform / SRE',
    assessmentGuidance: 'Inspect backup schedule, encryption, and offsite retention.',
    cisMappings: ['11.2', '11.3']
  },
  {
    id: 'CP-10', family: 'CP', name: 'System Recovery and Reconstitution',
    shortDescription: 'Provide the capability to recover and reconstitute the system to a known state.',
    baselines: ['Low', 'Moderate', 'High'],
    defaultInheritance: 'Customer',
    defaultResponsibleParty: 'Platform / SRE',
    assessmentGuidance: 'Validate documented restore procedures and last test result.',
    cisMappings: ['11.4', '11.5']
  },
  // ---- Identification & Authentication ----
  {
    id: 'IA-2', family: 'IA', name: 'Identification and Authentication (Organizational Users)',
    shortDescription: 'Uniquely identify and authenticate organizational users.',
    baselines: ['Low', 'Moderate', 'High'],
    defaultInheritance: 'Customer',
    defaultResponsibleParty: 'IAM Team',
    assessmentGuidance: 'Confirm SSO with MFA on all org-user access paths.',
    cisMappings: ['6.3', '6.5']
  },
  {
    id: 'IA-5', family: 'IA', name: 'Authenticator Management',
    shortDescription: 'Manage system authenticators including initial distribution, rotation, and revocation.',
    baselines: ['Low', 'Moderate', 'High'],
    defaultInheritance: 'Customer',
    defaultResponsibleParty: 'IAM Team',
    assessmentGuidance: 'Verify password policy strength; secrets rotation cadence; MFA enrollment.',
    cisMappings: ['5.2', '6.5']
  },
  {
    id: 'IA-8', family: 'IA', name: 'Identification and Authentication (Non-Organizational Users)',
    shortDescription: 'Uniquely identify and authenticate non-organizational users.',
    baselines: ['Low', 'Moderate', 'High'],
    defaultInheritance: 'Customer',
    defaultResponsibleParty: 'IAM Team & Application Owner',
    assessmentGuidance: 'Validate customer/partner identity flows; risk-based authentication.',
    cisMappings: ['6.6']
  },
  // ---- Incident Response ----
  {
    id: 'IR-4', family: 'IR', name: 'Incident Handling',
    shortDescription: 'Implement an incident handling capability for security incidents.',
    baselines: ['Low', 'Moderate', 'High'],
    defaultInheritance: 'Common Control',
    defaultResponsibleParty: 'CSIRT',
    assessmentGuidance: 'Confirm runbooks, on-call rotation, and tabletop exercise records.',
    cisMappings: ['17.4', '17.5']
  },
  {
    id: 'IR-6', family: 'IR', name: 'Incident Reporting',
    shortDescription: 'Report security incidents to organizational and external authorities as required.',
    baselines: ['Low', 'Moderate', 'High'],
    defaultInheritance: 'Common Control',
    defaultResponsibleParty: 'CSIRT & Legal',
    assessmentGuidance: 'Review escalation matrix and regulatory notification timelines.',
    cisMappings: ['17.2']
  },
  // ---- Maintenance ----
  {
    id: 'MA-2', family: 'MA', name: 'Controlled Maintenance',
    shortDescription: 'Schedule, document, and review records of system maintenance and repairs.',
    baselines: ['Low', 'Moderate', 'High'],
    defaultInheritance: 'AWS (Provider)',
    defaultResponsibleParty: 'AWS (for managed services)',
    assessmentGuidance: 'For customer-managed components, validate change records.',
    cisMappings: ['7.1']
  },
  // ---- Media Protection ----
  {
    id: 'MP-6', family: 'MP', name: 'Media Sanitization',
    shortDescription: 'Sanitize media containing system information prior to disposal or release.',
    baselines: ['Low', 'Moderate', 'High'],
    defaultInheritance: 'AWS (Provider)',
    defaultResponsibleParty: 'AWS',
    assessmentGuidance: 'Inherit AWS attestation; customer responsibility for client-side data.',
    cisMappings: ['3.6']
  },
  // ---- Physical & Environmental ----
  {
    id: 'PE-3', family: 'PE', name: 'Physical Access Control',
    shortDescription: 'Enforce physical access authorizations at system entry/exit points.',
    baselines: ['Low', 'Moderate', 'High'],
    defaultInheritance: 'AWS (Provider)',
    defaultResponsibleParty: 'AWS',
    assessmentGuidance: 'Fully inherited from AWS for cloud-resident systems.',
    cisMappings: []
  },
  // ---- Planning ----
  {
    id: 'PL-2', family: 'PL', name: 'System Security and Privacy Plans',
    shortDescription: 'Develop a security and privacy plan that describes the system and its security/privacy controls.',
    baselines: ['Low', 'Moderate', 'High'],
    defaultInheritance: 'Customer',
    defaultResponsibleParty: 'Security Architect',
    assessmentGuidance: 'Confirm SSP is current, reviewed, and signed.',
    cisMappings: []
  },
  // ---- Program Management ----
  {
    id: 'PM-9', family: 'PM', name: 'Risk Management Strategy',
    shortDescription: 'Establish a comprehensive strategy to manage information security and privacy risk.',
    baselines: ['Low', 'Moderate', 'High'],
    defaultInheritance: 'Common Control',
    defaultResponsibleParty: 'CISO Office',
    assessmentGuidance: 'Confirm risk framework, tolerance, and treatment process documented.',
    cisMappings: []
  },
  // ---- Personnel Security ----
  {
    id: 'PS-3', family: 'PS', name: 'Personnel Screening',
    shortDescription: 'Screen individuals prior to authorizing access and rescreen on a defined frequency.',
    baselines: ['Low', 'Moderate', 'High'],
    defaultInheritance: 'Common Control',
    defaultResponsibleParty: 'HR & Security',
    assessmentGuidance: 'Verify background check completion for in-scope roles.',
    cisMappings: []
  },
  // ---- Risk Assessment ----
  {
    id: 'RA-3', family: 'RA', name: 'Risk Assessment',
    shortDescription: 'Conduct an assessment of risk to the system.',
    baselines: ['Low', 'Moderate', 'High'],
    defaultInheritance: 'Customer',
    defaultResponsibleParty: 'Security Architect & Risk Office',
    assessmentGuidance: 'Verify RA frequency and that this SSP references current threat model.',
    cisMappings: []
  },
  {
    id: 'RA-5', family: 'RA', name: 'Vulnerability Monitoring and Scanning',
    shortDescription: 'Monitor and scan for vulnerabilities in the system.',
    baselines: ['Low', 'Moderate', 'High'],
    defaultInheritance: 'Customer',
    defaultResponsibleParty: 'AppSec & Platform',
    assessmentGuidance: 'Confirm scanner coverage; SLA for remediation by severity.',
    cisMappings: ['7.5', '7.6', '7.7']
  },
  // ---- System & Services Acquisition ----
  {
    id: 'SA-11', family: 'SA', name: 'Developer Testing and Evaluation',
    shortDescription: 'Require developers to perform security and privacy testing throughout the SDLC.',
    baselines: ['Moderate', 'High'],
    defaultInheritance: 'Customer',
    defaultResponsibleParty: 'Engineering',
    assessmentGuidance: 'Inspect SAST/DAST/SCA coverage and gating criteria.',
    cisMappings: ['16.10', '16.12']
  },
  // ---- System & Communications Protection ----
  {
    id: 'SC-7', family: 'SC', name: 'Boundary Protection',
    shortDescription: 'Monitor and control communications at external and key internal system boundaries.',
    baselines: ['Low', 'Moderate', 'High'],
    defaultInheritance: 'Hybrid',
    defaultResponsibleParty: 'Network Security',
    assessmentGuidance: 'Review WAF, security groups, and network ACLs for the boundary.',
    cisMappings: ['12.2', '13.10']
  },
  {
    id: 'SC-8', family: 'SC', name: 'Transmission Confidentiality and Integrity',
    shortDescription: 'Protect the confidentiality and integrity of transmitted information.',
    baselines: ['Moderate', 'High'],
    defaultInheritance: 'Customer',
    defaultResponsibleParty: 'Application Owner',
    assessmentGuidance: 'Confirm TLS 1.2+ everywhere; certificate management is automated.',
    cisMappings: ['3.10']
  },
  {
    id: 'SC-12', family: 'SC', name: 'Cryptographic Key Establishment and Management',
    shortDescription: 'Establish and manage cryptographic keys when cryptography is employed.',
    baselines: ['Low', 'Moderate', 'High'],
    defaultInheritance: 'Hybrid',
    defaultResponsibleParty: 'Cloud Platform / Security',
    assessmentGuidance: 'Verify KMS key policies, rotation, and access boundaries.',
    cisMappings: ['3.11']
  },
  {
    id: 'SC-13', family: 'SC', name: 'Cryptographic Protection',
    shortDescription: 'Implement FIPS-validated or NSA-approved cryptography.',
    baselines: ['Low', 'Moderate', 'High'],
    defaultInheritance: 'Hybrid',
    defaultResponsibleParty: 'Cloud Platform / Security',
    assessmentGuidance: 'Confirm FIPS 140 endpoint usage if required.',
    cisMappings: []
  },
  {
    id: 'SC-28', family: 'SC', name: 'Protection of Information at Rest',
    shortDescription: 'Protect the confidentiality and integrity of information at rest.',
    baselines: ['Moderate', 'High'],
    defaultInheritance: 'Customer',
    defaultResponsibleParty: 'Application Owner',
    assessmentGuidance: 'Verify SSE on S3, RDS, EBS; customer-managed keys for sensitive data.',
    cisMappings: ['3.11']
  },
  // ---- System & Information Integrity ----
  {
    id: 'SI-2', family: 'SI', name: 'Flaw Remediation',
    shortDescription: 'Identify, report, and correct system flaws within defined timeframes.',
    baselines: ['Low', 'Moderate', 'High'],
    defaultInheritance: 'Customer',
    defaultResponsibleParty: 'Engineering & Platform',
    assessmentGuidance: 'Review patch cadence and emergency-patch policy.',
    cisMappings: ['7.3', '7.4']
  },
  {
    id: 'SI-4', family: 'SI', name: 'System Monitoring',
    shortDescription: 'Monitor the system to detect attacks and indicators of potential attacks.',
    baselines: ['Low', 'Moderate', 'High'],
    defaultInheritance: 'Hybrid',
    defaultResponsibleParty: 'SecOps',
    assessmentGuidance: 'Verify GuardDuty, Security Hub, and detection rule coverage.',
    cisMappings: ['8.11', '13.1']
  },
  {
    id: 'SI-7', family: 'SI', name: 'Software, Firmware, and Information Integrity',
    shortDescription: 'Employ integrity verification tools to detect unauthorized changes.',
    baselines: ['Moderate', 'High'],
    defaultInheritance: 'Customer',
    defaultResponsibleParty: 'Platform / Engineering',
    assessmentGuidance: 'Confirm artifact signing, image-scan policy, and CloudTrail tamper detection.',
    cisMappings: ['2.6']
  },
  {
    id: 'SI-10', family: 'SI', name: 'Information Input Validation',
    shortDescription: 'Check the validity of system inputs.',
    baselines: ['Moderate', 'High'],
    defaultInheritance: 'Customer',
    defaultResponsibleParty: 'Application Owner',
    assessmentGuidance: 'Review server-side validation, schema enforcement, and WAF rules.',
    cisMappings: ['16.11']
  }
];

// ---- Additional base controls (M49 — comprehensive Rev 5 coverage) ----
// These extend the curated set above so every one of the 20 control
// families has substantive coverage. Implementation statements are
// produced by the SSP engine; the catalog entries below carry the
// metadata the engine needs: family, baselines, default inheritance,
// responsible party, assessment guidance, and CIS v8 mappings.

const ADDITIONAL_CONTROLS: NistControlDefinition[] = [
  // ---- AC additions ----
  { id: 'AC-1', family: 'AC', name: 'Policy and Procedures', shortDescription: 'Develop, document, and disseminate access control policy and procedures.', baselines: ['Low', 'Moderate', 'High'], defaultInheritance: 'Common Control', defaultResponsibleParty: 'CISO Office', assessmentGuidance: 'Verify policy currency and dissemination.', cisMappings: ['14.1'] },
  { id: 'AC-4', family: 'AC', name: 'Information Flow Enforcement', shortDescription: 'Control information flows within the system and between connected systems.', baselines: ['Moderate', 'High'], defaultInheritance: 'Customer', defaultResponsibleParty: 'Network Security', assessmentGuidance: 'Inspect security groups, NACLs, and VPC flow logs for boundary enforcement.', cisMappings: ['12.2'] },
  { id: 'AC-5', family: 'AC', name: 'Separation of Duties', shortDescription: 'Separate duties of individuals as necessary to prevent malevolent activity.', baselines: ['Moderate', 'High'], defaultInheritance: 'Customer', defaultResponsibleParty: 'IAM Team', assessmentGuidance: 'Confirm that no single individual holds incompatible role combinations.', cisMappings: ['5.4'] },
  { id: 'AC-7', family: 'AC', name: 'Unsuccessful Logon Attempts', shortDescription: 'Limit consecutive invalid logon attempts.', baselines: ['Low', 'Moderate', 'High'], defaultInheritance: 'Customer', defaultResponsibleParty: 'IAM Team', assessmentGuidance: 'Verify per-account and per-IP lockout thresholds.', cisMappings: ['6.5'] },
  { id: 'AC-8', family: 'AC', name: 'System Use Notification', shortDescription: 'Display approved system use notification before granting access.', baselines: ['Low', 'Moderate', 'High'], defaultInheritance: 'Customer', defaultResponsibleParty: 'Application Owner', assessmentGuidance: 'Confirm login banner is displayed and acknowledged.', cisMappings: [] },
  { id: 'AC-11', family: 'AC', name: 'Device Lock', shortDescription: 'Prevent access by initiating device lock after inactivity.', baselines: ['Moderate', 'High'], defaultInheritance: 'Common Control', defaultResponsibleParty: 'Endpoint Mgmt', assessmentGuidance: 'Verify MDM policy enforces lock after ≤15 min.', cisMappings: [] },
  { id: 'AC-12', family: 'AC', name: 'Session Termination', shortDescription: 'Automatically terminate sessions after defined conditions.', baselines: ['Moderate', 'High'], defaultInheritance: 'Customer', defaultResponsibleParty: 'Application Owner', assessmentGuidance: 'Confirm idle timeout and absolute session lifetime.', cisMappings: [] },
  { id: 'AC-14', family: 'AC', name: 'Permitted Actions Without Identification or Authentication', shortDescription: 'Identify actions that can be performed without identification or authentication.', baselines: ['Low', 'Moderate', 'High'], defaultInheritance: 'Customer', defaultResponsibleParty: 'Application Owner', assessmentGuidance: 'Confirm only documented anonymous actions are permitted.', cisMappings: [] },
  { id: 'AC-18', family: 'AC', name: 'Wireless Access', shortDescription: 'Establish usage restrictions and authentication for wireless access.', baselines: ['Low', 'Moderate', 'High'], defaultInheritance: 'Common Control', defaultResponsibleParty: 'Network Security', assessmentGuidance: 'Verify WPA3 / enterprise auth on corporate wireless.', cisMappings: ['12.8'] },
  { id: 'AC-19', family: 'AC', name: 'Access Control for Mobile Devices', shortDescription: 'Establish usage restrictions for mobile devices.', baselines: ['Low', 'Moderate', 'High'], defaultInheritance: 'Common Control', defaultResponsibleParty: 'Endpoint Mgmt', assessmentGuidance: 'Confirm MDM enrolment and policy enforcement.', cisMappings: [] },
  { id: 'AC-20', family: 'AC', name: 'Use of External Systems', shortDescription: 'Establish terms and conditions for use of external systems.', baselines: ['Low', 'Moderate', 'High'], defaultInheritance: 'Common Control', defaultResponsibleParty: 'Vendor Risk', assessmentGuidance: 'Verify DPAs / interconnection agreements with external systems.', cisMappings: ['15.1'] },
  { id: 'AC-21', family: 'AC', name: 'Information Sharing', shortDescription: 'Enable authorized users to make information-sharing decisions.', baselines: ['Moderate', 'High'], defaultInheritance: 'Customer', defaultResponsibleParty: 'Application Owner', assessmentGuidance: 'Confirm decision workflow for cross-org sharing.', cisMappings: [] },
  { id: 'AC-22', family: 'AC', name: 'Publicly Accessible Content', shortDescription: 'Designate individuals authorized to post information on publicly accessible systems.', baselines: ['Low', 'Moderate', 'High'], defaultInheritance: 'Customer', defaultResponsibleParty: 'Application Owner', assessmentGuidance: 'Verify content-review workflow before publication.', cisMappings: [] },

  // ---- AT additions ----
  { id: 'AT-1', family: 'AT', name: 'Policy and Procedures', shortDescription: 'Develop and maintain awareness and training policy.', baselines: ['Low', 'Moderate', 'High'], defaultInheritance: 'Common Control', defaultResponsibleParty: 'Security Awareness Program', assessmentGuidance: 'Verify policy currency.', cisMappings: [] },
  { id: 'AT-4', family: 'AT', name: 'Training Records', shortDescription: 'Maintain documentation of security and privacy training activities.', baselines: ['Low', 'Moderate', 'High'], defaultInheritance: 'Common Control', defaultResponsibleParty: 'HR & Security', assessmentGuidance: 'Confirm records retained per policy.', cisMappings: ['14.1'] },

  // ---- AU additions ----
  { id: 'AU-1', family: 'AU', name: 'Policy and Procedures', shortDescription: 'Develop and maintain audit policy.', baselines: ['Low', 'Moderate', 'High'], defaultInheritance: 'Common Control', defaultResponsibleParty: 'CISO Office', assessmentGuidance: 'Verify policy currency.', cisMappings: [] },
  { id: 'AU-4', family: 'AU', name: 'Audit Log Storage Capacity', shortDescription: 'Allocate audit log storage capacity.', baselines: ['Low', 'Moderate', 'High'], defaultInheritance: 'Customer', defaultResponsibleParty: 'SecOps', assessmentGuidance: 'Verify retention policy and storage alarm thresholds.', cisMappings: ['8.10'] },
  { id: 'AU-5', family: 'AU', name: 'Response to Audit Logging Process Failures', shortDescription: 'Alert on audit logging process failures.', baselines: ['Low', 'Moderate', 'High'], defaultInheritance: 'Customer', defaultResponsibleParty: 'SecOps', assessmentGuidance: 'Confirm logging-failure alarms exist and are routed.', cisMappings: ['8.11'] },
  { id: 'AU-7', family: 'AU', name: 'Audit Record Reduction and Report Generation', shortDescription: 'Provide audit record reduction and report generation capability.', baselines: ['Moderate', 'High'], defaultInheritance: 'Customer', defaultResponsibleParty: 'SecOps', assessmentGuidance: 'Verify query/dashboard tooling for log review.', cisMappings: [] },
  { id: 'AU-8', family: 'AU', name: 'Time Stamps', shortDescription: 'Use system clocks to generate time stamps for audit records.', baselines: ['Low', 'Moderate', 'High'], defaultInheritance: 'Hybrid', defaultResponsibleParty: 'Platform', assessmentGuidance: 'Verify NTP / Amazon Time Sync configuration.', cisMappings: ['8.4'] },
  { id: 'AU-10', family: 'AU', name: 'Non-Repudiation', shortDescription: 'Protect against an individual falsely denying having performed an action.', baselines: ['High'], defaultInheritance: 'Customer', defaultResponsibleParty: 'Application Owner', assessmentGuidance: 'Confirm cryptographic signing of significant actions.', cisMappings: [] },
  { id: 'AU-11', family: 'AU', name: 'Audit Record Retention', shortDescription: 'Retain audit records consistent with applicable laws and regulations.', baselines: ['Low', 'Moderate', 'High'], defaultInheritance: 'Customer', defaultResponsibleParty: 'SecOps & Compliance', assessmentGuidance: 'Verify retention aligns with HIPAA/PCI/etc. scope.', cisMappings: ['8.10'] },
  { id: 'AU-13', family: 'AU', name: 'Monitoring for Information Disclosure', shortDescription: 'Monitor open-source information for unauthorized disclosure of organizational information.', baselines: ['Moderate', 'High'], defaultInheritance: 'Common Control', defaultResponsibleParty: 'Threat Intelligence', assessmentGuidance: 'Confirm leak-monitoring tooling and triage.', cisMappings: [] },
  { id: 'AU-14', family: 'AU', name: 'Session Audit', shortDescription: 'Capture and audit user sessions when required.', baselines: ['High'], defaultInheritance: 'Customer', defaultResponsibleParty: 'SecOps', assessmentGuidance: 'Verify session-capture for privileged operations.', cisMappings: [] },

  // ---- CA additions ----
  { id: 'CA-1', family: 'CA', name: 'Policy and Procedures', shortDescription: 'Develop assessment, authorization, and monitoring policy.', baselines: ['Low', 'Moderate', 'High'], defaultInheritance: 'Common Control', defaultResponsibleParty: 'Compliance Office', assessmentGuidance: 'Verify policy currency.', cisMappings: [] },
  { id: 'CA-3', family: 'CA', name: 'Information Exchange', shortDescription: 'Approve and manage information exchange between systems.', baselines: ['Low', 'Moderate', 'High'], defaultInheritance: 'Customer', defaultResponsibleParty: 'Compliance Office', assessmentGuidance: 'Verify ISAs/MOUs for system interconnections.', cisMappings: ['15.1'] },
  { id: 'CA-5', family: 'CA', name: 'Plan of Action and Milestones (POA&M)', shortDescription: 'Develop a POA&M to document planned remedial actions.', baselines: ['Low', 'Moderate', 'High'], defaultInheritance: 'Customer', defaultResponsibleParty: 'Compliance Office', assessmentGuidance: 'Verify POA&M is current and tracks open findings.', cisMappings: [] },
  { id: 'CA-6', family: 'CA', name: 'Authorization', shortDescription: 'Authorize the system to operate.', baselines: ['Low', 'Moderate', 'High'], defaultInheritance: 'Customer', defaultResponsibleParty: 'Authorizing Official', assessmentGuidance: 'Verify signed ATO and continuous monitoring linkage.', cisMappings: [] },
  { id: 'CA-9', family: 'CA', name: 'Internal System Connections', shortDescription: 'Authorize internal system connections.', baselines: ['Low', 'Moderate', 'High'], defaultInheritance: 'Customer', defaultResponsibleParty: 'Architecture', assessmentGuidance: 'Verify internal connection inventory.', cisMappings: [] },

  // ---- CM additions ----
  { id: 'CM-1', family: 'CM', name: 'Policy and Procedures', shortDescription: 'Develop configuration management policy.', baselines: ['Low', 'Moderate', 'High'], defaultInheritance: 'Common Control', defaultResponsibleParty: 'Platform / DevOps', assessmentGuidance: 'Verify policy currency.', cisMappings: [] },
  { id: 'CM-3', family: 'CM', name: 'Configuration Change Control', shortDescription: 'Coordinate and provide oversight for changes.', baselines: ['Moderate', 'High'], defaultInheritance: 'Customer', defaultResponsibleParty: 'CAB / Engineering Mgmt', assessmentGuidance: 'Verify change review workflow.', cisMappings: ['4.1'] },
  { id: 'CM-4', family: 'CM', name: 'Impact Analyses', shortDescription: 'Analyze changes for potential security and privacy impact.', baselines: ['Low', 'Moderate', 'High'], defaultInheritance: 'Customer', defaultResponsibleParty: 'Engineering & SecOps', assessmentGuidance: 'Confirm security review on significant changes.', cisMappings: [] },
  { id: 'CM-5', family: 'CM', name: 'Access Restrictions for Change', shortDescription: 'Define, document, approve, and enforce restrictions for changes.', baselines: ['Moderate', 'High'], defaultInheritance: 'Customer', defaultResponsibleParty: 'Platform / DevOps', assessmentGuidance: 'Confirm only approved CI principals can apply changes.', cisMappings: ['6.8'] },
  { id: 'CM-9', family: 'CM', name: 'Configuration Management Plan', shortDescription: 'Develop and document a configuration management plan.', baselines: ['Moderate', 'High'], defaultInheritance: 'Customer', defaultResponsibleParty: 'Platform / DevOps', assessmentGuidance: 'Verify CM plan currency.', cisMappings: [] },
  { id: 'CM-10', family: 'CM', name: 'Software Usage Restrictions', shortDescription: 'Use software in accordance with contract agreements and copyright laws.', baselines: ['Low', 'Moderate', 'High'], defaultInheritance: 'Common Control', defaultResponsibleParty: 'Legal & Procurement', assessmentGuidance: 'Verify license inventory.', cisMappings: [] },
  { id: 'CM-11', family: 'CM', name: 'User-Installed Software', shortDescription: 'Establish policies governing installation of software by users.', baselines: ['Low', 'Moderate', 'High'], defaultInheritance: 'Common Control', defaultResponsibleParty: 'Endpoint Mgmt', assessmentGuidance: 'Verify MDM software-allowlist policy.', cisMappings: ['2.7'] },
  { id: 'CM-12', family: 'CM', name: 'Information Location', shortDescription: 'Identify and document the location of information.', baselines: ['Moderate', 'High'], defaultInheritance: 'Customer', defaultResponsibleParty: 'Data Governance', assessmentGuidance: 'Confirm data-flow diagrams identify storage locations.', cisMappings: [] },

  // ---- CP additions ----
  { id: 'CP-1', family: 'CP', name: 'Policy and Procedures', shortDescription: 'Develop contingency planning policy.', baselines: ['Low', 'Moderate', 'High'], defaultInheritance: 'Common Control', defaultResponsibleParty: 'BCDR Team', assessmentGuidance: 'Verify policy currency.', cisMappings: [] },
  { id: 'CP-3', family: 'CP', name: 'Contingency Training', shortDescription: 'Provide contingency training to personnel.', baselines: ['Low', 'Moderate', 'High'], defaultInheritance: 'Common Control', defaultResponsibleParty: 'BCDR Team', assessmentGuidance: 'Confirm training completion records.', cisMappings: [] },
  { id: 'CP-4', family: 'CP', name: 'Contingency Plan Testing', shortDescription: 'Test contingency plan capability.', baselines: ['Low', 'Moderate', 'High'], defaultInheritance: 'Customer', defaultResponsibleParty: 'BCDR Team', assessmentGuidance: 'Verify last full test result and lessons learned.', cisMappings: ['11.5'] },
  { id: 'CP-6', family: 'CP', name: 'Alternate Storage Site', shortDescription: 'Establish alternate storage site for backups.', baselines: ['Moderate', 'High'], defaultInheritance: 'Customer', defaultResponsibleParty: 'Platform / SRE', assessmentGuidance: 'Confirm cross-region backup destination.', cisMappings: ['11.4'] },
  { id: 'CP-7', family: 'CP', name: 'Alternate Processing Site', shortDescription: 'Establish alternate processing site for system recovery.', baselines: ['Moderate', 'High'], defaultInheritance: 'Customer', defaultResponsibleParty: 'Platform / SRE', assessmentGuidance: 'Confirm secondary-region readiness.', cisMappings: [] },
  { id: 'CP-8', family: 'CP', name: 'Telecommunications Services', shortDescription: 'Establish alternate telecommunications services.', baselines: ['Moderate', 'High'], defaultInheritance: 'Common Control', defaultResponsibleParty: 'Network Ops', assessmentGuidance: 'Confirm diverse-path connectivity for critical workloads.', cisMappings: [] },

  // ---- IA additions ----
  { id: 'IA-1', family: 'IA', name: 'Policy and Procedures', shortDescription: 'Develop identification and authentication policy.', baselines: ['Low', 'Moderate', 'High'], defaultInheritance: 'Common Control', defaultResponsibleParty: 'IAM Team', assessmentGuidance: 'Verify policy currency.', cisMappings: [] },
  { id: 'IA-3', family: 'IA', name: 'Device Identification and Authentication', shortDescription: 'Uniquely identify and authenticate devices.', baselines: ['Moderate', 'High'], defaultInheritance: 'Customer', defaultResponsibleParty: 'IAM Team & Network', assessmentGuidance: 'Verify device-cert / posture-based auth.', cisMappings: [] },
  { id: 'IA-4', family: 'IA', name: 'Identifier Management', shortDescription: 'Manage system identifiers (user, device, service).', baselines: ['Low', 'Moderate', 'High'], defaultInheritance: 'Customer', defaultResponsibleParty: 'IAM Team', assessmentGuidance: 'Verify ID lifecycle, including reuse rules.', cisMappings: ['5.1'] },
  { id: 'IA-6', family: 'IA', name: 'Authentication Feedback', shortDescription: 'Obscure feedback of authentication information.', baselines: ['Low', 'Moderate', 'High'], defaultInheritance: 'Customer', defaultResponsibleParty: 'Application Owner', assessmentGuidance: 'Verify password/MFA inputs are masked.', cisMappings: [] },
  { id: 'IA-7', family: 'IA', name: 'Cryptographic Module Authentication', shortDescription: 'Implement authentication mechanisms that satisfy FIPS validation.', baselines: ['Low', 'Moderate', 'High'], defaultInheritance: 'Hybrid', defaultResponsibleParty: 'Cloud Platform / Security', assessmentGuidance: 'Verify FIPS endpoints when required.', cisMappings: [] },
  { id: 'IA-11', family: 'IA', name: 'Re-authentication', shortDescription: 'Require re-authentication after defined conditions.', baselines: ['Low', 'Moderate', 'High'], defaultInheritance: 'Customer', defaultResponsibleParty: 'Application Owner', assessmentGuidance: 'Confirm re-auth for sensitive operations.', cisMappings: [] },
  { id: 'IA-12', family: 'IA', name: 'Identity Proofing', shortDescription: 'Identity-proof users requiring access.', baselines: ['Moderate', 'High'], defaultInheritance: 'Customer', defaultResponsibleParty: 'IAM Team & HR', assessmentGuidance: 'Verify proofing aligns with NIST 800-63A IAL.', cisMappings: [] },

  // ---- IR additions ----
  { id: 'IR-1', family: 'IR', name: 'Policy and Procedures', shortDescription: 'Develop incident response policy.', baselines: ['Low', 'Moderate', 'High'], defaultInheritance: 'Common Control', defaultResponsibleParty: 'CSIRT', assessmentGuidance: 'Verify policy currency.', cisMappings: [] },
  { id: 'IR-2', family: 'IR', name: 'Incident Response Training', shortDescription: 'Provide incident response training.', baselines: ['Low', 'Moderate', 'High'], defaultInheritance: 'Common Control', defaultResponsibleParty: 'CSIRT', assessmentGuidance: 'Verify role-specific training completion.', cisMappings: [] },
  { id: 'IR-3', family: 'IR', name: 'Incident Response Testing', shortDescription: 'Test incident response capability.', baselines: ['Moderate', 'High'], defaultInheritance: 'Common Control', defaultResponsibleParty: 'CSIRT', assessmentGuidance: 'Verify tabletop exercise within last 12 months.', cisMappings: ['17.7'] },
  { id: 'IR-5', family: 'IR', name: 'Incident Monitoring', shortDescription: 'Track and document incidents.', baselines: ['Low', 'Moderate', 'High'], defaultInheritance: 'Common Control', defaultResponsibleParty: 'CSIRT', assessmentGuidance: 'Verify ticketing of incidents and metrics.', cisMappings: [] },
  { id: 'IR-7', family: 'IR', name: 'Incident Response Assistance', shortDescription: 'Provide incident response support resource.', baselines: ['Low', 'Moderate', 'High'], defaultInheritance: 'Common Control', defaultResponsibleParty: 'CSIRT', assessmentGuidance: 'Verify on-call rotation and external IR retainer.', cisMappings: [] },
  { id: 'IR-8', family: 'IR', name: 'Incident Response Plan', shortDescription: 'Develop and maintain incident response plan.', baselines: ['Low', 'Moderate', 'High'], defaultInheritance: 'Common Control', defaultResponsibleParty: 'CSIRT', assessmentGuidance: 'Verify plan currency.', cisMappings: [] },

  // ---- MA additions ----
  { id: 'MA-1', family: 'MA', name: 'Policy and Procedures', shortDescription: 'Develop maintenance policy.', baselines: ['Low', 'Moderate', 'High'], defaultInheritance: 'Common Control', defaultResponsibleParty: 'Platform / SRE', assessmentGuidance: 'Verify policy currency.', cisMappings: [] },
  { id: 'MA-3', family: 'MA', name: 'Maintenance Tools', shortDescription: 'Approve, control, and monitor system maintenance tools.', baselines: ['Moderate', 'High'], defaultInheritance: 'Hybrid', defaultResponsibleParty: 'Platform / SRE', assessmentGuidance: 'Verify maintenance tools are inventoried.', cisMappings: [] },
  { id: 'MA-4', family: 'MA', name: 'Nonlocal Maintenance', shortDescription: 'Approve and monitor nonlocal maintenance activities.', baselines: ['Low', 'Moderate', 'High'], defaultInheritance: 'Customer', defaultResponsibleParty: 'Platform / SRE', assessmentGuidance: 'Verify session-recording for remote maintenance.', cisMappings: ['12.7'] },
  { id: 'MA-5', family: 'MA', name: 'Maintenance Personnel', shortDescription: 'Establish processes for authorizing maintenance personnel.', baselines: ['Low', 'Moderate', 'High'], defaultInheritance: 'Common Control', defaultResponsibleParty: 'HR & SecOps', assessmentGuidance: 'Verify background screening for contractors.', cisMappings: [] },

  // ---- MP additions ----
  { id: 'MP-1', family: 'MP', name: 'Policy and Procedures', shortDescription: 'Develop media protection policy.', baselines: ['Low', 'Moderate', 'High'], defaultInheritance: 'Common Control', defaultResponsibleParty: 'Data Protection Office', assessmentGuidance: 'Verify policy currency.', cisMappings: [] },
  { id: 'MP-2', family: 'MP', name: 'Media Access', shortDescription: 'Restrict access to media containing sensitive information.', baselines: ['Low', 'Moderate', 'High'], defaultInheritance: 'Common Control', defaultResponsibleParty: 'Data Protection Office', assessmentGuidance: 'Verify access logs for media stores.', cisMappings: [] },
  { id: 'MP-4', family: 'MP', name: 'Media Storage', shortDescription: 'Physically secure media containing sensitive information.', baselines: ['Moderate', 'High'], defaultInheritance: 'AWS (Provider)', defaultResponsibleParty: 'AWS / Common Control', assessmentGuidance: 'Inherited from AWS for cloud-resident systems.', cisMappings: [] },
  { id: 'MP-5', family: 'MP', name: 'Media Transport', shortDescription: 'Protect media during transport.', baselines: ['Moderate', 'High'], defaultInheritance: 'Common Control', defaultResponsibleParty: 'Data Protection Office', assessmentGuidance: 'Verify chain of custody.', cisMappings: [] },
  { id: 'MP-7', family: 'MP', name: 'Media Use', shortDescription: 'Restrict use of certain media types.', baselines: ['Low', 'Moderate', 'High'], defaultInheritance: 'Common Control', defaultResponsibleParty: 'Endpoint Mgmt', assessmentGuidance: 'Verify USB-storage policy on endpoints.', cisMappings: [] },

  // ---- PE additions ----
  { id: 'PE-1', family: 'PE', name: 'Policy and Procedures', shortDescription: 'Develop physical & environmental policy.', baselines: ['Low', 'Moderate', 'High'], defaultInheritance: 'AWS (Provider)', defaultResponsibleParty: 'AWS', assessmentGuidance: 'Inherited from AWS.', cisMappings: [] },
  { id: 'PE-2', family: 'PE', name: 'Physical Access Authorizations', shortDescription: 'Authorize physical access to the facility.', baselines: ['Low', 'Moderate', 'High'], defaultInheritance: 'AWS (Provider)', defaultResponsibleParty: 'AWS', assessmentGuidance: 'Inherited from AWS.', cisMappings: [] },
  { id: 'PE-6', family: 'PE', name: 'Monitoring Physical Access', shortDescription: 'Monitor physical access to the facility.', baselines: ['Low', 'Moderate', 'High'], defaultInheritance: 'AWS (Provider)', defaultResponsibleParty: 'AWS', assessmentGuidance: 'Inherited from AWS.', cisMappings: [] },
  { id: 'PE-12', family: 'PE', name: 'Emergency Lighting', shortDescription: 'Employ automatic emergency lighting.', baselines: ['Low', 'Moderate', 'High'], defaultInheritance: 'AWS (Provider)', defaultResponsibleParty: 'AWS', assessmentGuidance: 'Inherited from AWS.', cisMappings: [] },
  { id: 'PE-13', family: 'PE', name: 'Fire Protection', shortDescription: 'Employ fire suppression and detection.', baselines: ['Low', 'Moderate', 'High'], defaultInheritance: 'AWS (Provider)', defaultResponsibleParty: 'AWS', assessmentGuidance: 'Inherited from AWS.', cisMappings: [] },
  { id: 'PE-14', family: 'PE', name: 'Environmental Controls', shortDescription: 'Maintain temperature and humidity within acceptable levels.', baselines: ['Low', 'Moderate', 'High'], defaultInheritance: 'AWS (Provider)', defaultResponsibleParty: 'AWS', assessmentGuidance: 'Inherited from AWS.', cisMappings: [] },

  // ---- PL additions ----
  { id: 'PL-1', family: 'PL', name: 'Policy and Procedures', shortDescription: 'Develop planning policy.', baselines: ['Low', 'Moderate', 'High'], defaultInheritance: 'Common Control', defaultResponsibleParty: 'CISO Office', assessmentGuidance: 'Verify policy currency.', cisMappings: [] },
  { id: 'PL-4', family: 'PL', name: 'Rules of Behavior', shortDescription: 'Establish rules of behavior for users.', baselines: ['Low', 'Moderate', 'High'], defaultInheritance: 'Common Control', defaultResponsibleParty: 'HR & Security', assessmentGuidance: 'Confirm acceptance records.', cisMappings: ['14.1'] },
  { id: 'PL-8', family: 'PL', name: 'Security and Privacy Architectures', shortDescription: 'Develop security and privacy architectures.', baselines: ['Moderate', 'High'], defaultInheritance: 'Customer', defaultResponsibleParty: 'Security Architect', assessmentGuidance: 'Verify architecture diagrams and rationale.', cisMappings: [] },
  { id: 'PL-10', family: 'PL', name: 'Baseline Selection', shortDescription: 'Select a control baseline.', baselines: ['Low', 'Moderate', 'High'], defaultInheritance: 'Customer', defaultResponsibleParty: 'Security Architect', assessmentGuidance: 'Confirm baseline derived from FIPS 199.', cisMappings: [] },
  { id: 'PL-11', family: 'PL', name: 'Baseline Tailoring', shortDescription: 'Tailor the selected baseline.', baselines: ['Low', 'Moderate', 'High'], defaultInheritance: 'Customer', defaultResponsibleParty: 'Security Architect', assessmentGuidance: 'Document tailoring decisions.', cisMappings: [] },

  // ---- PM additions ----
  { id: 'PM-1', family: 'PM', name: 'Information Security Program Plan', shortDescription: 'Develop and disseminate organization-wide information security program plan.', baselines: ['Low', 'Moderate', 'High'], defaultInheritance: 'Common Control', defaultResponsibleParty: 'CISO Office', assessmentGuidance: 'Verify plan currency.', cisMappings: [] },
  { id: 'PM-2', family: 'PM', name: 'Information Security Program Leadership Role', shortDescription: 'Designate a senior information security officer.', baselines: ['Low', 'Moderate', 'High'], defaultInheritance: 'Common Control', defaultResponsibleParty: 'CISO Office', assessmentGuidance: 'Confirm CISO designation.', cisMappings: [] },
  { id: 'PM-5', family: 'PM', name: 'System Inventory', shortDescription: 'Develop and maintain an inventory of systems.', baselines: ['Low', 'Moderate', 'High'], defaultInheritance: 'Common Control', defaultResponsibleParty: 'CMDB Team', assessmentGuidance: 'Verify CMDB completeness.', cisMappings: ['1.1'] },
  { id: 'PM-7', family: 'PM', name: 'Enterprise Architecture', shortDescription: 'Develop and maintain an enterprise architecture.', baselines: ['Low', 'Moderate', 'High'], defaultInheritance: 'Common Control', defaultResponsibleParty: 'Enterprise Architecture', assessmentGuidance: 'Verify EA artifacts.', cisMappings: [] },
  { id: 'PM-11', family: 'PM', name: 'Mission and Business Process Definition', shortDescription: 'Define mission and business processes.', baselines: ['Low', 'Moderate', 'High'], defaultInheritance: 'Common Control', defaultResponsibleParty: 'Business Owner', assessmentGuidance: 'Verify documented mission alignment.', cisMappings: [] },
  { id: 'PM-14', family: 'PM', name: 'Testing, Training, and Monitoring', shortDescription: 'Establish process for ensuring training and monitoring are performed.', baselines: ['Low', 'Moderate', 'High'], defaultInheritance: 'Common Control', defaultResponsibleParty: 'CISO Office', assessmentGuidance: 'Verify cadence of testing/training/monitoring.', cisMappings: [] },

  // ---- PS additions ----
  { id: 'PS-1', family: 'PS', name: 'Policy and Procedures', shortDescription: 'Develop personnel security policy.', baselines: ['Low', 'Moderate', 'High'], defaultInheritance: 'Common Control', defaultResponsibleParty: 'HR & Security', assessmentGuidance: 'Verify policy currency.', cisMappings: [] },
  { id: 'PS-2', family: 'PS', name: 'Position Risk Designation', shortDescription: 'Assign risk designation to organizational positions.', baselines: ['Low', 'Moderate', 'High'], defaultInheritance: 'Common Control', defaultResponsibleParty: 'HR & Security', assessmentGuidance: 'Confirm position-risk inventory.', cisMappings: [] },
  { id: 'PS-4', family: 'PS', name: 'Personnel Termination', shortDescription: 'Manage termination of personnel.', baselines: ['Low', 'Moderate', 'High'], defaultInheritance: 'Common Control', defaultResponsibleParty: 'HR & IAM', assessmentGuidance: 'Confirm access revocation SLA.', cisMappings: ['5.3'] },
  { id: 'PS-5', family: 'PS', name: 'Personnel Transfer', shortDescription: 'Review access on personnel transfer.', baselines: ['Low', 'Moderate', 'High'], defaultInheritance: 'Common Control', defaultResponsibleParty: 'HR & IAM', assessmentGuidance: 'Verify mover-review workflow.', cisMappings: [] },
  { id: 'PS-6', family: 'PS', name: 'Access Agreements', shortDescription: 'Develop access agreements.', baselines: ['Low', 'Moderate', 'High'], defaultInheritance: 'Common Control', defaultResponsibleParty: 'HR & Legal', assessmentGuidance: 'Verify signed agreements on file.', cisMappings: [] },
  { id: 'PS-7', family: 'PS', name: 'External Personnel Security', shortDescription: 'Establish personnel security requirements for external providers.', baselines: ['Low', 'Moderate', 'High'], defaultInheritance: 'Common Control', defaultResponsibleParty: 'Vendor Risk', assessmentGuidance: 'Confirm vendor-personnel screening.', cisMappings: [] },
  { id: 'PS-8', family: 'PS', name: 'Personnel Sanctions', shortDescription: 'Apply formal sanctions for personnel failing to comply with policy.', baselines: ['Low', 'Moderate', 'High'], defaultInheritance: 'Common Control', defaultResponsibleParty: 'HR & Legal', assessmentGuidance: 'Verify sanctions process documented.', cisMappings: [] },

  // ---- PT (Personally Identifiable Information Processing and Transparency) — NEW Rev 5 family ----
  { id: 'PT-1', family: 'PT', name: 'Policy and Procedures', shortDescription: 'Develop PII processing and transparency policy.', baselines: ['Low', 'Moderate', 'High'], defaultInheritance: 'Common Control', defaultResponsibleParty: 'Privacy Office', assessmentGuidance: 'Verify privacy policy currency.', cisMappings: [] },
  { id: 'PT-2', family: 'PT', name: 'Authority to Process PII', shortDescription: 'Determine and document legal authority to process PII.', baselines: ['Low', 'Moderate', 'High'], defaultInheritance: 'Common Control', defaultResponsibleParty: 'Privacy Office & Legal', assessmentGuidance: 'Verify legal authority records.', cisMappings: [] },
  { id: 'PT-3', family: 'PT', name: 'Personally Identifiable Information Processing Purposes', shortDescription: 'Identify and document processing purposes.', baselines: ['Low', 'Moderate', 'High'], defaultInheritance: 'Customer', defaultResponsibleParty: 'Privacy Office & Application Owner', assessmentGuidance: 'Confirm purposes captured in RoPA.', cisMappings: [] },
  { id: 'PT-4', family: 'PT', name: 'Consent', shortDescription: 'Implement tools or mechanisms for individuals to consent.', baselines: ['Moderate', 'High'], defaultInheritance: 'Customer', defaultResponsibleParty: 'Application Owner', assessmentGuidance: 'Verify consent capture and withdrawal mechanisms.', cisMappings: [] },
  { id: 'PT-5', family: 'PT', name: 'Privacy Notice', shortDescription: 'Provide notice to individuals about PII processing.', baselines: ['Low', 'Moderate', 'High'], defaultInheritance: 'Customer', defaultResponsibleParty: 'Privacy Office & Application Owner', assessmentGuidance: 'Confirm public privacy notice current.', cisMappings: [] },
  { id: 'PT-6', family: 'PT', name: 'System of Records Notice', shortDescription: 'Identify systems of records requiring federal SORNs.', baselines: ['Low', 'Moderate', 'High'], defaultInheritance: 'Common Control', defaultResponsibleParty: 'Privacy Office', assessmentGuidance: 'Verify SORN publication where applicable.', cisMappings: [] },
  { id: 'PT-7', family: 'PT', name: 'Specific Categories of PII', shortDescription: 'Apply specific protections to special categories of PII.', baselines: ['Moderate', 'High'], defaultInheritance: 'Customer', defaultResponsibleParty: 'Privacy Office & Application Owner', assessmentGuidance: 'Verify special-category handling (PHI, biometrics).', cisMappings: [] },
  { id: 'PT-8', family: 'PT', name: 'Computer Matching Requirements', shortDescription: 'Apply specific requirements for computer matching activities.', baselines: ['High'], defaultInheritance: 'Common Control', defaultResponsibleParty: 'Privacy Office & Legal', assessmentGuidance: 'For federal use only.', cisMappings: [] },

  // ---- RA additions ----
  { id: 'RA-1', family: 'RA', name: 'Policy and Procedures', shortDescription: 'Develop risk assessment policy.', baselines: ['Low', 'Moderate', 'High'], defaultInheritance: 'Common Control', defaultResponsibleParty: 'Risk Office', assessmentGuidance: 'Verify policy currency.', cisMappings: [] },
  { id: 'RA-2', family: 'RA', name: 'Security Categorization', shortDescription: 'Categorize systems per FIPS 199.', baselines: ['Low', 'Moderate', 'High'], defaultInheritance: 'Customer', defaultResponsibleParty: 'Security Architect', assessmentGuidance: 'Verify categorization rationale.', cisMappings: [] },
  { id: 'RA-7', family: 'RA', name: 'Risk Response', shortDescription: 'Respond to identified risks.', baselines: ['Low', 'Moderate', 'High'], defaultInheritance: 'Customer', defaultResponsibleParty: 'Risk Office & Application Owner', assessmentGuidance: 'Verify risk acceptance and treatment records.', cisMappings: [] },
  { id: 'RA-9', family: 'RA', name: 'Criticality Analysis', shortDescription: 'Identify and assess critical system components.', baselines: ['Moderate', 'High'], defaultInheritance: 'Customer', defaultResponsibleParty: 'Architecture & SecOps', assessmentGuidance: 'Verify critical-asset list.', cisMappings: [] },
  { id: 'RA-10', family: 'RA', name: 'Threat Hunting', shortDescription: 'Conduct threat hunting activities.', baselines: ['High'], defaultInheritance: 'Common Control', defaultResponsibleParty: 'SecOps / Threat Intel', assessmentGuidance: 'Verify hunt program cadence.', cisMappings: [] },

  // ---- SA additions ----
  { id: 'SA-1', family: 'SA', name: 'Policy and Procedures', shortDescription: 'Develop system & services acquisition policy.', baselines: ['Low', 'Moderate', 'High'], defaultInheritance: 'Common Control', defaultResponsibleParty: 'Procurement & Security', assessmentGuidance: 'Verify policy currency.', cisMappings: [] },
  { id: 'SA-2', family: 'SA', name: 'Allocation of Resources', shortDescription: 'Allocate resources to plan and budget for security/privacy.', baselines: ['Low', 'Moderate', 'High'], defaultInheritance: 'Common Control', defaultResponsibleParty: 'CISO Office & Finance', assessmentGuidance: 'Confirm budget allocation.', cisMappings: [] },
  { id: 'SA-3', family: 'SA', name: 'System Development Life Cycle', shortDescription: 'Manage the system through a SDLC.', baselines: ['Low', 'Moderate', 'High'], defaultInheritance: 'Customer', defaultResponsibleParty: 'Engineering Mgmt', assessmentGuidance: 'Verify SDLC documented and followed.', cisMappings: [] },
  { id: 'SA-4', family: 'SA', name: 'Acquisition Process', shortDescription: 'Include security and privacy requirements in acquisitions.', baselines: ['Low', 'Moderate', 'High'], defaultInheritance: 'Common Control', defaultResponsibleParty: 'Procurement & Security', assessmentGuidance: 'Verify security in RFPs/contracts.', cisMappings: ['15.4'] },
  { id: 'SA-8', family: 'SA', name: 'Security and Privacy Engineering Principles', shortDescription: 'Apply security and privacy engineering principles.', baselines: ['Moderate', 'High'], defaultInheritance: 'Customer', defaultResponsibleParty: 'Security Architect', assessmentGuidance: 'Confirm principles applied in architecture.', cisMappings: [] },
  { id: 'SA-9', family: 'SA', name: 'External System Services', shortDescription: 'Establish requirements for external system services.', baselines: ['Low', 'Moderate', 'High'], defaultInheritance: 'Common Control', defaultResponsibleParty: 'Vendor Risk', assessmentGuidance: 'Verify external-provider risk assessment.', cisMappings: ['15.1'] },
  { id: 'SA-10', family: 'SA', name: 'Developer Configuration Management', shortDescription: 'Require developers to perform configuration management.', baselines: ['Moderate', 'High'], defaultInheritance: 'Customer', defaultResponsibleParty: 'Engineering', assessmentGuidance: 'Verify CI/CD has CM controls.', cisMappings: ['4.1'] },
  { id: 'SA-15', family: 'SA', name: 'Development Process, Standards, and Tools', shortDescription: 'Require developers to follow secure-development process.', baselines: ['High'], defaultInheritance: 'Customer', defaultResponsibleParty: 'Engineering Mgmt', assessmentGuidance: 'Verify secure-coding standard adoption.', cisMappings: ['16.1'] },
  { id: 'SA-17', family: 'SA', name: 'Developer Security and Privacy Architecture and Design', shortDescription: 'Require developers to produce security/privacy architecture.', baselines: ['High'], defaultInheritance: 'Customer', defaultResponsibleParty: 'Security Architect', assessmentGuidance: 'Verify architecture-review evidence.', cisMappings: [] },
  { id: 'SA-22', family: 'SA', name: 'Unsupported System Components', shortDescription: 'Replace components no longer supported.', baselines: ['Moderate', 'High'], defaultInheritance: 'Customer', defaultResponsibleParty: 'Platform / Engineering', assessmentGuidance: 'Verify no end-of-life components in production.', cisMappings: ['2.2'] },

  // ---- SC additions ----
  { id: 'SC-1', family: 'SC', name: 'Policy and Procedures', shortDescription: 'Develop system & communications protection policy.', baselines: ['Low', 'Moderate', 'High'], defaultInheritance: 'Common Control', defaultResponsibleParty: 'Network Security', assessmentGuidance: 'Verify policy currency.', cisMappings: [] },
  { id: 'SC-2', family: 'SC', name: 'Separation of System and User Functionality', shortDescription: 'Separate system management from user functionality.', baselines: ['Moderate', 'High'], defaultInheritance: 'Customer', defaultResponsibleParty: 'Architecture', assessmentGuidance: 'Verify admin plane is separate.', cisMappings: [] },
  { id: 'SC-4', family: 'SC', name: 'Information in Shared System Resources', shortDescription: 'Prevent unauthorized information transfer via shared resources.', baselines: ['Moderate', 'High'], defaultInheritance: 'AWS (Provider)', defaultResponsibleParty: 'AWS', assessmentGuidance: 'Inherited; verify tenant isolation attestation.', cisMappings: [] },
  { id: 'SC-5', family: 'SC', name: 'Denial-of-Service Protection', shortDescription: 'Protect against and limit effects of denial-of-service.', baselines: ['Low', 'Moderate', 'High'], defaultInheritance: 'Hybrid', defaultResponsibleParty: 'Network Security', assessmentGuidance: 'Verify WAF/Shield protections.', cisMappings: [] },
  { id: 'SC-10', family: 'SC', name: 'Network Disconnect', shortDescription: 'Terminate the network connection at end of session or after inactivity.', baselines: ['Moderate', 'High'], defaultInheritance: 'Customer', defaultResponsibleParty: 'Application Owner', assessmentGuidance: 'Verify connection-idle timeout.', cisMappings: [] },
  { id: 'SC-15', family: 'SC', name: 'Collaborative Computing Devices and Applications', shortDescription: 'Prohibit remote activation of collaborative computing devices.', baselines: ['Moderate', 'High'], defaultInheritance: 'Common Control', defaultResponsibleParty: 'Endpoint Mgmt', assessmentGuidance: 'Verify camera/mic permissions managed.', cisMappings: [] },
  { id: 'SC-17', family: 'SC', name: 'Public Key Infrastructure Certificates', shortDescription: 'Issue PKI certificates under approved certificate policy.', baselines: ['Moderate', 'High'], defaultInheritance: 'Hybrid', defaultResponsibleParty: 'Cloud Platform / Security', assessmentGuidance: 'Verify ACM / private-CA configuration.', cisMappings: [] },
  { id: 'SC-18', family: 'SC', name: 'Mobile Code', shortDescription: 'Establish usage restrictions and procedures for mobile code.', baselines: ['Moderate', 'High'], defaultInheritance: 'Common Control', defaultResponsibleParty: 'Endpoint Mgmt', assessmentGuidance: 'Verify mobile-code policies.', cisMappings: [] },
  { id: 'SC-20', family: 'SC', name: 'Secure Name/Address Resolution Service (Authoritative Source)', shortDescription: 'Provide authoritative source DNSSEC.', baselines: ['Low', 'Moderate', 'High'], defaultInheritance: 'Customer', defaultResponsibleParty: 'Network Security', assessmentGuidance: 'Verify DNSSEC on Route 53 zones.', cisMappings: [] },
  { id: 'SC-21', family: 'SC', name: 'Secure Name/Address Resolution Service (Recursive or Caching Resolver)', shortDescription: 'Request and perform data origin authentication and integrity verification.', baselines: ['Low', 'Moderate', 'High'], defaultInheritance: 'Customer', defaultResponsibleParty: 'Network Security', assessmentGuidance: 'Verify resolver enforces DNSSEC.', cisMappings: [] },
  { id: 'SC-22', family: 'SC', name: 'Architecture and Provisioning for Name/Address Resolution Service', shortDescription: 'Ensure DNS resilience.', baselines: ['Low', 'Moderate', 'High'], defaultInheritance: 'Hybrid', defaultResponsibleParty: 'Network Security', assessmentGuidance: 'Verify multi-region DNS.', cisMappings: [] },
  { id: 'SC-23', family: 'SC', name: 'Session Authenticity', shortDescription: 'Protect the authenticity of communications sessions.', baselines: ['Moderate', 'High'], defaultInheritance: 'Customer', defaultResponsibleParty: 'Application Owner', assessmentGuidance: 'Verify session-binding and integrity.', cisMappings: [] },
  { id: 'SC-39', family: 'SC', name: 'Process Isolation', shortDescription: 'Maintain a separate execution domain for each process.', baselines: ['Low', 'Moderate', 'High'], defaultInheritance: 'AWS (Provider)', defaultResponsibleParty: 'AWS', assessmentGuidance: 'Inherited; verify hypervisor isolation attestation.', cisMappings: [] },

  // ---- SI additions ----
  { id: 'SI-1', family: 'SI', name: 'Policy and Procedures', shortDescription: 'Develop system and information integrity policy.', baselines: ['Low', 'Moderate', 'High'], defaultInheritance: 'Common Control', defaultResponsibleParty: 'SecOps', assessmentGuidance: 'Verify policy currency.', cisMappings: [] },
  { id: 'SI-3', family: 'SI', name: 'Malicious Code Protection', shortDescription: 'Implement malicious code protection.', baselines: ['Low', 'Moderate', 'High'], defaultInheritance: 'Hybrid', defaultResponsibleParty: 'Endpoint Mgmt & SecOps', assessmentGuidance: 'Verify EDR coverage and tuning.', cisMappings: ['10.1'] },
  { id: 'SI-5', family: 'SI', name: 'Security Alerts, Advisories, and Directives', shortDescription: 'Receive security alerts and directives from external sources.', baselines: ['Low', 'Moderate', 'High'], defaultInheritance: 'Common Control', defaultResponsibleParty: 'Threat Intel', assessmentGuidance: 'Verify subscription and triage.', cisMappings: [] },
  { id: 'SI-6', family: 'SI', name: 'Security and Privacy Function Verification', shortDescription: 'Verify the correct operation of security and privacy functions.', baselines: ['High'], defaultInheritance: 'Customer', defaultResponsibleParty: 'SecOps', assessmentGuidance: 'Verify periodic function tests.', cisMappings: [] },
  { id: 'SI-8', family: 'SI', name: 'Spam Protection', shortDescription: 'Employ spam protection mechanisms.', baselines: ['Moderate', 'High'], defaultInheritance: 'Common Control', defaultResponsibleParty: 'Email Ops', assessmentGuidance: 'Verify mail-server filters.', cisMappings: [] },
  { id: 'SI-11', family: 'SI', name: 'Error Handling', shortDescription: 'Generate error messages that do not reveal sensitive information.', baselines: ['Moderate', 'High'], defaultInheritance: 'Customer', defaultResponsibleParty: 'Application Owner', assessmentGuidance: 'Verify error-handling rules.', cisMappings: [] },
  { id: 'SI-12', family: 'SI', name: 'Information Management and Retention', shortDescription: 'Manage and retain information in accordance with applicable laws.', baselines: ['Low', 'Moderate', 'High'], defaultInheritance: 'Common Control', defaultResponsibleParty: 'Data Governance', assessmentGuidance: 'Verify retention schedule.', cisMappings: [] },
  { id: 'SI-16', family: 'SI', name: 'Memory Protection', shortDescription: 'Implement controls to protect memory from unauthorized code execution.', baselines: ['Moderate', 'High'], defaultInheritance: 'Hybrid', defaultResponsibleParty: 'Platform / Engineering', assessmentGuidance: 'Verify ASLR/DEP/Stack-canaries / managed runtimes.', cisMappings: [] },

  // ---- SR (Supply Chain Risk Management) — NEW Rev 5 family ----
  { id: 'SR-1', family: 'SR', name: 'Policy and Procedures', shortDescription: 'Develop supply chain risk management policy.', baselines: ['Low', 'Moderate', 'High'], defaultInheritance: 'Common Control', defaultResponsibleParty: 'Vendor Risk', assessmentGuidance: 'Verify policy currency.', cisMappings: [] },
  { id: 'SR-2', family: 'SR', name: 'Supply Chain Risk Management Plan', shortDescription: 'Develop a plan for managing supply chain risks.', baselines: ['Moderate', 'High'], defaultInheritance: 'Common Control', defaultResponsibleParty: 'Vendor Risk & Security Architect', assessmentGuidance: 'Verify SCRM plan.', cisMappings: ['15.5'] },
  { id: 'SR-3', family: 'SR', name: 'Supply Chain Controls and Processes', shortDescription: 'Establish processes for identifying and addressing supply chain risks.', baselines: ['Low', 'Moderate', 'High'], defaultInheritance: 'Common Control', defaultResponsibleParty: 'Vendor Risk', assessmentGuidance: 'Verify supplier-onboarding process.', cisMappings: ['15.1'] },
  { id: 'SR-4', family: 'SR', name: 'Provenance', shortDescription: 'Document, monitor, and maintain valid provenance of system components.', baselines: ['Moderate', 'High'], defaultInheritance: 'Customer', defaultResponsibleParty: 'Platform / Engineering', assessmentGuidance: 'Verify SBOM and artifact-signing.', cisMappings: ['2.6'] },
  { id: 'SR-5', family: 'SR', name: 'Acquisition Strategies, Tools, and Methods', shortDescription: 'Employ acquisition strategies to manage supply chain risks.', baselines: ['Moderate', 'High'], defaultInheritance: 'Common Control', defaultResponsibleParty: 'Procurement & Security', assessmentGuidance: 'Verify SBOM and contract clauses.', cisMappings: ['15.4'] },
  { id: 'SR-6', family: 'SR', name: 'Supplier Assessments and Reviews', shortDescription: 'Assess and review the security posture of suppliers.', baselines: ['Moderate', 'High'], defaultInheritance: 'Common Control', defaultResponsibleParty: 'Vendor Risk', assessmentGuidance: 'Verify SOC2/ISO assessment on file.', cisMappings: ['15.3'] },
  { id: 'SR-8', family: 'SR', name: 'Notification Agreements', shortDescription: 'Establish notification agreements with suppliers.', baselines: ['Low', 'Moderate', 'High'], defaultInheritance: 'Common Control', defaultResponsibleParty: 'Vendor Risk & Legal', assessmentGuidance: 'Verify breach-notification clauses.', cisMappings: [] },
  { id: 'SR-10', family: 'SR', name: 'Inspection of Systems or Components', shortDescription: 'Inspect systems or components for tampering.', baselines: ['Moderate', 'High'], defaultInheritance: 'Customer', defaultResponsibleParty: 'Platform / Engineering', assessmentGuidance: 'Verify artifact verification.', cisMappings: ['2.6'] },
  { id: 'SR-11', family: 'SR', name: 'Component Authenticity', shortDescription: 'Develop and implement anti-counterfeit policy and procedures.', baselines: ['Moderate', 'High'], defaultInheritance: 'Customer', defaultResponsibleParty: 'Platform / Engineering', assessmentGuidance: 'Verify image-signing and SBOM verification.', cisMappings: [] },
  { id: 'SR-12', family: 'SR', name: 'Component Disposal', shortDescription: 'Dispose of system components and information securely.', baselines: ['Low', 'Moderate', 'High'], defaultInheritance: 'AWS (Provider)', defaultResponsibleParty: 'AWS / Customer', assessmentGuidance: 'AWS-inherited for cloud; verify customer-managed disposal.', cisMappings: ['3.6'] }
];

// Concatenate at the bottom so downstream import order is stable.
NIST_CONTROLS.push(...ADDITIONAL_CONTROLS);

export function findControl(id: string): NistControlDefinition | undefined {
  return NIST_CONTROLS.find(c => c.id === id);
}
