// FedRAMP-grade package generator. Emits the artifacts the FedRAMP
// PMO expects alongside the SSP for an authorization package:
//
//   - Baseline-tailored control selection + FedRAMP parameter values
//   - Authorization Boundary description
//   - POA&M (Plan of Action and Milestones)
//   - Privacy Threshold Analysis + Privacy Impact Assessment
//   - Information System Contingency Plan summary
//   - Incident Response Plan summary
//   - Rules of Behavior
//   - Configuration Management Plan summary
//   - Continuous Monitoring Strategy
//   - E-Authentication Worksheet
//   - Agency overlays (DoD IL, IRS 1075, CMS ARS, CJIS)
//   - FIPS 140 platform attestation
//
// Output is structured (typed) so the export route can render it as
// markdown, JSON, OSCAL POA&M, or the bundled FedRAMP ZIP pack.

import {
  Assessment, ArbPackage, FedrampPackage, AuthorizationBoundary, PoamItem,
  PrivacyThresholdAnalysis, PrivacyImpactAssessment, ContingencyPlanSummary,
  IncidentResponsePlanSummary, ConfigurationManagementPlanSummary,
  ContinuousMonitoringStrategy, EAuthWorksheet, AgencyOverlay
} from '../types/assessment';
import { fedrampBaselineControls, fedrampBaselineForImpact, fedrampParametersFor, FedrampBaseline } from '../data/fedramp';
import { fipsStatus } from './fips';

function pickBaseline(a: Assessment, p: ArbPackage): FedrampBaseline {
  if (a.advanced?.preferredAwsRegion?.includes('gov')) {
    // GovCloud almost always implies at least MODERATE.
    const base = fedrampBaselineForImpact(p.categorization.overallCategorization);
    return base === 'LOW' ? 'MODERATE' : base;
  }
  return fedrampBaselineForImpact(p.categorization.overallCategorization);
}

export function isFedrampInScope(a: Assessment): boolean {
  return a.compliance.frameworks.includes('FedRAMP') || a.compliance.frameworks.includes('CMMC') || (a.advanced?.preferredAwsRegion ?? '').startsWith('us-gov');
}

function buildAuthorizationBoundary(a: Assessment, p: ArbPackage): AuthorizationBoundary {
  return {
    description: `Authorization boundary for ${a.business.applicationName} comprises ${p.architecture.components.length} components across ${new Set(p.architecture.components.map(c => c.layer)).size} architectural tiers. The boundary terminates at the AWS-managed PaaS interfaces and the declared third-party integrations.`,
    inScopeComponents: p.architecture.components.map(c => ({ id: c.id, name: c.name, trustZone: c.trustZone })),
    externalConnections: a.integrations.map(i => ({
      source: i.source, destination: i.destination, purpose: i.description ?? 'as declared in assessment',
      protocol: i.protocol, safeguards: `${i.authentication} + TLS where applicable`
    })),
    outOfScopeAssertions: [
      'Underlying AWS physical / hypervisor controls are inherited (FedRAMP-authorized AWS).',
      'Corporate identity provider is a Common Control evaluated separately.',
      'End-user devices accessing the system are governed by enterprise endpoint policy.'
    ]
  };
}

function nowPlusDays(days: number): string {
  const d = new Date(Date.now() + days * 86_400_000);
  return d.toISOString().slice(0, 10);
}

function severityFromRisk(r: 'Low' | 'Medium' | 'High' | 'Critical'): PoamItem['severity'] {
  return r;
}

function poamFromArbPackage(p: ArbPackage): PoamItem[] {
  const items: PoamItem[] = [];
  let n = 1;
  const id = () => `V-${String(n++).padStart(4, '0')}`;

  for (const r of p.residualRisks) {
    if (r.residualRisk === 'Low') continue;
    items.push({
      poamId: id(),
      weakness: r.description,
      source: r.source === 'STRIDE' ? 'STRIDE' : r.source === 'Operational' ? 'Operational' : r.source === 'Recovery' ? 'Recovery' : 'Compliance',
      severity: severityFromRisk(r.residualRisk),
      identifiedAt: new Date().toISOString().slice(0, 10),
      scheduledCompletion: r.residualRisk === 'Critical' ? nowPlusDays(30) : r.residualRisk === 'High' ? nowPlusDays(90) : nowPlusDays(180),
      status: r.treatment === 'Accept' ? 'Risk Accepted' : 'Open',
      pointOfContact: r.owner,
      resourcesRequired: 'In-team engineering capacity; no external spend expected unless noted.',
      milestones: [
        { description: 'Develop remediation plan', date: nowPlusDays(7), completed: false },
        { description: 'Implement controls', date: nowPlusDays(60), completed: false },
        { description: 'Validate effectiveness', date: nowPlusDays(75), completed: false }
      ],
      controlsImpacted: r.description.match(/[A-Z]{2}-\d+/g) ?? []
    });
  }

  for (const m of p.complianceMappings) {
    if (m.coverage !== 'Gap') continue;
    items.push({
      poamId: id(),
      weakness: `[${m.framework} ${m.controlId}] ${m.description}`,
      source: 'Compliance',
      severity: 'High',
      identifiedAt: new Date().toISOString().slice(0, 10),
      scheduledCompletion: nowPlusDays(120),
      status: 'Open',
      pointOfContact: 'Compliance Office',
      resourcesRequired: 'Implementation of mapped NIST controls.',
      milestones: [{ description: 'Implement mapped controls', date: nowPlusDays(90), completed: false }],
      controlsImpacted: []
    });
  }

  if (p.sbomAnalysis) {
    for (const v of p.sbomAnalysis.kevHits) {
      items.push({
        poamId: id(),
        weakness: `KEV-listed vulnerability ${v.id} (${v.severity}) affecting ${v.affectsComponents.join(', ')}`,
        source: 'SBOM/KEV',
        severity: v.severity === 'Unknown' ? 'High' : v.severity,
        identifiedAt: new Date().toISOString().slice(0, 10),
        scheduledCompletion: nowPlusDays(15),    // CISA BOD 22-01 mandates remediation within KEV-defined date
        status: 'Open',
        pointOfContact: 'Application Owner',
        resourcesRequired: 'Patch / upgrade affected dependencies.',
        milestones: [{ description: 'Upgrade affected component', date: nowPlusDays(7), completed: false }],
        controlsImpacted: ['SI-2', 'RA-5', 'SR-4']
      });
    }
  }

  for (const g of p.recovery.gaps) {
    items.push({
      poamId: id(),
      weakness: `Recovery gap: ${g}`,
      source: 'Recovery',
      severity: 'Medium',
      identifiedAt: new Date().toISOString().slice(0, 10),
      scheduledCompletion: nowPlusDays(120),
      status: 'Open',
      pointOfContact: 'BCDR Team',
      resourcesRequired: 'Architecture change + DR drill.',
      milestones: [{ description: 'Architect remediation', date: nowPlusDays(30), completed: false }],
      controlsImpacted: ['CP-2', 'CP-10']
    });
  }

  return items;
}

function buildPta(a: Assessment): PrivacyThresholdAnalysis {
  const tags = a.data.sensitiveDataTags;
  const collectsPii = tags.includes('PII') || tags.includes('PHI') || tags.includes('PCI') || a.data.dataCategories.includes('Customer Information') || a.data.dataCategories.includes('Employee Information');
  const sensitive = tags.includes('PHI') || tags.includes('PCI');
  return {
    collectsPii,
    piiCategoriesPresent: tags,
    containsSensitiveCategories: sensitive,
    piaRequired: collectsPii,
    rationale: collectsPii
      ? `System collects PII categories: ${tags.join(', ') || 'derived from data categories'}. PIA is required.`
      : 'No PII collected; PIA not required.',
    systemOfRecordsApplicable: collectsPii && a.business.userTypes.includes('Employees')
  };
}

function buildPia(a: Assessment, pta: PrivacyThresholdAnalysis): PrivacyImpactAssessment | null {
  if (!pta.piaRequired) return null;
  return {
    introduction: `This PIA documents privacy considerations for ${a.business.applicationName}. The system processes ${pta.piiCategoriesPresent.join(', ') || 'PII'} as part of ${a.business.businessProblem}.`,
    informationCollected: `Identifiers, contact information, and (where declared) ${pta.containsSensitiveCategories ? 'special-category data' : 'standard PII'}.`,
    lawfulBasis: [
      'Performance of a contract / agency mission',
      'Compliance with legal obligation',
      'Legitimate interest (security monitoring, fraud prevention)'
    ],
    retentionAndDisposition: 'PII is retained for the minimum period necessary; disposed via cryptographic erasure (KMS key deletion) and S3 lifecycle expiry.',
    individualParticipation: 'Subjects can access, rectify, restrict, and erase their data via the self-service rights portal documented in the privacy notice.',
    dataSharing: a.integrations.map(i => ({
      partner: i.destination,
      purpose: i.description ?? 'Declared integration',
      safeguards: `${i.authentication}; data processing agreement (DPA) required`
    })),
    privacyRisks: [
      { description: 'Re-identification of subjects from analytics workloads', mitigation: 'Pseudonymisation, k-anonymity, separation of operational/analytical IDs' },
      { description: 'Disclosure to unauthorised personnel', mitigation: 'Least-privilege IAM, periodic entitlement review (AC-6)' },
      { description: 'Inability to fulfil data subject rights within statutory window', mitigation: 'Rights workflow with SLA + vendor coordination clauses' }
    ],
    approval: { drafter: 'Privacy Office', reviewer: 'Senior Agency Official for Privacy (SAOP)' }
  };
}

function buildIscp(a: Assessment, p: ArbPackage): ContingencyPlanSummary {
  return {
    systemName: a.business.applicationName,
    rto: a.recovery.rto,
    rpo: a.recovery.rpo,
    recoveryPriorities: [
      'Restore identity and access control plane.',
      'Restore data tier from most-recent verified backup.',
      'Restore application tier behind validated edge.',
      'Restore observability and notify stakeholders.'
    ],
    alternateProcessing: p.recovery.multiRegion ? 'Active-active or warm-standby region per stated RTO' : 'In-region Multi-AZ; cross-region backup destination',
    alternateStorage: p.recovery.multiRegion ? 'Cross-region replicated backup vault (object-lock)' : 'In-region backup vault with object-lock; cross-region copy on critical events',
    notificationProcedures: [
      'BCDR Team notifies on-call within 30 minutes of declared incident.',
      'CSIRT notifies system owner and CISO Office.',
      'External notifications per IRP timeline.'
    ],
    testingCadence: p.recovery.restoreTestingCadence,
    recoveryProcedures: [
      'Failover DNS to alternate region (Route 53 health-checked failover).',
      'Restore database from latest validated backup.',
      'Validate data integrity (HMAC chain / row count).',
      'Promote alternate region to primary.',
      'Communicate restoration to stakeholders.'
    ]
  };
}

function buildIrp(a: Assessment): IncidentResponsePlanSummary {
  return {
    scope: `Cybersecurity incidents affecting ${a.business.applicationName} or the supporting infrastructure.`,
    categories: ['Confidentiality breach', 'Integrity event', 'Availability event', 'Insider threat', 'Supply chain compromise'],
    declarationCriteria: 'Confirmed unauthorised access to CUI/PII, ransomware indicators, sustained availability impact, or any incident triggering external notification.',
    rolesAndResponsibilities: [
      { role: 'On-call SecOps', responsibility: 'Triage, containment, evidence preservation' },
      { role: 'CSIRT Lead', responsibility: 'Declare incident; coordinate response' },
      { role: 'CISO Office', responsibility: 'Executive comms; regulator notification' },
      { role: 'Legal & Privacy', responsibility: 'Notification timelines; breach analysis' },
      { role: 'Application Owner', responsibility: 'System-specific knowledge; remediation' }
    ],
    reportingTimeline: 'US-CERT notification within 1 hour of confirmed incident (FedRAMP IR-6).',
    notificationContacts: ['US-CERT', 'Agency CISO', 'Authorizing Official', 'Affected customers per breach-notification law'],
    containmentSteps: ['Isolate affected components', 'Rotate compromised credentials', 'Disable compromised accounts', 'Block IOCs at edge'],
    eradicationSteps: ['Patch exploited weakness', 'Remove attacker artefacts', 'Rebuild affected hosts from clean baseline'],
    recoverySteps: ['Restore from validated backup', 'Re-enable affected services', 'Validate detection rules captured the event'],
    lessonsLearned: 'Post-incident review within 14 days; action items tracked in POA&M; controls updated in SSP.'
  };
}

function rulesOfBehavior(): string[] {
  return [
    'I will protect my credentials and not share them.',
    'I will use MFA for every authentication.',
    'I will only access data necessary for my authorized duties.',
    'I will not export or copy CUI to unmanaged endpoints.',
    'I will report suspected security incidents to the CSIRT immediately.',
    'I will complete required security and privacy training annually.',
    'I will lock my workstation when away.',
    'I will not install unauthorised software.',
    'I will use only approved communication tools for CUI.',
    'I will follow change-management procedures for production changes.',
    'I understand my activity is logged and may be reviewed.'
  ];
}

function buildCmp(): ConfigurationManagementPlanSummary {
  return {
    baselineSource: 'Infrastructure-as-Code (Terraform/CDK) in the authorized repository.',
    changeControlProcess: 'All production changes are PR-reviewed by two engineers; security-sensitive changes additionally reviewed by Security; deployed via approved CI/CD pipeline.',
    approvalAuthority: 'Engineering Manager + Security designee for sensitive changes; Change Advisory Board for emergency changes.',
    driftDetection: 'AWS Config records resource configuration; nightly IaC plan reports drift; drift exceeding policy triggers an alert.',
    reviewCadence: 'Configuration baselines reviewed quarterly; conformance pack compliance reviewed monthly.'
  };
}

function buildConmon(a: Assessment): ContinuousMonitoringStrategy {
  return {
    vulnScans: { scope: 'OS, web application, database', cadence: 'Monthly (FedRAMP ConMon)' },
    pentest: { cadence: 'Annual', scope: 'Authorization boundary + public attack surface' },
    configCompliance: { scope: 'CIS AWS Foundations, FedRAMP conformance pack', cadence: 'Continuous (AWS Config)' },
    controlSubsetReviews: {
      quarterly: ['AC-2', 'AC-6', 'AU-6', 'CA-7', 'CM-2', 'CM-6', 'CP-2', 'IR-4', 'SI-4'],
      annual: ['Every other in-baseline control via 3PAO']
    },
    reportingCadence: 'Monthly ConMon report to agency authorizing official; significant changes reported via SCR.',
    metrics: [
      'Number of open critical vulnerabilities (target: 0)',
      'Number of POA&M items past scheduled completion (target: 0)',
      'CIS conformance score (target: ≥ 95%)',
      `Mean time to patch high-severity vulnerabilities (target: ≤ 30 days)`,
      `Number of failed audit-logging events (target: 0)`
    ]
  };
}

function buildEAuth(a: Assessment): EAuthWorksheet {
  const sensitive = a.data.sensitiveDataTags.length > 0 || a.data.confidentialToCompany;
  const fedrampHigh = a.compliance.frameworks.includes('FedRAMP') && (a.data.sensitiveDataTags.includes('PHI') || a.data.confidentialToCompany);
  if (fedrampHigh) {
    return {
      assuranceLevel: 'IAL3', authenticatorAssuranceLevel: 'AAL3', federationAssuranceLevel: 'FAL3',
      rationale: 'FedRAMP HIGH with sensitive data — phishing-resistant MFA and in-person identity proofing required.',
      mfaRequired: true, phishingResistantRequired: true
    };
  }
  if (sensitive) {
    return {
      assuranceLevel: 'IAL2', authenticatorAssuranceLevel: 'AAL2', federationAssuranceLevel: 'FAL2',
      rationale: 'FedRAMP MODERATE with sensitive data — remote identity proofing + MFA.',
      mfaRequired: true, phishingResistantRequired: false
    };
  }
  return {
    assuranceLevel: 'IAL1', authenticatorAssuranceLevel: 'AAL2', federationAssuranceLevel: 'FAL1',
    rationale: 'Low-impact system with MFA required for all authenticated access.',
    mfaRequired: true, phishingResistantRequired: false
  };
}

function buildAgencyOverlays(a: Assessment): AgencyOverlay[] {
  const overlays: AgencyOverlay[] = [];
  const ov = a.advanced?.preferredAwsRegion ?? '';
  if (a.compliance.frameworks.includes('IRS Pub 1075')) {
    overlays.push({
      name: 'IRS Publication 1075',
      additionalControls: ['AC-2', 'AU-2', 'AU-3', 'AU-12', 'IA-2', 'SC-7', 'SC-28', 'SC-12'],
      parameterOverrides: [
        { controlId: 'AU-11', value: 'Retain audit records for 7 years (IRS 1075)' },
        { controlId: 'SC-28', value: 'FTI encrypted with FIPS 140-validated module + customer-managed key' }
      ],
      citizenshipRequirement: 'US Persons Only',
      dataLocation: 'CONUS only'
    });
  }
  if (ov.startsWith('us-gov')) {
    overlays.push({
      name: 'DoD Impact Level 4 (IL4)',
      additionalControls: ['SC-7(3)', 'SC-13(1)', 'AC-17(2)'],
      parameterOverrides: [{ controlId: 'IA-2', value: 'CAC/PIV required for privileged access' }],
      citizenshipRequirement: 'US Citizen Only',
      dataLocation: 'AWS GovCloud (us-gov-west-1 / us-gov-east-1)'
    });
  }
  if (a.business.userTypes.includes('Public Users') && a.data.dataCategories.includes('Customer Information')) {
    overlays.push({
      name: 'CMS Acceptable Risk Safeguards (ARS) 5.1',
      additionalControls: ['AC-2', 'AU-2', 'SC-28', 'IA-2'],
      parameterOverrides: [{ controlId: 'AU-11', value: 'Retain audit records for 6 years (HIPAA / CMS ARS)' }],
      citizenshipRequirement: 'No Restriction'
    });
  }
  return overlays;
}

export function buildFedrampPackage(a: Assessment, pkg: ArbPackage): FedrampPackage | null {
  if (!isFedrampInScope(a)) return null;
  const baseline = pickBaseline(a, pkg);
  const baselineSet = fedrampBaselineControls(baseline);
  const sspIds = new Set(pkg.ssp.map(c => c.id));
  const controlsInBaseline = Array.from(baselineSet);
  const controlsNotImplemented = controlsInBaseline.filter(id => !sspIds.has(id));

  // Parameter values that apply to the selected baseline
  const params: { controlId: string; paramId: string; value: string }[] = [];
  for (const id of baselineSet) {
    for (const p of fedrampParametersFor(id, baseline)) {
      params.push({ controlId: p.controlId, paramId: p.paramId, value: p.value });
    }
  }

  const pta = buildPta(a);

  return {
    baseline,
    baselineControlCount: baselineSet.size,
    parameterValues: params,
    controlsInBaseline,
    controlsNotImplemented,
    authorizationBoundary: buildAuthorizationBoundary(a, pkg),
    poam: poamFromArbPackage(pkg),
    pta,
    pia: buildPia(a, pta),
    iscp: buildIscp(a, pkg),
    irp: buildIrp(a),
    rulesOfBehavior: rulesOfBehavior(),
    cmp: buildCmp(),
    conmon: buildConmon(a),
    eAuthWorksheet: buildEAuth(a),
    agencyOverlays: buildAgencyOverlays(a),
    fipsAttestation: fipsStatus()
  };
}
