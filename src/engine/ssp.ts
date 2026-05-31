// NIST 800-53 Rev 5 System Security Plan (SSP) engine.
// Selects controls applicable for the system's categorization, tailors
// implementation statements using actual architecture components, and
// records inheritance (Customer / AWS / Hybrid / Common). Each control
// carries the rationale (which input drove its selection).

import {
  Assessment, Categorization, Architecture, SspControl, ImpactLevel, ControlInheritance
} from '../types/assessment';
import { NIST_CONTROLS, NistControlDefinition } from '../data/nistControls';
import { baselineFromCategory } from './categorization';

function componentNamesByLayer(arch: Architecture, layer: string): string[] {
  return arch.components.filter(c => c.layer === layer).map(c => c.name);
}

function evidenceFor(controlId: string, arch: Architecture): string[] {
  const ev: string[] = [];
  const namesByLayer = (l: string) => componentNamesByLayer(arch, l);
  switch (controlId) {
    case 'AC-2': case 'AC-3': case 'AC-6': case 'IA-2': case 'IA-5': case 'IA-8':
      ev.push(...namesByLayer('identity')); break;
    case 'AC-17':
      ev.push('AWS Systems Manager Session Manager', 'AWS IAM Identity Center'); break;
    case 'AU-2': case 'AU-3': case 'AU-6': case 'AU-9': case 'AU-12': case 'CA-7':
      ev.push(...namesByLayer('logging'), ...namesByLayer('monitoring')); break;
    case 'CM-2': case 'CM-6': case 'CM-7': case 'CM-8':
      ev.push('AWS Config', 'AWS Organizations / SCPs', 'Infrastructure-as-Code repository'); break;
    case 'CP-2': case 'CP-9': case 'CP-10':
      ev.push(...namesByLayer('backup'), 'AWS Backup vault lock policy'); break;
    case 'SC-7':
      ev.push(...namesByLayer('edge')); break;
    case 'SC-8': case 'SC-13':
      ev.push('TLS 1.2+ everywhere (ALB/CloudFront/API GW)'); break;
    case 'SC-12': case 'SC-28':
      ev.push('AWS KMS (Customer-Managed Keys)', ...namesByLayer('data')); break;
    case 'SI-2': case 'SI-7': case 'SI-10':
      ev.push(...namesByLayer('app'), 'Amazon Inspector', 'Image scanning in CI'); break;
    case 'SI-4':
      ev.push('Amazon GuardDuty', 'AWS Security Hub'); break;
    case 'IR-4': case 'IR-6':
      ev.push('CSIRT runbooks', 'AWS Detective for investigation'); break;
    case 'RA-5':
      ev.push('Amazon Inspector', 'SAST/DAST/SCA in CI'); break;
    default:
      ev.push('See architecture diagram and operational runbooks'); break;
  }
  return Array.from(new Set(ev));
}

function inheritanceFor(def: NistControlDefinition, a: Assessment): ControlInheritance {
  if (a.hosting.model === 'AWS') return def.defaultInheritance;
  if (a.hosting.model === 'On-Prem') {
    // On-prem flips everything AWS would otherwise carry back to the customer
    return def.defaultInheritance === 'AWS (Provider)' ? 'Customer' : def.defaultInheritance;
  }
  // Other clouds: keep AWS-attested controls as Common Control aspirationally
  if (def.defaultInheritance === 'AWS (Provider)') return 'Common Control';
  return def.defaultInheritance;
}

function rationaleFor(def: NistControlDefinition, a: Assessment, cat: Categorization): string {
  const reasons: string[] = [];
  if (def.baselines.includes(cat.overallCategorization)) {
    reasons.push(`Required for FIPS 199 ${cat.overallCategorization} baseline`);
  }
  if (def.id === 'AC-6' && a.data.confidentialToCompany) reasons.push('Confidentiality requirement triggered least-privilege focus');
  if (def.id === 'IA-2' && a.data.confidentialToCompany) reasons.push('Confidentiality requirement triggered MFA mandate');
  if ((def.id === 'CP-2' || def.id === 'CP-9' || def.id === 'CP-10') && cat.availabilityImpact === 'High') {
    reasons.push(`HIGH availability impact (RTO=${a.recovery.rto}, RPO=${a.recovery.rpo})`);
  }
  if (def.id === 'SC-28' && (a.data.sensitiveDataTags.length > 0)) reasons.push(`Sensitive data tags: ${a.data.sensitiveDataTags.join(', ')}`);
  if (a.compliance.frameworks.includes('PCI DSS') && (def.id === 'AU-2' || def.id === 'SC-8' || def.id === 'SC-28')) {
    reasons.push('PCI DSS scope reinforces logging + crypto');
  }
  if (a.compliance.frameworks.includes('HIPAA') && (def.id === 'AC-2' || def.id === 'AU-2' || def.id === 'SC-28')) {
    reasons.push('HIPAA Security Rule alignment');
  }
  return reasons.join('; ') || `Baseline ${def.id} applies to the system category`;
}

function statementFor(def: NistControlDefinition, a: Assessment, arch: Architecture): string {
  const apps = componentNamesByLayer(arch, 'app').join(', ') || 'application tier';
  const data = componentNamesByLayer(arch, 'data').join(', ') || 'data tier';
  const idp = componentNamesByLayer(arch, 'identity').join(', ');
  const logging = componentNamesByLayer(arch, 'logging').join(', ');
  const monitoring = componentNamesByLayer(arch, 'monitoring').join(', ');

  switch (def.id) {
    case 'AC-2':
      return `Accounts for ${a.business.applicationName} are provisioned through ${idp || 'Okta + AWS IAM Identity Center'} and synchronized to AWS via permission sets. Joiner-mover-leaver events are sourced from HRIS; quarterly entitlement reviews are mandatory.`;
    case 'AC-3':
      return `Access decisions are enforced at API Gateway, application authorizers, and resource-based policies on ${data}. Allow lists are explicit; default-deny is the system posture.`;
    case 'AC-6':
      return `IAM roles for ${apps} grant only the actions needed for the function they implement. Wildcard actions and resources are prohibited by SCP. Privileged access is time-bound through AWS IAM Identity Center session policies.`;
    case 'AC-17':
      return `Remote administrative access is performed through AWS Systems Manager Session Manager, federated through ${idp || 'Okta'} with MFA enforced at the IdP.`;
    case 'AU-2':
      return `Auditable events include authentication outcomes, privilege changes, KMS key usage, security-group changes, data exports, and CloudTrail tampering. Events are written by ${logging || 'CloudTrail, CloudWatch Logs, AWS Config'}.`;
    case 'AU-3':
      return `Audit records capture identity, source IP, action, resource, outcome, and timestamp. CloudTrail and structured application JSON logs both meet this requirement.`;
    case 'AU-6':
      return `${monitoring || 'GuardDuty and Security Hub'} aggregate findings; on-call rotates 24×7 with severity-based response SLA.`;
    case 'AU-9':
      return `The log archive bucket enforces S3 Object Lock (Compliance mode) with retention of ${a.advanced?.loggingRetentionDays ?? 365} days. KMS key policy denies deletion except by the security team.`;
    case 'AU-12':
      return `Each component in ${apps}, ${data}, and the edge tier emits logs to ${logging || 'CloudWatch Logs'}; CloudTrail covers AWS API activity.`;
    case 'CA-7':
      return `Continuous monitoring metrics — config compliance, GuardDuty severity, IAM Access Analyzer findings — are reviewed weekly and reported to system owner monthly.`;
    case 'CM-2': case 'CM-6':
      return `The system baseline is defined in Infrastructure-as-Code (Terraform/CDK); AWS Config conformance packs (CIS AWS Foundations, NIST 800-53) enforce mandatory settings.`;
    case 'CM-7':
      return `Only the ports, services, and IAM actions required for ${apps} are enabled; unused defaults are disabled via baseline modules.`;
    case 'CM-8':
      return `AWS Config maintains the authoritative inventory; deviation from the IaC baseline triggers an alert.`;
    case 'CP-2': case 'CP-9': case 'CP-10':
      return `${a.business.applicationName} targets RTO ${a.recovery.rto} and RPO ${a.recovery.rpo}. ${componentNamesByLayer(arch, 'backup').join(', ') || 'AWS Backup'} provides ${a.recovery.rpo === 'No Data Loss' ? 'continuous' : 'scheduled'} backups with vault-lock retention. Restore drills are executed quarterly.`;
    case 'IA-2': case 'IA-8':
      return `Identity is established at ${idp || 'Okta'} and federated into AWS via SAML; MFA is required for all human access.`;
    case 'IA-5':
      return `Authenticator policies inherit from the Okta password policy (NIST 800-63B aligned); secrets for ${apps} are stored in AWS Secrets Manager with automatic rotation.`;
    case 'IR-4': case 'IR-6':
      return `Incident response is handled by the central CSIRT using documented runbooks. Severity-based regulatory notification timelines are tracked in the IR plan.`;
    case 'SC-7':
      return `Boundary protection is provided by ${componentNamesByLayer(arch, 'edge').join(', ') || 'AWS WAF + CloudFront + ALB'}; egress is constrained by VPC endpoints and SCPs.`;
    case 'SC-8':
      return `All traffic uses TLS 1.2 or higher with modern ciphers; certificates are managed by AWS Certificate Manager and rotated automatically.`;
    case 'SC-12': case 'SC-13':
      return `Cryptographic keys are managed by AWS KMS (FIPS 140 validated); CMKs rotate annually. Key policies separate key administrators from key users.`;
    case 'SC-28':
      return `Data at rest in ${data} is encrypted with KMS CMKs. Tables/buckets with sensitive tags use dedicated CMKs with restrictive grants.`;
    case 'SI-2':
      return `Critical CVEs are patched within 7 days; high within 30; SSM Patch Manager and managed container image rebuilds enforce cadence.`;
    case 'SI-4':
      return `Amazon GuardDuty and AWS Security Hub monitor the system continuously; detection rules cover privilege escalation, anomalous API usage, and data exfiltration patterns.`;
    case 'SI-7':
      return `Container images and artifacts are signed; image-scanning gates deploys; CloudTrail integrity validation is enabled.`;
    case 'SI-10':
      return `All inputs are validated server-side using JSON-schema or equivalent. AWS WAF managed rules block obvious malicious patterns at the edge.`;
    case 'RA-5':
      return `Amazon Inspector continuously scans EC2/ECR/Lambda; SAST/DAST/SCA run in CI; findings are tracked in a central vulnerability backlog with SLAs.`;
    default:
      return `${def.shortDescription} Implementation is documented in operational runbooks and aligned to the architecture for ${a.business.applicationName}.`;
  }
}

export function buildSsp(a: Assessment, cat: Categorization, arch: Architecture): SspControl[] {
  const baseline = baselineFromCategory(cat.overallCategorization);
  const excluded = new Set(a.advanced?.excludeControlIds ?? []);
  const extras = new Set(a.advanced?.customControlIds ?? []);

  const out: SspControl[] = [];
  for (const def of NIST_CONTROLS) {
    if (excluded.has(def.id)) continue;
    const inBaseline = def.baselines.some((b: ImpactLevel) => baseline.includes(b));
    if (!inBaseline && !extras.has(def.id)) continue;

    out.push({
      id: def.id,
      name: def.name,
      family: def.family,
      baseline: def.baselines,
      implementationStatement: statementFor(def, a, arch),
      responsibleParty: def.defaultResponsibleParty,
      evidence: evidenceFor(def.id, arch),
      inheritance: inheritanceFor(def, a),
      assessmentGuidance: def.assessmentGuidance,
      implementationStatus: 'Implemented',
      rationale: rationaleFor(def, a, cat),
      cisMappings: def.cisMappings
    });
  }

  return out;
}
