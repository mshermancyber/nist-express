// STRIDE threat model. Each component is walked through the six
// STRIDE categories with deterministic rules based on its layer,
// trust zone, sensitive-data flag, and authentication mechanism.
// Likelihood × Impact yields the inherent risk; applying the
// recommended controls reduces it to the residual risk.

import {
  Architecture,
  StrideFinding,
  Categorization,
  Assessment,
  ArchitectureComponent,
  FlowStrideFinding
} from '../types/assessment';

type Risk = 'Low' | 'Medium' | 'High' | 'Critical';
type LM = 'Low' | 'Medium' | 'High';

const RISK_MATRIX: Record<LM, Record<LM, Risk>> = {
  Low: { Low: 'Low', Medium: 'Low', High: 'Medium' },
  Medium: { Low: 'Low', Medium: 'Medium', High: 'High' },
  High: { Low: 'Medium', Medium: 'High', High: 'Critical' }
};

function risk(likelihood: LM, impact: LM): Risk {
  return RISK_MATRIX[likelihood][impact];
}

function reduce(r: Risk, steps: number): Risk {
  const order: Risk[] = ['Low', 'Medium', 'High', 'Critical'];
  const idx = Math.max(0, order.indexOf(r) - steps);
  return order[idx]!;
}

function add(findings: StrideFinding[], f: StrideFinding) {
  // Final residual = inherent reduced by 1 step for each distinct mitigation,
  // capped at 2 (we will not claim controls eliminate risk entirely).
  const reductionSteps = Math.min(2, f.mitigations.length);
  f.residualRisk = reduce(f.inherentRisk, reductionSteps);
  findings.push(f);
}

function categoryImpact(cat: Categorization): LM {
  return cat.overallCategorization === 'High'
    ? 'High'
    : cat.overallCategorization === 'Moderate'
    ? 'Medium'
    : 'Low';
}

export function buildThreatModel(
  a: Assessment,
  arch: Architecture,
  cat: Categorization
): StrideFinding[] {
  const findings: StrideFinding[] = [];
  const baseImpact = categoryImpact(cat);
  const elevated: LM = baseImpact === 'Low' ? 'Medium' : 'High';
  const isPublic = a.business.userTypes.includes('Public Users') || a.business.userTypes.includes('Customers');

  for (const c of arch.components) {
    const sensitive = c.containsSensitiveData;

    // ---- Spoofing ----
    if (c.layer === 'edge' || c.layer === 'app' || c.layer === 'identity' || c.layer === 'integration') {
      const likelihood: LM = c.layer === 'integration' ? 'High' : c.layer === 'edge' ? (isPublic ? 'High' : 'Medium') : 'Medium';
      const impact: LM = c.layer === 'identity' ? 'High' : sensitive ? elevated : baseImpact;
      const mit = ['IA-2', 'IA-5', c.layer === 'identity' ? 'IA-8' : 'AC-3'];
      if (isPublic && c.layer === 'edge') mit.push('SC-7');
      add(findings, {
        componentId: c.id, componentName: c.name,
        category: 'Spoofing',
        description: c.layer === 'identity'
          ? `Adversary attempts to impersonate ${c.name} or forge tokens to obtain unauthorized access.`
          : c.layer === 'integration'
          ? `Adversary impersonates the legitimate integration counterpart to exfiltrate data or push malicious payloads.`
          : `Adversary attempts to abuse exposed endpoints with stolen, forged, or replayed credentials.`,
        attackPath: `Threat actor -> ${c.name} -> downstream component using stolen identity assertions.`,
        likelihood, impact,
        inherentRisk: risk(likelihood, impact),
        mitigations: mit,
        residualRisk: 'Low'
      });
    }

    // ---- Tampering ----
    if (c.layer === 'data' || c.layer === 'logging' || c.layer === 'app' || c.layer === 'backup') {
      const likelihood: LM = c.layer === 'app' ? 'Medium' : 'Low';
      const impact: LM = c.layer === 'logging' ? 'High' : sensitive ? elevated : baseImpact;
      const mit = ['SI-7', 'SC-8'];
      if (c.layer === 'logging') mit.push('AU-9');
      if (c.layer === 'data' || c.layer === 'backup') mit.push('SC-28');
      add(findings, {
        componentId: c.id, componentName: c.name,
        category: 'Tampering',
        description: c.layer === 'logging'
          ? `Adversary modifies or deletes audit records on ${c.name} to cover tracks.`
          : c.layer === 'backup'
          ? `Adversary tampers with backups to defeat recovery (e.g. ransomware-aware attacker).`
          : `Unauthorized modification of data or code at ${c.name}.`,
        attackPath: `Credential theft / supply-chain -> ${c.name} -> integrity loss.`,
        likelihood, impact,
        inherentRisk: risk(likelihood, impact),
        mitigations: mit,
        residualRisk: 'Low'
      });
    }

    // ---- Repudiation ----
    if (c.layer === 'app' || c.layer === 'identity' || c.layer === 'data' || c.layer === 'admin') {
      const likelihood: LM = c.layer === 'admin' ? 'Medium' : 'Low';
      const impact: LM = baseImpact;
      add(findings, {
        componentId: c.id, componentName: c.name,
        category: 'Repudiation',
        description: c.layer === 'admin'
          ? `Privileged operator denies performing destructive operations.`
          : `User or service denies an action; absence of non-repudiable logs would block forensics.`,
        attackPath: `Action performed -> no/weak audit -> later denial.`,
        likelihood, impact,
        inherentRisk: risk(likelihood, impact),
        mitigations: ['AU-2', 'AU-3', 'AU-6', 'AU-12'],
        residualRisk: 'Low'
      });
    }

    // ---- Information Disclosure ----
    if (sensitive || c.layer === 'data' || c.layer === 'integration' || c.layer === 'edge') {
      const likelihood: LM = c.layer === 'edge' && isPublic ? 'High' : sensitive ? 'Medium' : 'Low';
      const impact: LM = sensitive ? 'High' : baseImpact;
      const mit = ['SC-8', 'SC-13', 'AC-3', 'AC-6'];
      if (c.encryptionAtRest) mit.push('SC-28');
      if (c.layer === 'edge') mit.push('SC-7');
      add(findings, {
        componentId: c.id, componentName: c.name,
        category: 'Information Disclosure',
        description: sensitive
          ? `Sensitive data (PII/PCI/PHI/IP) handled by ${c.name} may be disclosed via misconfiguration, weak crypto, or over-permissive access.`
          : `Unauthorized read of data flowing through ${c.name}.`,
        attackPath: `Misconfig / over-broad IAM / sniffing -> read of sensitive payload.`,
        likelihood, impact,
        inherentRisk: risk(likelihood, impact),
        mitigations: mit,
        residualRisk: 'Low'
      });
    }

    // ---- Denial of Service ----
    if (c.layer === 'edge' || c.layer === 'app' || c.layer === 'data') {
      const likelihood: LM = c.layer === 'edge' && isPublic ? 'High' : 'Medium';
      const impact: LM = cat.availabilityImpact === 'High' ? 'High' : cat.availabilityImpact === 'Moderate' ? 'Medium' : 'Low';
      const mit = ['SC-7', 'SI-4'];
      if (c.layer === 'edge') mit.push('SI-10');
      if (cat.availabilityImpact === 'High') mit.push('CP-2', 'CP-10');
      add(findings, {
        componentId: c.id, componentName: c.name,
        category: 'Denial of Service',
        description: c.layer === 'edge'
          ? `Volumetric or L7 attack saturates ${c.name} causing service outage.`
          : `Resource exhaustion at ${c.name} (e.g. connection storm, slow queries).`,
        attackPath: `Botnet / abusive client -> ${c.name} -> downstream capacity loss.`,
        likelihood, impact,
        inherentRisk: risk(likelihood, impact),
        mitigations: mit,
        residualRisk: 'Low'
      });
    }

    // ---- Elevation of Privilege ----
    if (c.layer === 'identity' || c.layer === 'admin' || c.layer === 'app') {
      const likelihood: LM = c.layer === 'identity' ? 'Medium' : c.layer === 'admin' ? 'Medium' : 'Low';
      const impact: LM = 'High';
      add(findings, {
        componentId: c.id, componentName: c.name,
        category: 'Elevation of Privilege',
        description: c.layer === 'identity'
          ? `IAM/SAML misconfiguration grants over-broad rights; assumed role chain bypasses boundary.`
          : c.layer === 'admin'
          ? `Operator escalates from standard admin to root/cross-account access.`
          : `Service privilege escalation via SSRF, IMDSv1, or excessive task-role permissions.`,
        attackPath: `Initial foothold -> ${c.name} -> elevated privileges across account/boundary.`,
        likelihood, impact,
        inherentRisk: risk(likelihood, impact),
        mitigations: ['AC-6', 'AC-3', 'IA-2', 'CM-7', 'SI-4'],
        residualRisk: 'Low'
      });
    }
  }

  return findings;
}

export function summarizeRiskCounts(findings: StrideFinding[]): { inherent: Record<Risk, number>; residual: Record<Risk, number> } {
  const blank = (): Record<Risk, number> => ({ Low: 0, Medium: 0, High: 0, Critical: 0 });
  const inherent = blank();
  const residual = blank();
  for (const f of findings) {
    inherent[f.inherentRisk] += 1;
    residual[f.residualRisk] += 1;
  }
  return { inherent, residual };
}

// STRIDE per data-flow — adds per-flow findings to complement the
// per-component model. DFD-driven STRIDE is the canonical form for
// most published methodologies.
export function buildFlowThreatModel(
  arch: Architecture,
  cat: Categorization
): FlowStrideFinding[] {
  const out: FlowStrideFinding[] = [];
  const compName = new Map(arch.components.map(c => [c.id, c.name]));
  const compLayer = new Map(arch.components.map(c => [c.id, c.layer]));
  const baseImpact: LM = cat.overallCategorization === 'High' ? 'High' : cat.overallCategorization === 'Moderate' ? 'Medium' : 'Low';

  const push = (f: FlowStrideFinding) => {
    const steps = Math.min(2, f.mitigations.length);
    f.residualRisk = reduce(f.inherentRisk, steps);
    out.push(f);
  };

  for (const flow of arch.flows) {
    const fromName = compName.get(flow.fromComponentId) ?? flow.fromComponentId;
    const toName = compName.get(flow.toComponentId) ?? flow.toComponentId;
    const baseFlow = {
      flowId: flow.id,
      flowLabel: flow.label,
      fromComponentName: fromName,
      toComponentName: toName
    };

    // Spoofing — endpoint identity is spoofable for cross-boundary flows.
    if (flow.crossesTrustBoundary) {
      const likelihood: LM = flow.encrypted ? 'Medium' : 'High';
      const impact: LM = flow.carriesSensitiveData ? 'High' : baseImpact;
      push({
        ...baseFlow,
        category: 'Spoofing',
        description: `Either endpoint of "${flow.label}" can be impersonated by an attacker that controls a trusted-zone foothold.`,
        likelihood, impact,
        inherentRisk: risk(likelihood, impact),
        mitigations: ['IA-2', 'IA-5', 'SC-7'],
        residualRisk: 'Low'
      });
    }

    // Tampering — payload modification in flight.
    {
      const likelihood: LM = flow.encrypted ? 'Low' : 'High';
      const impact: LM = flow.carriesSensitiveData ? 'High' : baseImpact;
      push({
        ...baseFlow,
        category: 'Tampering',
        description: flow.encrypted
          ? `In-flight tampering of "${flow.label}" is defeated by TLS integrity but trust hinges on certificate validation.`
          : `Unencrypted flow "${flow.label}" can be silently modified by any on-path actor.`,
        likelihood, impact,
        inherentRisk: risk(likelihood, impact),
        mitigations: flow.encrypted ? ['SC-8', 'SC-13'] : ['SC-8'],
        residualRisk: 'Low'
      });
    }

    // Information Disclosure — payload visibility.
    if (flow.carriesSensitiveData || !flow.encrypted) {
      const likelihood: LM = flow.encrypted ? 'Low' : 'High';
      const impact: LM = flow.carriesSensitiveData ? 'High' : 'Medium';
      push({
        ...baseFlow,
        category: 'Information Disclosure',
        description: flow.encrypted
          ? `Sensitive payload on "${flow.label}" is observable to anyone holding the TLS key — protect with mTLS or field-level encryption.`
          : `Cleartext flow "${flow.label}" exposes data to any on-path observer.`,
        likelihood, impact,
        inherentRisk: risk(likelihood, impact),
        mitigations: flow.encrypted ? ['SC-8', 'SC-12', 'SC-28'] : ['SC-8'],
        residualRisk: 'Low'
      });
    }

    // Repudiation — between component pairs, who logs the action?
    if (compLayer.get(flow.fromComponentId) === 'app' || compLayer.get(flow.toComponentId) === 'data') {
      push({
        ...baseFlow,
        category: 'Repudiation',
        description: `If only one side logs "${flow.label}", a compromised endpoint can deny actions later.`,
        likelihood: 'Low', impact: baseImpact,
        inherentRisk: risk('Low', baseImpact),
        mitigations: ['AU-2', 'AU-3', 'AU-12'],
        residualRisk: 'Low'
      });
    }

    // Denial of Service — high-fanout flows.
    if (compLayer.get(flow.toComponentId) === 'data' || compLayer.get(flow.toComponentId) === 'app') {
      const likelihood: LM = compLayer.get(flow.fromComponentId) === 'edge' ? 'High' : 'Medium';
      const impact: LM = cat.availabilityImpact === 'High' ? 'High' : 'Medium';
      push({
        ...baseFlow,
        category: 'Denial of Service',
        description: `Volumetric or amplification attack against "${flow.label}" can saturate the downstream component.`,
        likelihood, impact,
        inherentRisk: risk(likelihood, impact),
        mitigations: ['SC-7', 'SI-4', 'CP-2'],
        residualRisk: 'Low'
      });
    }
  }

  return out;
}
