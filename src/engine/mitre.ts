// MITRE ATT&CK mapping for STRIDE findings. The mapping is a curated
// STRIDE-category × component-layer matrix that picks the most-likely
// ATT&CK tactic + technique pair. CAPEC references are added in parallel
// because detection engineers and pen-testers tend to ask for both.

import { StrideFinding, MitreMapping, CapecReference, Architecture } from '../types/assessment';

interface AttackEntry {
  tacticId: string;
  tacticName: string;
  techniqueId: string;
  techniqueName: string;
}

// STRIDE → ATT&CK (per layer). Default fallback per category at the end.
const ATTACK_BY_CATEGORY_LAYER: Record<string, Record<string, AttackEntry>> = {
  Spoofing: {
    edge:     { tacticId: 'TA0001', tacticName: 'Initial Access',  techniqueId: 'T1190', techniqueName: 'Exploit Public-Facing Application' },
    identity: { tacticId: 'TA0006', tacticName: 'Credential Access', techniqueId: 'T1078', techniqueName: 'Valid Accounts' },
    integration: { tacticId: 'TA0001', tacticName: 'Initial Access', techniqueId: 'T1199', techniqueName: 'Trusted Relationship' },
    app:      { tacticId: 'TA0001', tacticName: 'Initial Access',  techniqueId: 'T1078', techniqueName: 'Valid Accounts' }
  },
  Tampering: {
    data:     { tacticId: 'TA0040', tacticName: 'Impact',           techniqueId: 'T1565', techniqueName: 'Data Manipulation' },
    logging:  { tacticId: 'TA0005', tacticName: 'Defense Evasion',  techniqueId: 'T1562', techniqueName: 'Impair Defenses' },
    backup:   { tacticId: 'TA0040', tacticName: 'Impact',           techniqueId: 'T1490', techniqueName: 'Inhibit System Recovery' },
    app:      { tacticId: 'TA0003', tacticName: 'Persistence',      techniqueId: 'T1554', techniqueName: 'Compromise Client Software Binary' }
  },
  Repudiation: {
    app:      { tacticId: 'TA0005', tacticName: 'Defense Evasion',  techniqueId: 'T1070', techniqueName: 'Indicator Removal' },
    identity: { tacticId: 'TA0005', tacticName: 'Defense Evasion',  techniqueId: 'T1070', techniqueName: 'Indicator Removal' },
    data:     { tacticId: 'TA0005', tacticName: 'Defense Evasion',  techniqueId: 'T1070', techniqueName: 'Indicator Removal' },
    admin:    { tacticId: 'TA0005', tacticName: 'Defense Evasion',  techniqueId: 'T1070', techniqueName: 'Indicator Removal' }
  },
  'Information Disclosure': {
    edge:     { tacticId: 'TA0010', tacticName: 'Exfiltration',     techniqueId: 'T1567', techniqueName: 'Exfiltration Over Web Service' },
    data:     { tacticId: 'TA0009', tacticName: 'Collection',       techniqueId: 'T1530', techniqueName: 'Data from Cloud Storage Object' },
    integration: { tacticId: 'TA0010', tacticName: 'Exfiltration',  techniqueId: 'T1567', techniqueName: 'Exfiltration Over Web Service' },
    app:      { tacticId: 'TA0009', tacticName: 'Collection',       techniqueId: 'T1213', techniqueName: 'Data from Information Repositories' }
  },
  'Denial of Service': {
    edge:     { tacticId: 'TA0040', tacticName: 'Impact',           techniqueId: 'T1498', techniqueName: 'Network Denial of Service' },
    app:      { tacticId: 'TA0040', tacticName: 'Impact',           techniqueId: 'T1499', techniqueName: 'Endpoint Denial of Service' },
    data:     { tacticId: 'TA0040', tacticName: 'Impact',           techniqueId: 'T1485', techniqueName: 'Data Destruction' }
  },
  'Elevation of Privilege': {
    identity: { tacticId: 'TA0004', tacticName: 'Privilege Escalation', techniqueId: 'T1078.004', techniqueName: 'Cloud Accounts' },
    admin:    { tacticId: 'TA0004', tacticName: 'Privilege Escalation', techniqueId: 'T1098', techniqueName: 'Account Manipulation' },
    app:      { tacticId: 'TA0004', tacticName: 'Privilege Escalation', techniqueId: 'T1611', techniqueName: 'Escape to Host' }
  }
};

// Category-level fallback if a layer is missing from the matrix.
const FALLBACK: Record<string, AttackEntry> = {
  Spoofing: { tacticId: 'TA0001', tacticName: 'Initial Access', techniqueId: 'T1078', techniqueName: 'Valid Accounts' },
  Tampering: { tacticId: 'TA0040', tacticName: 'Impact', techniqueId: 'T1565', techniqueName: 'Data Manipulation' },
  Repudiation: { tacticId: 'TA0005', tacticName: 'Defense Evasion', techniqueId: 'T1070', techniqueName: 'Indicator Removal' },
  'Information Disclosure': { tacticId: 'TA0010', tacticName: 'Exfiltration', techniqueId: 'T1041', techniqueName: 'Exfiltration Over C2 Channel' },
  'Denial of Service': { tacticId: 'TA0040', tacticName: 'Impact', techniqueId: 'T1499', techniqueName: 'Endpoint Denial of Service' },
  'Elevation of Privilege': { tacticId: 'TA0004', tacticName: 'Privilege Escalation', techniqueId: 'T1068', techniqueName: 'Exploitation for Privilege Escalation' }
};

export function buildMitreMappings(findings: StrideFinding[], arch: Architecture): MitreMapping[] {
  const compLayer = new Map(arch.components.map(c => [c.id, c.layer]));
  return findings.map((f, idx) => {
    const layer = compLayer.get(f.componentId) ?? 'app';
    const entry =
      ATTACK_BY_CATEGORY_LAYER[f.category]?.[layer] ??
      FALLBACK[f.category];
    return {
      strideFindingIndex: idx,
      attackTacticId: entry.tacticId,
      attackTacticName: entry.tacticName,
      attackTechniqueId: entry.techniqueId,
      attackTechniqueName: entry.techniqueName,
      rationale: `${f.category} against ${layer} layer most-commonly maps to ${entry.techniqueId} (${entry.techniqueName}).`
    };
  });
}

// CAPEC entries — Common Attack Pattern Enumeration and Classification.
// We surface a small curated set that aligns to the STRIDE categories
// present in the threat model.
interface CapecDef {
  id: string;
  name: string;
  description: string;
  matchesStride: StrideFinding['category'][];
  matchesLayer?: string[];
}

const CAPEC_CATALOG: CapecDef[] = [
  { id: 'CAPEC-115', name: 'Authentication Bypass', description: 'Adversary bypasses application authentication via flawed validation, missing checks, or token misuse.', matchesStride: ['Spoofing'], matchesLayer: ['app', 'edge', 'identity'] },
  { id: 'CAPEC-151', name: 'Identity Spoofing', description: 'Attacker impersonates a legitimate user or system via stolen, forged, or replayed identity tokens.', matchesStride: ['Spoofing'] },
  { id: 'CAPEC-22',  name: 'Exploiting Trust in Client', description: 'Attacker manipulates client-side state or trust assumptions to deceive the server.', matchesStride: ['Spoofing', 'Tampering'], matchesLayer: ['app', 'edge'] },
  { id: 'CAPEC-100', name: 'Overflow Buffers', description: 'Buffer-overflow conditions allow code execution or tampering of in-memory data.', matchesStride: ['Tampering', 'Elevation of Privilege'] },
  { id: 'CAPEC-66',  name: 'SQL Injection', description: 'Improperly sanitised inputs allow attacker-supplied SQL to execute against the data tier.', matchesStride: ['Tampering', 'Information Disclosure'], matchesLayer: ['app', 'data'] },
  { id: 'CAPEC-63',  name: 'Cross-Site Scripting (XSS)', description: 'Untrusted output executes in the victim browser, enabling token theft or coerced actions.', matchesStride: ['Tampering', 'Information Disclosure'], matchesLayer: ['edge', 'app'] },
  { id: 'CAPEC-148', name: 'Content Spoofing', description: 'Attacker manipulates server-rendered or cached content to mislead users.', matchesStride: ['Tampering', 'Spoofing'], matchesLayer: ['edge'] },
  { id: 'CAPEC-93',  name: 'Log Injection-Tampering-Forging', description: 'Attacker injects, modifies, or removes log entries to defeat forensics.', matchesStride: ['Tampering', 'Repudiation'], matchesLayer: ['logging', 'app'] },
  { id: 'CAPEC-117', name: 'Interception (Sniffing)', description: 'Attacker captures network traffic to recover credentials or sensitive payloads.', matchesStride: ['Information Disclosure'], matchesLayer: ['integration', 'edge'] },
  { id: 'CAPEC-37',  name: 'Retrieve Embedded Sensitive Data', description: 'Sensitive data embedded in objects (debug, comments, error messages) is harvested.', matchesStride: ['Information Disclosure'], matchesLayer: ['app', 'edge'] },
  { id: 'CAPEC-125', name: 'Flooding', description: 'Resource exhaustion via volumetric requests denies service.', matchesStride: ['Denial of Service'], matchesLayer: ['edge', 'app'] },
  { id: 'CAPEC-130', name: 'Excessive Allocation', description: 'Application allocates resources without bound on attacker-controlled input, exhausting capacity.', matchesStride: ['Denial of Service'], matchesLayer: ['app', 'data'] },
  { id: 'CAPEC-122', name: 'Privilege Abuse', description: 'Authorised account performs actions beyond intended scope.', matchesStride: ['Elevation of Privilege'], matchesLayer: ['identity', 'admin', 'app'] },
  { id: 'CAPEC-233', name: 'Privilege Escalation', description: 'Attacker leverages a software flaw or misconfiguration to elevate privileges within the system.', matchesStride: ['Elevation of Privilege'] },
  { id: 'CAPEC-180', name: 'Exploiting Incorrectly Configured Access Control Lists', description: 'Misconfigured ACLs grant unauthorised actors access to protected resources.', matchesStride: ['Information Disclosure', 'Elevation of Privilege'], matchesLayer: ['data', 'identity'] }
];

export function buildCapecReferences(findings: StrideFinding[], arch: Architecture): CapecReference[] {
  const compLayer = new Map(arch.components.map(c => [c.id, c.layer]));
  const out = new Map<string, CapecReference>();
  for (const f of findings) {
    const layer = compLayer.get(f.componentId) ?? 'app';
    for (const def of CAPEC_CATALOG) {
      if (!def.matchesStride.includes(f.category)) continue;
      if (def.matchesLayer && !def.matchesLayer.includes(layer)) continue;
      const ref = out.get(def.id) ?? {
        capecId: def.id,
        name: def.name,
        description: def.description,
        strideCategories: [],
        appliesToComponentIds: []
      };
      if (!ref.strideCategories.includes(f.category)) ref.strideCategories.push(f.category);
      if (!ref.appliesToComponentIds.includes(f.componentId)) ref.appliesToComponentIds.push(f.componentId);
      out.set(def.id, ref);
    }
  }
  return Array.from(out.values());
}
