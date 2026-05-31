// Attack tree generator. For each residual risk (Critical / High) we
// emit a small DAG: goal → tactic(s) → technique(s) → precondition(s).
// Roots are tightly coupled to the STRIDE category of the finding
// that produced the risk so the tree explains how an adversary would
// realise the residual condition.

import { AttackTree, AttackTreeNode, ResidualRisk, StrideFinding } from '../types/assessment';

interface TreeTemplate {
  goal: string;
  tactics: { name: string; techniques: string[]; preconditions: string[] }[];
}

const TEMPLATES: Partial<Record<StrideFinding['category'], TreeTemplate>> = {
  Spoofing: {
    goal: 'Authenticate as a legitimate principal',
    tactics: [
      { name: 'Credential Theft', techniques: ['Phishing (T1566)', 'Credential dumping (T1003)'], preconditions: ['Email reachability', 'Reused passwords'] },
      { name: 'Token Replay', techniques: ['Web session cookie (T1539)'], preconditions: ['Cleartext transit', 'Long-lived tokens'] }
    ]
  },
  Tampering: {
    goal: 'Modify data or code without authorisation',
    tactics: [
      { name: 'Supply Chain Compromise', techniques: ['Compromise software supply chain (T1195)'], preconditions: ['Unsigned artifacts', 'Permissive dependency policy'] },
      { name: 'Cloud API Abuse', techniques: ['Cloud Service Modification (T1578)'], preconditions: ['Over-broad IAM', 'No SCP guardrails'] }
    ]
  },
  'Information Disclosure': {
    goal: 'Read sensitive data outside policy',
    tactics: [
      { name: 'Misconfiguration', techniques: ['Cloud Storage Object (T1530)'], preconditions: ['Public bucket', 'Missing Block-Public-Access'] },
      { name: 'Exfiltration', techniques: ['Exfiltration over web service (T1567)'], preconditions: ['Outbound DNS allowed', 'No DLP'] }
    ]
  },
  'Denial of Service': {
    goal: 'Make the service unavailable',
    tactics: [
      { name: 'Volumetric', techniques: ['Network DoS (T1498)'], preconditions: ['No WAF rate-limit', 'No Shield Advanced'] },
      { name: 'Application Layer', techniques: ['Endpoint DoS (T1499)'], preconditions: ['Unbounded request size', 'No backpressure'] }
    ]
  },
  Repudiation: {
    goal: 'Deny having performed an action',
    tactics: [
      { name: 'Log Tampering', techniques: ['Indicator Removal (T1070)'], preconditions: ['Mutable log store', 'No CloudTrail integrity'] }
    ]
  },
  'Elevation of Privilege': {
    goal: 'Escalate from a low-privilege foothold',
    tactics: [
      { name: 'Cloud IAM Abuse', techniques: ['Account Manipulation (T1098)'], preconditions: ['Permissive iam:PassRole', 'No IAM Access Analyzer'] },
      { name: 'Container Escape', techniques: ['Escape to Host (T1611)'], preconditions: ['Privileged containers', 'Outdated runtime'] }
    ]
  }
};

function nodeId(prefix: string, i: number) { return `${prefix}_${i}`; }

export function buildAttackTrees(threats: StrideFinding[], risks: ResidualRisk[]): AttackTree[] {
  const trees: AttackTree[] = [];
  // Pair each high-severity STRIDE finding with the residual risk that mentions it.
  for (let i = 0; i < risks.length; i++) {
    const r = risks[i]!;
    if (r.residualRisk !== 'Critical' && r.residualRisk !== 'High') continue;
    const match = r.description.match(/STRIDE\/([A-Za-z &]+)\]/);
    const category = (match?.[1] || 'Spoofing') as StrideFinding['category'];
    const tpl = TEMPLATES[category] ?? TEMPLATES.Spoofing!;
    const root: AttackTreeNode = {
      id: nodeId('goal', i),
      label: tpl.goal,
      type: 'goal',
      children: tpl.tactics.map((t, j) => ({
        id: nodeId(`tactic_${i}`, j),
        label: t.name,
        type: 'tactic' as const,
        children: [
          ...t.techniques.map((tech, k) => ({ id: nodeId(`technique_${i}_${j}`, k), label: tech, type: 'technique' as const, children: [] })),
          ...t.preconditions.map((pre, k) => ({ id: nodeId(`pre_${i}_${j}`, k), label: pre, type: 'precondition' as const, children: [] }))
        ]
      }))
    };
    trees.push({ riskId: r.id, goal: tpl.goal, root });
  }
  return trees;
}
