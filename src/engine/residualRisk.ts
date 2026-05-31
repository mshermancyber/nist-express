// Residual Risk Register. Pulls residual entries from the STRIDE
// model, operational threats, compliance gaps, and recovery gaps
// into a single risk register suitable for ARB review.

import {
  ResidualRisk, StrideFinding, OperationalThreat, ComplianceMapping, RecoveryAssessment
} from '../types/assessment';

function inh(level: 'Low' | 'Medium' | 'High' | 'Critical'): 'Low' | 'Medium' | 'High' | 'Critical' { return level; }

function uid(prefix: string, idx: number) { return `${prefix}-${String(idx + 1).padStart(3, '0')}`; }

export function buildResidualRisk(
  threats: StrideFinding[],
  ops: OperationalThreat[],
  mappings: ComplianceMapping[],
  recovery: RecoveryAssessment
): ResidualRisk[] {
  const out: ResidualRisk[] = [];
  let idx = 0;

  for (const t of threats) {
    if (t.residualRisk === 'Low') continue;
    out.push({
      id: uid('RR', idx++),
      description: `[STRIDE/${t.category}] ${t.componentName}: ${t.description}`,
      source: 'STRIDE',
      inherentRisk: inh(t.inherentRisk),
      residualRisk: inh(t.residualRisk),
      rationale: `Mitigations applied (${t.mitigations.join(', ')}) reduced inherent ${t.inherentRisk} to residual ${t.residualRisk}.`,
      treatment: t.residualRisk === 'Critical' ? 'Mitigate' : 'Accept',
      owner: 'Application Owner'
    });
  }

  for (const o of ops) {
    const lvl = riskFromLM(o.likelihood, o.impact);
    if (lvl === 'Low') continue;
    out.push({
      id: uid('RR', idx++),
      description: `[Operational/${o.category}] ${o.description}`,
      source: 'Operational',
      inherentRisk: lvl,
      residualRisk: lvl,
      rationale: o.recommendation,
      treatment: lvl === 'Critical' ? 'Mitigate' : 'Accept',
      owner: 'Platform / SRE'
    });
  }

  for (const m of mappings) {
    if (m.coverage !== 'Gap') continue;
    out.push({
      id: uid('RR', idx++),
      description: `[Compliance/${m.framework}] ${m.controlId} — ${m.description}: no mapped NIST control implemented.`,
      source: 'Compliance',
      inherentRisk: 'High', residualRisk: 'High',
      rationale: 'No baseline control implemented for this framework requirement.',
      treatment: 'Mitigate',
      owner: 'Compliance Office'
    });
  }

  for (const g of recovery.gaps) {
    out.push({
      id: uid('RR', idx++),
      description: `[Recovery] ${g}`,
      source: 'Recovery',
      inherentRisk: 'High', residualRisk: 'Medium',
      rationale: 'Recovery design gap reduced by inherited AWS managed services but not eliminated.',
      treatment: 'Mitigate',
      owner: 'Application Owner & BCDR Team'
    });
  }

  return out;
}

function riskFromLM(l: 'Low' | 'Medium' | 'High', i: 'Low' | 'Medium' | 'High'): 'Low' | 'Medium' | 'High' | 'Critical' {
  const map: Record<'Low' | 'Medium' | 'High', number> = { Low: 1, Medium: 2, High: 3 };
  const s = map[l] + map[i];
  if (s >= 6) return 'Critical';
  if (s >= 5) return 'High';
  if (s >= 4) return 'Medium';
  return 'Low';
}
