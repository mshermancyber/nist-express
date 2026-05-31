// AWS Well-Architected Framework scoring across the three pillars
// the spec calls out (Security, Reliability, Operational Excellence).
// Score is derived deterministically from the architecture, recovery
// posture, and SSP. Findings/recommendations are framework-language.

import {
  Assessment, Architecture, RecoveryAssessment, SspControl, WellArchitectedScore, StrideFinding
} from '../types/assessment';

function pct(x: number, total: number): number {
  return total === 0 ? 0 : Math.round((x / total) * 100);
}

export function buildWellArchitected(
  a: Assessment,
  arch: Architecture,
  ssp: SspControl[],
  recovery: RecoveryAssessment,
  threats: StrideFinding[]
): WellArchitectedScore[] {
  const findings: Record<string, string[]> = { Security: [], Reliability: [], 'Operational Excellence': [] };
  const recs: Record<string, string[]> = { Security: [], Reliability: [], 'Operational Excellence': [] };

  // ---- Security ----
  let sec = 50; // baseline
  const hasMfaControls = ssp.find(c => c.id === 'IA-2');
  if (hasMfaControls) { sec += 8; findings.Security.push('Identity federated with MFA enforced.'); }
  if (ssp.find(c => c.id === 'SC-7')) { sec += 6; findings.Security.push('Boundary protection in place.'); }
  if (ssp.find(c => c.id === 'SC-28')) { sec += 6; findings.Security.push('Encryption at rest implemented.'); }
  if (ssp.find(c => c.id === 'SI-4')) { sec += 6; findings.Security.push('System monitoring (GuardDuty/Security Hub) configured.'); }
  if (ssp.find(c => c.id === 'AU-9')) { sec += 4; findings.Security.push('Audit information protected with object lock.'); }
  if (ssp.find(c => c.id === 'SC-12')) { sec += 4; findings.Security.push('KMS-based key management with rotation.'); }
  const criticals = threats.filter(t => t.residualRisk === 'Critical' || t.residualRisk === 'High').length;
  if (criticals > 0) {
    sec -= Math.min(20, criticals * 3);
    findings.Security.push(`${criticals} residual High/Critical STRIDE findings remain.`);
    recs.Security.push('Resolve High/Critical residual risks before authorization.');
  } else {
    recs.Security.push('Run a tabletop exercise against the top three residual scenarios.');
  }
  if (!ssp.find(c => c.id === 'IA-5')) recs.Security.push('Add IA-5 authenticator management.');
  recs.Security.push('Adopt SCPs for preventive controls on IAM, KMS, and S3 public access.');

  // ---- Reliability ----
  let rel = 50;
  if (recovery.multiAz) { rel += 8; findings.Reliability.push('Multi-AZ deployment configured.'); }
  if (recovery.multiRegion) { rel += 10; findings.Reliability.push('Multi-region recovery designed.'); }
  if (recovery.availabilityTier === 'Tier 1') rel += 4;
  if (recovery.gaps.length === 0) { rel += 8; findings.Reliability.push('No recovery gaps identified.'); }
  else { rel -= recovery.gaps.length * 4; findings.Reliability.push(`${recovery.gaps.length} recovery gap(s) detected.`); recs.Reliability.push(...recovery.gaps); }
  if (a.recovery.rpo === 'No Data Loss' && !recovery.multiRegion) {
    rel -= 6;
    recs.Reliability.push('Tighten RPO with continuous backup or revise the objective.');
  }
  recs.Reliability.push(`Test recovery on a ${recovery.restoreTestingCadence.toLowerCase()} basis; capture measured RTO/RPO.`);
  recs.Reliability.push('Run regular GameDays to validate failover automation.');

  // ---- Operational Excellence ----
  let ops = 50;
  if (ssp.find(c => c.id === 'CM-2')) { ops += 8; findings['Operational Excellence'].push('IaC-managed baseline.'); }
  if (ssp.find(c => c.id === 'CA-7')) { ops += 6; findings['Operational Excellence'].push('Continuous monitoring strategy defined.'); }
  if (ssp.find(c => c.id === 'IR-4')) { ops += 6; findings['Operational Excellence'].push('Incident response process documented.'); }
  if (ssp.find(c => c.id === 'SI-2')) { ops += 6; findings['Operational Excellence'].push('Patch cadence defined.'); }
  if (a.integrations.length === 0) {
    findings['Operational Excellence'].push('No declared integrations — confirm this matches reality.');
  }
  recs['Operational Excellence'].push('Track DORA metrics (deploy freq, lead time, MTTR, change-fail rate).');
  recs['Operational Excellence'].push('Adopt blameless post-mortems with action-item tracking.');

  const clamp = (v: number) => Math.max(0, Math.min(100, v));

  const pillars: WellArchitectedScore['pillar'][] = ['Security', 'Reliability', 'Operational Excellence'];
  return pillars.map(p => ({
    pillar: p,
    score: clamp(p === 'Security' ? sec : p === 'Reliability' ? rel : ops),
    findings: findings[p],
    recommendations: recs[p]
  }));
}

export function _pct(x: number, total: number): number { return pct(x, total); } // exported for tests if needed
