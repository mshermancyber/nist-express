// Operational threat model — non-security operational risks that
// ARBs care about: SPOFs, misconfig blast radius, capacity, backup
// integrity, monitoring gaps, vendor dependency, identity ops, DR
// readiness. Each finding cites the controls that mitigate it so it
// can be cross-linked to the SSP and evidence requests.

import {
  Assessment, Architecture, Categorization, OperationalThreat
} from '../types/assessment';

export function buildOperationalThreats(
  a: Assessment,
  arch: Architecture,
  cat: Categorization
): OperationalThreat[] {
  const out: OperationalThreat[] = [];
  const multiRegion = a.advanced?.multiRegion === true || cat.availabilityImpact === 'High' || a.recovery.rto === '15 Minutes';
  const containsSensitive = a.data.sensitiveDataTags.length > 0 || a.data.confidentialToCompany;
  const isHighAv = cat.availabilityImpact === 'High';

  // SPOF
  if (!multiRegion) {
    out.push({
      category: 'Single Point of Failure',
      description: 'Single-region deployment is a regional SPOF; an AWS regional impairment would cause an outage.',
      affectedComponents: arch.components.filter(c => c.layer === 'app' || c.layer === 'data').map(c => c.id),
      likelihood: 'Low',
      impact: isHighAv ? 'High' : 'Medium',
      recommendation: 'Add a warm secondary region or pilot-light DR; promote Route 53 to health-checked failover routing.',
      controlReferences: ['CP-2', 'CP-10']
    });
  }
  out.push({
    category: 'Single Point of Failure',
    description: 'Identity-plane availability is critical — Okta or IAM Identity Center outage blocks all authentications.',
    affectedComponents: ['idp_okta', 'aws_idc'],
    likelihood: 'Low',
    impact: 'High',
    recommendation: 'Document break-glass procedure with IAM Identity Center fallback and offline break-glass user; tested twice a year.',
    controlReferences: ['IA-2', 'CP-2']
  });

  // Misconfiguration
  out.push({
    category: 'Misconfiguration',
    description: 'IAM and S3 misconfiguration are the dominant breach vector in AWS.',
    affectedComponents: arch.components.filter(c => c.layer === 'data' || c.layer === 'identity').map(c => c.id),
    likelihood: 'Medium',
    impact: containsSensitive ? 'High' : 'Medium',
    recommendation: 'Enforce SCPs preventing public S3 buckets, public AMIs, and public RDS snapshots; AWS Config conformance pack for CIS AWS Foundations.',
    controlReferences: ['CM-2', 'CM-6', 'CM-8']
  });

  // Capacity
  out.push({
    category: 'Capacity',
    description: `Expected growth (${a.population.expectedGrowth || 'unspecified'}) on a ${a.population.userCount} user base must drive scaling and quota planning.`,
    affectedComponents: arch.components.filter(c => c.layer === 'app' || c.layer === 'data').map(c => c.id),
    likelihood: 'Medium',
    impact: isHighAv ? 'High' : 'Medium',
    recommendation: 'Review AWS service quotas; configure autoscaling targets; load-test to 1.5× expected peak.',
    controlReferences: ['CP-2']
  });

  // Backup
  out.push({
    category: 'Backup',
    description: 'Backups can be silently broken by IAM/KMS policy drift or undetected key rotation issues.',
    affectedComponents: ['bkp_backup', 'data_rds', 'data_s3'],
    likelihood: 'Low',
    impact: 'High',
    recommendation: 'Enable AWS Backup vault lock with WORM retention; run restore drills quarterly and alert on backup-failure metric.',
    controlReferences: ['CP-9', 'CP-10', 'AU-9']
  });

  // Monitoring gaps
  out.push({
    category: 'Monitoring Gap',
    description: 'High alert-volume causes critical findings to be lost; ensure GuardDuty/Security Hub findings have triage SLAs.',
    affectedComponents: ['mon_gd', 'mon_sechub'],
    likelihood: 'Medium',
    impact: 'Medium',
    recommendation: 'Define severity-based SLA (Critical: 1h, High: 4h, Medium: 24h, Low: 5d); route to ticketing system with auto-close.',
    controlReferences: ['SI-4', 'IR-4', 'AU-6']
  });

  // Vendor dependency
  if (a.integrations.length > 0) {
    out.push({
      category: 'Vendor Dependency',
      description: `${a.integrations.length} declared integration(s) introduce supply-chain and availability dependencies.`,
      affectedComponents: a.integrations.map((_, i) => `integ_${i}`),
      likelihood: 'Medium',
      impact: 'Medium',
      recommendation: 'Maintain vendor inventory; require SOC2 Type II; design circuit breakers and degradation paths.',
      controlReferences: ['SA-11', 'CA-7']
    });
  }

  // Identity ops
  out.push({
    category: 'Identity',
    description: 'Orphaned accounts and stale entitlements accumulate without periodic review.',
    affectedComponents: ['idp_okta', 'aws_idc'],
    likelihood: 'Medium',
    impact: containsSensitive ? 'High' : 'Medium',
    recommendation: 'Quarterly entitlement review with auto-disable on 60 days idle; integrate joiner-mover-leaver with HRIS.',
    controlReferences: ['AC-2', 'AC-6', 'IA-5']
  });

  // DR
  out.push({
    category: 'Disaster Recovery',
    description: `Stated RTO=${a.recovery.rto}, RPO=${a.recovery.rpo}. Validate recovery plan supports these objectives.`,
    affectedComponents: ['bkp_backup', 'data_rds', 'data_s3'],
    likelihood: 'Low',
    impact: isHighAv ? 'High' : 'Medium',
    recommendation: multiRegion
      ? 'Run full regional failover game-day annually; measure actual RTO/RPO and update plan.'
      : 'Document and exercise restore procedure; consider warm DR if RTO requires.',
    controlReferences: ['CP-2', 'CP-10']
  });

  return out;
}
