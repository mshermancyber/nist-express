// Recovery and resiliency assessment. Maps RTO/RPO + availability
// impact to an availability tier, then identifies the strategy gaps
// for the chosen architecture (multi-region/multi-AZ, backup
// cadence, restore-test cadence, failover approach).

import { Assessment, Categorization, RecoveryAssessment } from '../types/assessment';

export function buildRecovery(a: Assessment, cat: Categorization): RecoveryAssessment {
  const isAggressiveRto = a.recovery.rto === '15 Minutes' || a.recovery.rto === '1 Hour';
  const isTightRpo = a.recovery.rpo === 'No Data Loss' || a.recovery.rpo === '15 Minutes';
  const isHighAv = cat.availabilityImpact === 'High';

  const tier: RecoveryAssessment['availabilityTier'] = isAggressiveRto && isHighAv
    ? 'Tier 1'
    : isHighAv || isAggressiveRto
    ? 'Tier 2'
    : cat.availabilityImpact === 'Moderate'
    ? 'Tier 3'
    : 'Tier 4';

  const multiRegion =
    a.advanced?.multiRegion === true ||
    tier === 'Tier 1' ||
    (tier === 'Tier 2' && a.recovery.rto === '15 Minutes');

  const multiAz = tier !== 'Tier 4';

  const backupStrategy = isTightRpo
    ? 'Continuous backup (e.g. Aurora continuous backups / S3 versioning + replication) to support near-zero RPO.'
    : a.recovery.rpo === '1 Hour'
    ? 'Hourly snapshot cadence with point-in-time recovery enabled.'
    : 'Daily snapshots with cross-region copies retained per policy.';

  const restoreTestingCadence = tier === 'Tier 1' || tier === 'Tier 2'
    ? 'Quarterly full restore drill; monthly partial restore.'
    : 'Semi-annual restore drill.';

  const failoverApproach = tier === 'Tier 1'
    ? 'Active-active multi-region behind Route 53 health-checked routing; automated failover.'
    : tier === 'Tier 2'
    ? 'Warm standby in secondary region; documented runbook for promotion within RTO.'
    : tier === 'Tier 3'
    ? 'Multi-AZ within region; backup-and-restore DR posture.'
    : 'Single-AZ tolerable; rely on backup-and-restore.';

  const gaps: string[] = [];
  const recommendations: string[] = [];

  if (tier === 'Tier 1' && !multiRegion) {
    gaps.push('Tier 1 availability tier without multi-region deployment.');
    recommendations.push('Stand up active-active in a secondary region with Route 53 latency/failover routing.');
  }
  if (isTightRpo && a.hosting.model !== 'AWS') {
    gaps.push('Tight RPO declared but hosting model is not AWS — verify chosen platform supports continuous backup.');
    recommendations.push('Confirm continuous backup capability or revise RPO.');
  }
  if (a.recovery.rpo === 'No Data Loss' && !isAggressiveRto) {
    gaps.push('Zero data loss requested but RTO is relaxed — confirm objective is correctly stated.');
  }
  if (!a.compliance.frameworks.length) {
    recommendations.push('Even without external compliance mandate, document an internal recovery policy with named owner.');
  }
  recommendations.push('Use AWS Backup vault lock with WORM retention to ensure ransomware-resilient recovery.');
  recommendations.push('Treat the recovery procedure as code (runbook + tested automation), not a wiki page.');

  return {
    rto: a.recovery.rto,
    rpo: a.recovery.rpo,
    availabilityTier: tier,
    multiRegion,
    multiAz,
    backupStrategy,
    restoreTestingCadence,
    failoverApproach,
    gaps,
    recommendations
  };
}
