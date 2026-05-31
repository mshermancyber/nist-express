// Cost estimation for the generated reference architecture. Values
// are deliberate **bands** (low/high) sourced from public AWS pricing
// rounded to credible ranges; the goal is a defensible T-shirt size
// for ARB consumption, not penny-perfect accuracy.

import { Architecture, Assessment, CostEstimate, RecoveryAssessment } from '../types/assessment';

interface ServiceCostBand {
  monthlyLowUsd: number;
  monthlyHighUsd: number;
  rationale: string;
  populationMultiplier?: boolean;  // multiply by user-count factor
}

// Indexed by the AWS service name we emit from the architecture engine.
const SERVICE_COSTS: Record<string, ServiceCostBand> = {
  'Amazon CloudFront':              { monthlyLowUsd: 50,   monthlyHighUsd: 800,   rationale: 'Data-transfer-driven', populationMultiplier: true },
  'AWS WAF':                        { monthlyLowUsd: 30,   monthlyHighUsd: 200,   rationale: 'Web-ACL + rules + request volume' },
  'AWS Shield Standard':            { monthlyLowUsd: 0,    monthlyHighUsd: 0,     rationale: 'Included with AWS' },
  'Amazon Route 53':                { monthlyLowUsd: 5,    monthlyHighUsd: 50,    rationale: 'Hosted zones + queries' },
  'Elastic Load Balancing (ALB)':   { monthlyLowUsd: 25,   monthlyHighUsd: 250,   rationale: 'LCU consumption' },
  'AWS IAM Identity Center':        { monthlyLowUsd: 0,    monthlyHighUsd: 0,     rationale: 'No charge' },
  'AWS IAM':                        { monthlyLowUsd: 0,    monthlyHighUsd: 0,     rationale: 'No charge' },
  'Amazon Cognito':                 { monthlyLowUsd: 25,   monthlyHighUsd: 500,   rationale: 'MAU-priced', populationMultiplier: true },
  'AWS Secrets Manager':            { monthlyLowUsd: 10,   monthlyHighUsd: 100,   rationale: 'Per-secret + API calls' },
  'AWS KMS':                        { monthlyLowUsd: 5,    monthlyHighUsd: 100,   rationale: 'Per-key + API calls' },
  'Amazon ECS (Fargate)':           { monthlyLowUsd: 150,  monthlyHighUsd: 3000,  rationale: 'vCPU + memory per task' },
  'Amazon EKS':                     { monthlyLowUsd: 220,  monthlyHighUsd: 5000,  rationale: 'Cluster fee + nodes' },
  'AWS Lambda':                     { monthlyLowUsd: 5,    monthlyHighUsd: 500,   rationale: 'Request + GB-second' },
  'Amazon API Gateway':             { monthlyLowUsd: 15,   monthlyHighUsd: 700,   rationale: 'Per million requests', populationMultiplier: true },
  'Amazon EC2':                     { monthlyLowUsd: 200,  monthlyHighUsd: 4000,  rationale: 'Instance hours' },
  'Amazon RDS (PostgreSQL)':        { monthlyLowUsd: 200,  monthlyHighUsd: 4000,  rationale: 'Instance + storage + IOPS' },
  'Amazon Aurora':                  { monthlyLowUsd: 300,  monthlyHighUsd: 6000,  rationale: 'ACUs + storage + IO' },
  'Amazon DynamoDB':                { monthlyLowUsd: 30,   monthlyHighUsd: 2000,  rationale: 'On-demand or provisioned' },
  'Amazon S3':                      { monthlyLowUsd: 25,   monthlyHighUsd: 2000,  rationale: 'Storage + requests + transfer' },
  'Amazon ElastiCache (Redis)':     { monthlyLowUsd: 80,   monthlyHighUsd: 1500,  rationale: 'Node hours' },
  'Amazon EventBridge':             { monthlyLowUsd: 5,    monthlyHighUsd: 200,   rationale: 'Per-event pricing' },
  'Amazon SQS':                     { monthlyLowUsd: 5,    monthlyHighUsd: 150,   rationale: 'Per million requests' },
  'Amazon MSK':                     { monthlyLowUsd: 300,  monthlyHighUsd: 4000,  rationale: 'Broker + storage' },
  'AWS Transfer Family':            { monthlyLowUsd: 200,  monthlyHighUsd: 800,   rationale: 'Endpoint hours + data' },
  'AWS CloudTrail':                 { monthlyLowUsd: 0,    monthlyHighUsd: 200,   rationale: 'Mgmt events free; data events cost' },
  'Amazon CloudWatch Logs':         { monthlyLowUsd: 30,   monthlyHighUsd: 1000,  rationale: 'Ingestion + retention' },
  'AWS Config':                     { monthlyLowUsd: 30,   monthlyHighUsd: 300,   rationale: 'Per-config-item + rule evaluations' },
  'Amazon S3 (Log Archive)':        { monthlyLowUsd: 25,   monthlyHighUsd: 500,   rationale: 'Object Lock storage + replication' },
  'AWS Security Hub':               { monthlyLowUsd: 30,   monthlyHighUsd: 300,   rationale: 'Findings + standards' },
  'Amazon GuardDuty':               { monthlyLowUsd: 50,   monthlyHighUsd: 500,   rationale: 'CloudTrail + VPC + DNS analysis volume' },
  'Amazon Inspector':               { monthlyLowUsd: 30,   monthlyHighUsd: 400,   rationale: 'Per-asset scans' },
  'Amazon Detective':               { monthlyLowUsd: 80,   monthlyHighUsd: 800,   rationale: 'GB-ingested' },
  'AWS Backup':                     { monthlyLowUsd: 50,   monthlyHighUsd: 1500,  rationale: 'Backup storage' },
  'Amazon S3 (Backup)':             { monthlyLowUsd: 50,   monthlyHighUsd: 1000,  rationale: 'Versioned storage + replication' },
  'AWS Systems Manager':            { monthlyLowUsd: 0,    monthlyHighUsd: 100,   rationale: 'Most features free; Patch Mgr instance-priced' },
  'AWS Organizations':              { monthlyLowUsd: 0,    monthlyHighUsd: 0,     rationale: 'No charge' }
};

const POPULATION_FACTOR: Record<string, number> = {
  'Under 100':  0.5,
  '100-1000':   1.0,
  '1000-10000': 2.0,
  '10000+':     4.0
};

function multiRegionMultiplier(recovery: RecoveryAssessment): number {
  return recovery.multiRegion ? 1.8 : 1.0;
}

function tierFor(monthlyHigh: number): CostEstimate['tier'] {
  if (monthlyHigh < 1000) return 'XS';
  if (monthlyHigh < 5000) return 'S';
  if (monthlyHigh < 15000) return 'M';
  if (monthlyHigh < 50000) return 'L';
  return 'XL';
}

export function estimateCost(a: Assessment, arch: Architecture, recovery: RecoveryAssessment): CostEstimate {
  const popFactor = POPULATION_FACTOR[a.population.userCount] ?? 1.0;
  const regionMult = multiRegionMultiplier(recovery);
  const drivers: CostEstimate['drivers'] = [];

  let lowTotal = 0;
  let highTotal = 0;

  // Unique services used by the architecture.
  const services = new Set<string>();
  for (const c of arch.components) if (c.awsService) services.add(c.awsService);

  for (const svc of services) {
    const band = SERVICE_COSTS[svc];
    if (!band) continue;
    const popMul = band.populationMultiplier ? popFactor : 1.0;
    const low = Math.round(band.monthlyLowUsd * popMul * regionMult);
    const high = Math.round(band.monthlyHighUsd * popMul * regionMult);
    drivers.push({ item: svc, lowUsd: low, highUsd: high, rationale: band.rationale });
    lowTotal += low;
    highTotal += high;
  }

  // Data egress is a hidden tax — add a band based on the population.
  const egressLow = Math.round(50 * popFactor * regionMult);
  const egressHigh = Math.round(800 * popFactor * regionMult);
  drivers.push({ item: 'Data Egress (cross-region + internet)', lowUsd: egressLow, highUsd: egressHigh, rationale: 'User population + multi-region replication' });
  lowTotal += egressLow;
  highTotal += egressHigh;

  // Support: at the High tier, assume Enterprise Support's minimum.
  if (highTotal > 15000) {
    drivers.push({ item: 'AWS Enterprise Support (minimum)', lowUsd: 0, highUsd: 5500, rationale: '$5,500/mo minimum at this spend' });
    highTotal += 5500;
  }

  const notes: string[] = [
    'Bands are first-order estimates; replace with Pricing Calculator output before commit.',
    `Population factor applied: ${popFactor}x. Multi-region factor: ${regionMult}x.`
  ];
  if (recovery.multiRegion) notes.push('Multi-region cost includes warm secondary; active-active will be higher.');
  if (a.advanced?.preferredAwsRegion?.startsWith('us-gov')) notes.push('GovCloud regions carry a typical 25–40% premium not modelled here.');

  return {
    currency: 'USD',
    monthlyLowUsd: Math.round(lowTotal),
    monthlyHighUsd: Math.round(highTotal),
    tier: tierFor(highTotal),
    drivers: drivers.sort((a, b) => b.highUsd - a.highUsd),
    notes
  };
}
