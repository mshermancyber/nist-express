// Architecture engine — derives an AWS reference architecture from
// the questionnaire. Rules favour defence-in-depth: every system gets
// boundary protection, identity, logging, monitoring, and backup
// tiers. Components scale based on user population, RTO/RPO, and
// data sensitivity. Each component carries the rationale (which
// business/security/compliance/risk decision motivated it).

import {
  Assessment,
  Architecture,
  ArchitectureComponent,
  DataFlow,
  Categorization,
  Integration
} from '../types/assessment';
import { CloudProfile, profileFor } from './cloudProfiles';

function id(prefix: string, idx: number) {
  return `${prefix}_${idx}`;
}

// Mapping from internal component id -> cloud-profile role key. After
// the AWS architecture is built we use this map to re-label
// components for Azure / GCP renderings.
const ID_TO_ROLE: Record<string, keyof CloudProfile['services']> = {
  aws_idc: 'sso',
  aws_kms: 'kms',
  aws_secrets: 'secrets',
  edge_route53: 'dns',
  edge_waf: 'waf',
  edge_cf: 'cdn',
  edge_alb: 'alb',
  app_apigw: 'apigw',
  app_lambda: 'app_serverless',
  app_ecs: 'app_containers',
  data_rds: 'data_relational',
  data_s3: 'data_object',
  log_cloudtrail: 'log_audit',
  log_cwl: 'log_app',
  log_config: 'log_config',
  log_archive: 'log_archive',
  mon_sechub: 'mon_posture',
  mon_gd: 'mon_threat',
  bkp_backup: 'backup',
  adm_ssm: 'admin_ops'
};

export function buildArchitecture(a: Assessment, cat: Categorization): Architecture {
  const arch = buildArchitectureAws(a, cat);
  const profile = profileFor(a.hosting.model);
  if (profile.cloudName === 'AWS') return arch;
  return retargetToProfile(arch, profile);
}

function retargetToProfile(arch: Architecture, profile: CloudProfile): Architecture {
  // Components: swap awsService and the user-facing name to the profile
  // equivalent where a mapping exists. Trust zones and rationales are
  // cloud-agnostic and kept verbatim.
  arch.components = arch.components.map(c => {
    const role = ID_TO_ROLE[c.id];
    if (!role) return c;
    const newSvc = profile.services[role];
    const newLabel = profile.componentLabels[role];
    return {
      ...c,
      awsService: newSvc,
      name: newLabel ?? c.name
    };
  });
  arch.rationale.unshift(`Architecture rendered for ${profile.cloudName}; equivalent services substituted for the AWS reference design.`);
  return arch;
}

function buildArchitectureAws(a: Assessment, cat: Categorization): Architecture {
  const components: ArchitectureComponent[] = [];
  const flows: DataFlow[] = [];
  const rationale: string[] = [];

  const requiresMfa = a.data.confidentialToCompany || a.advanced?.forceMfa === true;
  const isPublic = a.business.userTypes.includes('Public Users') || a.business.userTypes.includes('Customers');
  const isInternalOnly = !isPublic && !a.business.userTypes.includes('Partners') && !a.business.userTypes.includes('Vendors');
  const containsSensitive = a.data.sensitiveDataTags.length > 0 || a.data.confidentialToCompany;
  const isHA = ['15 Minutes', '1 Hour', '4 Hours'].includes(a.recovery.rto);
  const isMultiRegion =
    a.advanced?.multiRegion === true ||
    a.recovery.rto === '15 Minutes' ||
    cat.availabilityImpact === 'High';

  // ---- Identity tier ----
  const okta: ArchitectureComponent = {
    id: 'idp_okta',
    name: 'Okta (Identity Provider)',
    layer: 'identity',
    awsService: undefined,
    description: 'Enterprise IdP federating into AWS via SAML/OIDC. Enforces MFA, adaptive policies, and lifecycle.',
    trustZone: 'Identity Provider',
    encryptionAtRest: true,
    encryptionInTransit: true,
    containsSensitiveData: true,
    authentication: 'SAML',
    rationale: requiresMfa
      ? 'Confidentiality requirement triggered MFA and SAML federation; Okta is the standard enterprise IdP.'
      : 'SSO and centralized identity reduce account-management risk and satisfy IA-2/IA-8.'
  };
  components.push(okta);

  const idc: ArchitectureComponent = {
    id: 'aws_idc',
    name: 'AWS IAM Identity Center',
    layer: 'identity',
    awsService: 'AWS IAM Identity Center',
    description: 'Receives SAML assertions from Okta and issues permission sets to AWS accounts.',
    trustZone: 'AWS Control Plane',
    encryptionAtRest: true,
    encryptionInTransit: true,
    containsSensitiveData: false,
    authentication: 'SAML',
    rationale: 'Provides single-source-of-truth AWS access aligned to least-privilege roles (AC-3, AC-6).'
  };
  components.push(idc);

  const kms: ArchitectureComponent = {
    id: 'aws_kms',
    name: 'AWS KMS (Customer-Managed Keys)',
    layer: 'identity',
    awsService: 'AWS KMS',
    description: 'Customer-managed CMKs with automatic annual rotation. Key policies scope usage.',
    trustZone: 'Restricted Crypto',
    encryptionAtRest: true,
    encryptionInTransit: true,
    containsSensitiveData: true,
    rationale: containsSensitive
      ? 'Sensitive data (PII/PCI/PHI/IP) requires customer-managed keys for SC-12/SC-13/SC-28.'
      : 'KMS is the default key broker for all at-rest encryption.'
  };
  components.push(kms);

  const secrets: ArchitectureComponent = {
    id: 'aws_secrets',
    name: 'AWS Secrets Manager',
    layer: 'identity',
    awsService: 'AWS Secrets Manager',
    description: 'Stores DB credentials, API keys, and integration secrets with automatic rotation.',
    trustZone: 'Restricted Crypto',
    encryptionAtRest: true,
    encryptionInTransit: true,
    containsSensitiveData: true,
    rationale: 'Eliminates static secrets in code/config and supports IA-5 authenticator management.'
  };
  components.push(secrets);

  // ---- Edge tier ----
  const users: ArchitectureComponent = {
    id: 'users',
    name: 'End Users',
    layer: 'edge',
    description: `${a.business.userTypes.join(', ')} interacting per: ${a.business.userInteractionDescription || 'web/mobile clients'}.`,
    trustZone: 'Public Internet',
    encryptionAtRest: false,
    encryptionInTransit: true,
    containsSensitiveData: false,
    rationale: 'Anchor for trust-boundary diagrams.'
  };
  components.push(users);

  const route53: ArchitectureComponent = {
    id: 'edge_route53',
    name: 'Amazon Route 53',
    layer: 'edge',
    awsService: 'Amazon Route 53',
    description: 'Authoritative DNS with health checks and (when applicable) latency or failover routing.',
    trustZone: 'AWS Edge',
    encryptionAtRest: true,
    encryptionInTransit: true,
    containsSensitiveData: false,
    rationale: isMultiRegion ? 'Multi-region failover required by HIGH availability.' : 'Standard public DNS entry point.'
  };
  components.push(route53);

  const waf: ArchitectureComponent = {
    id: 'edge_waf',
    name: 'AWS WAF + Shield',
    layer: 'edge',
    awsService: 'AWS WAF',
    description: 'OWASP Top 10 managed rules + rate-based rules; Shield Standard provides L3/L4 DDoS protection.',
    trustZone: 'AWS Edge',
    encryptionAtRest: false,
    encryptionInTransit: true,
    containsSensitiveData: false,
    rationale: 'SC-7 boundary protection and SI-10 input filtering for public entry points.'
  };
  components.push(waf);

  if (isPublic) {
    const cf: ArchitectureComponent = {
      id: 'edge_cf',
      name: 'Amazon CloudFront',
      layer: 'edge',
      awsService: 'Amazon CloudFront',
      description: 'CDN with TLS 1.2+ termination, signed-URL support, and AWS WAF integration.',
      trustZone: 'AWS Edge',
      encryptionAtRest: false,
      encryptionInTransit: true,
      containsSensitiveData: false,
      rationale: 'Public-facing surface needs caching, TLS termination at edge, and DDoS absorption.'
    };
    components.push(cf);
  }

  const alb: ArchitectureComponent = {
    id: 'edge_alb',
    name: 'Application Load Balancer',
    layer: 'edge',
    awsService: 'Elastic Load Balancing (ALB)',
    description: 'L7 load balancer with TLS 1.2+ policy and (when sensitive data) mTLS to backends.',
    trustZone: 'DMZ',
    encryptionAtRest: false,
    encryptionInTransit: true,
    containsSensitiveData: false,
    rationale: 'Terminates TLS, distributes to app tier, and is the natural enforcement point for WAF.'
  };
  components.push(alb);

  // ---- App tier ----
  const apigw: ArchitectureComponent = {
    id: 'app_apigw',
    name: 'Amazon API Gateway',
    layer: 'app',
    awsService: 'Amazon API Gateway',
    description: 'Managed API front door with throttling, request validation, and Cognito/IAM authorizers.',
    trustZone: 'Private App',
    encryptionAtRest: false,
    encryptionInTransit: true,
    containsSensitiveData: false,
    authentication: 'OAuth2',
    rationale: 'Centralised API policy enforcement for AC-3 and SI-10.'
  };
  components.push(apigw);

  const useServerless = a.population.userCount === 'Under 100' || a.population.userCount === '100-1000';
  const app: ArchitectureComponent = useServerless
    ? {
        id: 'app_lambda',
        name: 'Application (AWS Lambda)',
        layer: 'app',
        awsService: 'AWS Lambda',
        description: 'Serverless application functions, per-function IAM, short-lived execution.',
        trustZone: 'Private App',
        encryptionAtRest: true,
        encryptionInTransit: true,
        containsSensitiveData: containsSensitive,
        rationale: 'Right-sized for current user population; reduces CM-7 attack surface.'
      }
    : {
        id: 'app_ecs',
        name: 'Application (ECS Fargate)',
        layer: 'app',
        awsService: 'Amazon ECS (Fargate)',
        description: 'Containerised application services with task-role IAM and image scanning.',
        trustZone: 'Private App',
        encryptionAtRest: true,
        encryptionInTransit: true,
        containsSensitiveData: containsSensitive,
        rationale: 'Population scale and steady traffic favour container workloads with autoscaling.'
      };
  components.push(app);

  // ---- Data tier ----
  const db: ArchitectureComponent = {
    id: 'data_rds',
    name: 'Primary Database (Amazon Aurora PostgreSQL)',
    layer: 'data',
    awsService: 'Amazon Aurora',
    description: 'Managed relational DB with SSE-KMS, TLS connections, automated backups, and PITR.',
    trustZone: 'Restricted Data',
    encryptionAtRest: true,
    encryptionInTransit: true,
    containsSensitiveData: containsSensitive,
    rationale: containsSensitive
      ? 'Sensitive data requires SSE-KMS with CMK (SC-28) and IAM-based DB auth where possible.'
      : 'Aurora provides Multi-AZ, automated backups, and broad NIST baseline coverage.'
  };
  components.push(db);

  const s3: ArchitectureComponent = {
    id: 'data_s3',
    name: 'Object Storage (Amazon S3)',
    layer: 'data',
    awsService: 'Amazon S3',
    description: 'Encrypted buckets with bucket policies, block-public-access, and access logging.',
    trustZone: 'Restricted Data',
    encryptionAtRest: true,
    encryptionInTransit: true,
    containsSensitiveData: containsSensitive,
    rationale: 'Document/artifact storage with SC-28 and CM-6 hardening defaults.'
  };
  components.push(s3);

  // ---- Integration tier (built from declared integrations) ----
  for (let i = 0; i < a.integrations.length; i++) {
    const integ = a.integrations[i] as Integration;
    components.push({
      id: id('integ', i),
      name: `${integ.source} ↔ ${integ.destination}`,
      layer: 'integration',
      description: `${integ.dataDirection} ${integ.protocol} integration authenticated via ${integ.authentication}. ${integ.description ?? ''}`.trim(),
      trustZone: 'Integration Bridge',
      encryptionAtRest: false,
      encryptionInTransit: integ.protocol === 'HTTPS' || integ.protocol === 'TLS' || integ.protocol === 'mTLS' as never,
      containsSensitiveData: containsSensitive,
      authentication: integ.authentication,
      rationale: `Declared integration requires SC-7 boundary controls and IA-5 authenticator management on the ${integ.authentication} method.`
    });
  }

  // ---- Logging tier ----
  components.push({
    id: 'log_cloudtrail',
    name: 'AWS CloudTrail (Org Trail)',
    layer: 'logging',
    awsService: 'AWS CloudTrail',
    description: 'Organisation-wide multi-region trail delivered to a dedicated log-archive account.',
    trustZone: 'Logging',
    encryptionAtRest: true,
    encryptionInTransit: true,
    containsSensitiveData: false,
    rationale: 'Foundational AU-2, AU-3, AU-12 coverage of AWS API activity.'
  });
  components.push({
    id: 'log_cwl',
    name: 'Amazon CloudWatch Logs',
    layer: 'logging',
    awsService: 'Amazon CloudWatch Logs',
    description: 'Application/service logs with metric filters and subscription filters to detection pipeline.',
    trustZone: 'Logging',
    encryptionAtRest: true,
    encryptionInTransit: true,
    containsSensitiveData: false,
    rationale: 'Captures application-level audit events called out in AU-2.'
  });
  components.push({
    id: 'log_config',
    name: 'AWS Config',
    layer: 'logging',
    awsService: 'AWS Config',
    description: 'Configuration history and conformance packs (CIS, NIST, FSBP).',
    trustZone: 'Logging',
    encryptionAtRest: true,
    encryptionInTransit: true,
    containsSensitiveData: false,
    rationale: 'CM-2, CM-6, CM-8 drift detection.'
  });
  components.push({
    id: 'log_archive',
    name: 'Log Archive (Amazon S3 with Object Lock)',
    layer: 'logging',
    awsService: 'Amazon S3 (Log Archive)',
    description: 'Immutable log archive with object-lock retention and cross-region replication.',
    trustZone: 'Logging',
    encryptionAtRest: true,
    encryptionInTransit: true,
    containsSensitiveData: false,
    rationale: 'AU-9 protection of audit information against tampering.'
  });

  // ---- Monitoring tier ----
  components.push({
    id: 'mon_sechub',
    name: 'AWS Security Hub',
    layer: 'monitoring',
    awsService: 'AWS Security Hub',
    description: 'Cross-account posture management aggregating findings from native + partner sources.',
    trustZone: 'Monitoring',
    encryptionAtRest: true,
    encryptionInTransit: true,
    containsSensitiveData: false,
    rationale: 'Continuous monitoring (CA-7) and centralised SI-4 view.'
  });
  components.push({
    id: 'mon_gd',
    name: 'Amazon GuardDuty',
    layer: 'monitoring',
    awsService: 'Amazon GuardDuty',
    description: 'ML-driven threat detection across CloudTrail, VPC Flow Logs, DNS, EKS audit.',
    trustZone: 'Monitoring',
    encryptionAtRest: true,
    encryptionInTransit: true,
    containsSensitiveData: false,
    rationale: 'Required for SI-4 system monitoring; strongly recommended by CIS 13.1.'
  });

  // ---- Backup tier ----
  components.push({
    id: 'bkp_backup',
    name: 'AWS Backup (Vault Lock)',
    layer: 'backup',
    awsService: 'AWS Backup',
    description: `Centralized cross-account backups for RPO=${a.recovery.rpo} with WORM vault lock and ${isMultiRegion ? 'cross-region' : 'in-region'} copies.`,
    trustZone: 'Backup',
    encryptionAtRest: true,
    encryptionInTransit: true,
    containsSensitiveData: containsSensitive,
    rationale: `Driven by RPO=${a.recovery.rpo} and CP-9/CP-10. Multi-region copies are ${isMultiRegion ? 'enabled' : 'optional'}.`
  });

  // ---- Admin tier ----
  components.push({
    id: 'adm_ssm',
    name: 'AWS Systems Manager',
    layer: 'admin',
    awsService: 'AWS Systems Manager',
    description: 'Session Manager for bastion-free admin access; Patch Manager for OS patching.',
    trustZone: 'Admin',
    encryptionAtRest: true,
    encryptionInTransit: true,
    containsSensitiveData: false,
    rationale: 'Eliminates bastions/SSH keys (AC-17, CM-6, MA-2).'
  });

  // ---- Flows ----
  const addFlow = (from: string, to: string, label: string, protocol: DataFlow['protocol'], encrypted: boolean, sensitive: boolean, crosses = true) => {
    flows.push({
      id: `${from}->${to}`,
      fromComponentId: from,
      toComponentId: to,
      label,
      protocol,
      encrypted,
      crossesTrustBoundary: crosses,
      carriesSensitiveData: sensitive
    });
  };

  addFlow('users', 'idp_okta', 'Authenticate (SAML/OIDC + MFA)', 'HTTPS', true, true);
  addFlow('idp_okta', 'aws_idc', 'SAML assertion', 'HTTPS', true, false);
  if (isPublic) addFlow('users', 'edge_cf', 'HTTPS request', 'HTTPS', true, false);
  addFlow(isPublic ? 'edge_cf' : 'users', 'edge_waf', 'Filtered request', 'HTTPS', true, false);
  addFlow('edge_waf', 'edge_alb', 'Routed request', 'HTTPS', true, false);
  addFlow('edge_alb', 'app_apigw', 'API request', 'HTTPS', true, false);
  addFlow('app_apigw', useServerless ? 'app_lambda' : 'app_ecs', 'Invoke service', 'HTTPS', true, false, false);
  addFlow(useServerless ? 'app_lambda' : 'app_ecs', 'data_rds', 'Query / write', 'TLS', true, containsSensitive);
  addFlow(useServerless ? 'app_lambda' : 'app_ecs', 'data_s3', 'Object I/O', 'HTTPS', true, containsSensitive);
  addFlow(useServerless ? 'app_lambda' : 'app_ecs', 'aws_secrets', 'Retrieve secrets', 'HTTPS', true, true, false);
  addFlow('data_rds', 'aws_kms', 'Envelope encryption', 'HTTPS', true, false, false);
  addFlow('data_s3', 'aws_kms', 'Envelope encryption', 'HTTPS', true, false, false);

  // Logging flows
  addFlow('aws_idc', 'log_cloudtrail', 'API audit', 'HTTPS', true, false, false);
  addFlow(useServerless ? 'app_lambda' : 'app_ecs', 'log_cwl', 'App logs', 'HTTPS', true, false, false);
  addFlow('log_cloudtrail', 'log_archive', 'Immutable archive', 'HTTPS', true, false, false);
  addFlow('log_cwl', 'log_archive', 'Subscription filter', 'HTTPS', true, false, false);
  addFlow('log_config', 'log_archive', 'Config snapshots', 'HTTPS', true, false, false);

  // Monitoring flows
  addFlow('log_cloudtrail', 'mon_gd', 'Findings source', 'HTTPS', true, false, false);
  addFlow('mon_gd', 'mon_sechub', 'Findings', 'HTTPS', true, false, false);
  addFlow('log_config', 'mon_sechub', 'Config findings', 'HTTPS', true, false, false);

  // Backup flow
  addFlow('data_rds', 'bkp_backup', `Backup (RPO=${a.recovery.rpo})`, 'HTTPS', true, containsSensitive, false);
  addFlow('data_s3', 'bkp_backup', 'Versioned replicas', 'HTTPS', true, containsSensitive, false);

  // Admin flow
  addFlow('aws_idc', 'adm_ssm', 'Session Manager access', 'HTTPS', true, false, false);

  // Integration flows
  for (let i = 0; i < a.integrations.length; i++) {
    const integ = a.integrations[i] as Integration;
    addFlow(
      useServerless ? 'app_lambda' : 'app_ecs',
      id('integ', i),
      `${integ.dataDirection} ${integ.protocol}/${integ.authentication}`,
      integ.protocol,
      integ.protocol === 'HTTPS' || integ.protocol === 'TLS',
      containsSensitive,
      true
    );
  }

  // ---- Trust boundaries ----
  const trustBoundaries = [
    {
      name: 'Public Internet',
      componentIds: ['users'],
      description: 'Untrusted clients on the open internet.'
    },
    {
      name: 'AWS Edge',
      componentIds: ['edge_route53', 'edge_waf', ...(isPublic ? ['edge_cf'] : [])],
      description: 'AWS-managed edge with WAF/Shield filtering.'
    },
    {
      name: 'DMZ',
      componentIds: ['edge_alb'],
      description: 'TLS termination and ingress filtering.'
    },
    {
      name: 'Private App',
      componentIds: ['app_apigw', useServerless ? 'app_lambda' : 'app_ecs', ...a.integrations.map((_, i) => id('integ', i))],
      description: 'Private subnets / serverless VPC; no direct internet egress.'
    },
    {
      name: 'Restricted Data',
      componentIds: ['data_rds', 'data_s3'],
      description: 'Data tier reachable only from app tier with IAM-bound access.'
    },
    {
      name: 'Restricted Crypto',
      componentIds: ['aws_kms', 'aws_secrets'],
      description: 'Key/secret material with strict resource policies.'
    },
    {
      name: 'Identity Plane',
      componentIds: ['idp_okta', 'aws_idc'],
      description: 'External IdP + AWS SSO; authoritative for all human identity.'
    },
    {
      name: 'Telemetry & Backup',
      componentIds: ['log_cloudtrail', 'log_cwl', 'log_config', 'log_archive', 'mon_sechub', 'mon_gd', 'bkp_backup'],
      description: 'Read-only telemetry and immutable backups; tamper protection enforced.'
    },
    { name: 'Admin', componentIds: ['adm_ssm'], description: 'Privileged operations plane.' }
  ];

  rationale.push(
    `User population (${a.population.userCount}) selected ${useServerless ? 'Lambda' : 'ECS Fargate'} for the app tier.`,
    `${isPublic ? 'Public exposure' : 'Internal-only access'} drove ${isPublic ? 'CloudFront inclusion' : 'omission of CloudFront'}.`,
    `${isHA ? `Aggressive RTO (${a.recovery.rto}) requires Multi-AZ and active health checks.` : 'Standard availability tier.'}`,
    `${isMultiRegion ? 'Multi-region backup and DNS failover required by HIGH availability impact.' : 'Single-region with in-region failover.'}`,
    `${containsSensitive ? 'Sensitive data tags drove KMS CMKs, SC-28 at rest, and TLS to data tier.' : 'Standard encryption defaults applied.'}`,
    `${requiresMfa ? 'Confidentiality requirement forced Okta MFA + SAML federation.' : 'No additional MFA mandate beyond defaults.'}`,
    `${isInternalOnly ? 'Internal-only — Cognito intentionally excluded.' : ''}`.trim()
  );

  return { components, flows, trustBoundaries, rationale: rationale.filter(Boolean) };
}
