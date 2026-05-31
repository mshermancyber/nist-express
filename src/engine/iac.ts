// IaC reconciliation. Accepts a Terraform plan JSON, CloudFormation
// template (YAML/JSON), or CDK synth JSON and reconciles the
// resources described there against the expected architecture
// emitted by the engine. The output tells assessors which described
// components are missing in the IaC, which IaC resources are not
// described, and where encryption posture disagrees.
//
// We deliberately keep this lightweight — we are not validating
// security configuration (Checkov/tfsec do that better). The point
// is to confirm the *paper architecture* matches the *deployed
// architecture* before treating the ARB package as authoritative.

import yaml from 'js-yaml';
import { Architecture, ArchitectureComponent, IacReconciliationReport } from '../types/assessment';

interface Observed {
  type: string;
  name: string;
  layer: string;
  encryptionAtRest?: boolean;
  encryptionInTransit?: boolean;
}

// Resource-type → architectural layer. Covers AWS, Azure, and GCP
// canonical resource types we expect to see in IaC.
const RESOURCE_LAYER: Record<string, ArchitectureComponent['layer']> = {
  // AWS
  'AWS::CloudFront::Distribution': 'edge',
  'AWS::WAFv2::WebACL': 'edge',
  'AWS::Route53::HostedZone': 'edge',
  'AWS::ElasticLoadBalancingV2::LoadBalancer': 'edge',
  'AWS::SSO::PermissionSet': 'identity',
  'AWS::IAM::Role': 'identity',
  'AWS::SecretsManager::Secret': 'identity',
  'AWS::KMS::Key': 'identity',
  'AWS::Lambda::Function': 'app',
  'AWS::ECS::Service': 'app',
  'AWS::ECS::Cluster': 'app',
  'AWS::ApiGateway::RestApi': 'app',
  'AWS::ApiGatewayV2::Api': 'app',
  'AWS::RDS::DBInstance': 'data',
  'AWS::RDS::DBCluster': 'data',
  'AWS::S3::Bucket': 'data',
  'AWS::DynamoDB::Table': 'data',
  'AWS::CloudTrail::Trail': 'logging',
  'AWS::Logs::LogGroup': 'logging',
  'AWS::Config::ConfigurationRecorder': 'logging',
  'AWS::SecurityHub::Hub': 'monitoring',
  'AWS::GuardDuty::Detector': 'monitoring',
  'AWS::Backup::BackupVault': 'backup',
  'AWS::SSM::Document': 'admin',
  // Azure (Terraform AzureRM)
  'azurerm_frontdoor': 'edge',
  'azurerm_application_gateway': 'edge',
  'azurerm_dns_zone': 'edge',
  'azurerm_key_vault': 'identity',
  'azurerm_user_assigned_identity': 'identity',
  'azurerm_linux_function_app': 'app',
  'azurerm_container_app': 'app',
  'azurerm_api_management': 'app',
  'azurerm_mssql_database': 'data',
  'azurerm_storage_account': 'data',
  'azurerm_log_analytics_workspace': 'logging',
  'azurerm_security_center_workspace': 'monitoring',
  'azurerm_sentinel_alert_rule': 'monitoring',
  'azurerm_backup_protected_vm': 'backup',
  'azurerm_bastion_host': 'admin',
  // GCP (Terraform google)
  'google_compute_global_forwarding_rule': 'edge',
  'google_compute_url_map': 'edge',
  'google_dns_managed_zone': 'edge',
  'google_compute_security_policy': 'edge',
  'google_kms_crypto_key': 'identity',
  'google_secret_manager_secret': 'identity',
  'google_cloud_run_v2_service': 'app',
  'google_cloudfunctions2_function': 'app',
  'google_api_gateway_api': 'app',
  'google_sql_database_instance': 'data',
  'google_storage_bucket': 'data',
  'google_logging_project_sink': 'logging',
  'google_scc_source': 'monitoring',
  'google_backup_dr_backup_plan': 'backup',
  'google_iap_tunnel_iam_policy': 'admin'
};

// Roughly map architectural component IDs to one or more resource types.
// A described component is "matched" if at least one observed resource
// has a type in its accepted set.
const COMPONENT_RESOURCE_HINTS: Record<string, string[]> = {
  edge_route53: ['AWS::Route53::HostedZone', 'azurerm_dns_zone', 'google_dns_managed_zone'],
  edge_waf: ['AWS::WAFv2::WebACL', 'azurerm_frontdoor', 'google_compute_security_policy'],
  edge_cf: ['AWS::CloudFront::Distribution', 'azurerm_frontdoor'],
  edge_alb: ['AWS::ElasticLoadBalancingV2::LoadBalancer', 'azurerm_application_gateway', 'google_compute_global_forwarding_rule'],
  aws_kms: ['AWS::KMS::Key', 'azurerm_key_vault', 'google_kms_crypto_key'],
  aws_secrets: ['AWS::SecretsManager::Secret', 'azurerm_key_vault', 'google_secret_manager_secret'],
  app_apigw: ['AWS::ApiGateway::RestApi', 'AWS::ApiGatewayV2::Api', 'azurerm_api_management', 'google_api_gateway_api'],
  app_lambda: ['AWS::Lambda::Function', 'azurerm_linux_function_app', 'google_cloudfunctions2_function'],
  app_ecs: ['AWS::ECS::Service', 'AWS::ECS::Cluster', 'azurerm_container_app', 'google_cloud_run_v2_service'],
  data_rds: ['AWS::RDS::DBInstance', 'AWS::RDS::DBCluster', 'azurerm_mssql_database', 'google_sql_database_instance'],
  data_s3: ['AWS::S3::Bucket', 'azurerm_storage_account', 'google_storage_bucket'],
  log_cloudtrail: ['AWS::CloudTrail::Trail', 'azurerm_log_analytics_workspace', 'google_logging_project_sink'],
  log_cwl: ['AWS::Logs::LogGroup', 'azurerm_log_analytics_workspace', 'google_logging_project_sink'],
  log_config: ['AWS::Config::ConfigurationRecorder'],
  log_archive: ['AWS::S3::Bucket', 'azurerm_storage_account', 'google_storage_bucket'],
  mon_sechub: ['AWS::SecurityHub::Hub', 'azurerm_security_center_workspace', 'google_scc_source'],
  mon_gd: ['AWS::GuardDuty::Detector', 'azurerm_sentinel_alert_rule'],
  bkp_backup: ['AWS::Backup::BackupVault', 'azurerm_backup_protected_vm', 'google_backup_dr_backup_plan'],
  adm_ssm: ['AWS::SSM::Document', 'azurerm_bastion_host', 'google_iap_tunnel_iam_policy']
};

// Hard ceiling on IaC document size. Terraform plans / CloudFormation
// templates / CDK synth outputs for legitimate estates hit a few MB at
// most; bigger inputs are DoS / OOM risk.
const MAX_IAC_BYTES = 50 * 1024 * 1024;

export function detectFormat(content: string): IacReconciliationReport['format'] {
  if (content.length > MAX_IAC_BYTES) return 'unknown';
  const trimmed = content.trimStart();
  if (trimmed.startsWith('{')) {
    try {
      const j = JSON.parse(trimmed);
      if (j && typeof j === 'object' && ('resource_changes' in j || 'planned_values' in j)) return 'terraform-plan';
      if (j && typeof j === 'object' && ('Resources' in j || 'resources' in j)) return 'cloudformation';
      if (j && typeof j === 'object' && 'tree' in j) return 'cdk-synth';
      if (Array.isArray(j)) return 'cdk-synth';
    } catch { /* fallthrough */ }
  }
  if (/^AWSTemplateFormatVersion|^Resources:|^Parameters:/.test(trimmed)) return 'cloudformation';
  return 'unknown';
}

export function parseIac(content: string): { format: IacReconciliationReport['format']; observed: Observed[] } {
  if (content.length > MAX_IAC_BYTES) return { format: 'unknown', observed: [] };
  const format = detectFormat(content);
  const observed: Observed[] = [];

  try {
    if (format === 'terraform-plan') {
      const j = JSON.parse(content) as {
        resource_changes?: { type: string; name: string; change?: { after?: Record<string, unknown> } }[];
        planned_values?: { root_module?: { resources?: { type: string; name: string; values?: Record<string, unknown> }[] } };
      };
      const list = j.resource_changes ?? j.planned_values?.root_module?.resources ?? [];
      for (const r of list as { type: string; name: string; change?: { after?: Record<string, unknown> }; values?: Record<string, unknown> }[]) {
        const values = r.change?.after ?? r.values ?? {};
        observed.push({
          type: r.type,
          name: r.name,
          layer: RESOURCE_LAYER[r.type] ?? 'app',
          encryptionAtRest: bool(values['storage_encrypted'] ?? values['server_side_encryption_configuration'] ?? values['encryption']),
          encryptionInTransit: bool(values['minimum_tls_version'] ?? values['require_secure_transport'])
        });
      }
    } else if (format === 'cloudformation') {
      const j: { Resources?: Record<string, { Type: string; Properties?: Record<string, unknown> }> } =
        // JSON_SCHEMA disallows `!!js/function`, binary, timestamp and
        // other types whose constructors could be coerced into native
        // code or denial-of-service amplification.
        content.trimStart().startsWith('{') ? JSON.parse(content) : (yaml.load(content, { schema: yaml.JSON_SCHEMA }) as never);
      const res = j.Resources ?? {};
      for (const [name, def] of Object.entries(res)) {
        observed.push({
          type: def.Type,
          name,
          layer: RESOURCE_LAYER[def.Type] ?? 'app',
          encryptionAtRest: bool((def.Properties as Record<string, unknown>)?.['BucketEncryption'] ?? (def.Properties as Record<string, unknown>)?.['StorageEncrypted'] ?? (def.Properties as Record<string, unknown>)?.['KmsKeyId']),
          encryptionInTransit: bool((def.Properties as Record<string, unknown>)?.['MinimumProtocolVersion'])
        });
      }
    } else if (format === 'cdk-synth') {
      const j = JSON.parse(content) as { Resources?: Record<string, { Type: string; Properties?: Record<string, unknown> }> } | Record<string, unknown>[];
      const cf = Array.isArray(j) ? null : j;
      if (cf?.Resources) {
        for (const [name, def] of Object.entries(cf.Resources)) {
          observed.push({
            type: def.Type,
            name,
            layer: RESOURCE_LAYER[def.Type] ?? 'app',
            encryptionAtRest: bool((def.Properties as Record<string, unknown>)?.['BucketEncryption']),
            encryptionInTransit: undefined
          });
        }
      }
    }
  } catch (err) {
    // Tolerate malformed input; report empty observed list.
    return { format, observed: [] };
  }
  return { format, observed };
}

function bool(v: unknown): boolean | undefined {
  if (v === undefined || v === null) return undefined;
  if (typeof v === 'boolean') return v;
  if (typeof v === 'string') return /^(true|enabled|aws:kms|tls.*1\.[2-9])/i.test(v);
  if (typeof v === 'object') return true; // presence of a config object implies enabled
  return undefined;
}

export function reconcileIac(content: string, arch: Architecture): IacReconciliationReport {
  const { format, observed } = parseIac(content);

  const matched: IacReconciliationReport['matched'] = [];
  const missing: IacReconciliationReport['missing'] = [];
  const encryptionMismatches: IacReconciliationReport['encryptionMismatches'] = [];

  const observedTypes = new Set(observed.map(o => o.type));
  const matchedObservedNames = new Set<string>();

  for (const c of arch.components) {
    const hints = COMPONENT_RESOURCE_HINTS[c.id];
    if (!hints) continue; // not all components are IaC-managed (e.g. users, IdP)
    const obs = observed.find(o => hints.includes(o.type));
    if (!obs) {
      missing.push({ expectedId: c.id, expectedName: c.name, layer: c.layer });
      continue;
    }
    matched.push({ expectedId: c.id, observedType: obs.type, observedName: obs.name });
    matchedObservedNames.add(`${obs.type}:${obs.name}`);
    if (c.encryptionAtRest && obs.encryptionAtRest === false) {
      encryptionMismatches.push({ component: c.name, expected: 'encryption-at-rest=on', observed: 'off' });
    }
    if (c.encryptionInTransit && obs.encryptionInTransit === false) {
      encryptionMismatches.push({ component: c.name, expected: 'encryption-in-transit=on', observed: 'off' });
    }
  }

  const unexpected = observed
    .filter(o => !matchedObservedNames.has(`${o.type}:${o.name}`))
    .map(o => ({ observedType: o.type, observedName: o.name }));

  const summary = `${matched.length} components matched IaC; ${missing.length} described component(s) not found; ${unexpected.length} IaC resource(s) without architectural mapping; ${encryptionMismatches.length} encryption mismatch(es).`;

  return {
    format,
    observedResources: observed,
    expectedComponents: arch.components.map(c => ({ id: c.id, name: c.name, layer: c.layer })),
    matched,
    missing,
    unexpected,
    encryptionMismatches,
    summary
  };
}
