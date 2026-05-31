// Cloud snapshot reconciliation. Accepts a JSON snapshot from one of:
//   - AWS Config (list-discovered-resources / get-resource-config-history)
//   - AWS Security Hub (get-findings)
//   - Azure Resource Graph (POST /providers/Microsoft.ResourceGraph/resources)
//   - GCP Cloud Asset Inventory (assets.list)
//
// Resource types are normalised so they can be matched against the
// expected architecture, similar to the IaC reconciler but with the
// addition of live findings (Security Hub / Defender / SCC).

import { Architecture, CloudReconciliationReport } from '../types/assessment';

type Resource = { type: string; id: string; region?: string };
type Finding = { id: string; title: string; severity: string; resource?: string };

const COMPONENT_HINTS: Record<string, string[]> = {
  // From the IaC reconciler — kept in sync deliberately
  edge_route53: ['AWS::Route53::HostedZone', 'Microsoft.Network/dnsZones', 'dns.googleapis.com/ManagedZone'],
  edge_waf: ['AWS::WAFv2::WebACL', 'Microsoft.Network/frontDoors', 'compute.googleapis.com/SecurityPolicy'],
  edge_cf: ['AWS::CloudFront::Distribution', 'Microsoft.Network/frontDoors'],
  edge_alb: ['AWS::ElasticLoadBalancingV2::LoadBalancer', 'Microsoft.Network/applicationGateways', 'compute.googleapis.com/GlobalForwardingRule'],
  aws_kms: ['AWS::KMS::Key', 'Microsoft.KeyVault/vaults', 'cloudkms.googleapis.com/CryptoKey'],
  aws_secrets: ['AWS::SecretsManager::Secret', 'Microsoft.KeyVault/vaults', 'secretmanager.googleapis.com/Secret'],
  app_apigw: ['AWS::ApiGateway::RestApi', 'AWS::ApiGatewayV2::Api', 'Microsoft.ApiManagement/service', 'apigateway.googleapis.com/Api'],
  app_lambda: ['AWS::Lambda::Function', 'Microsoft.Web/sites', 'cloudfunctions.googleapis.com/CloudFunction'],
  app_ecs: ['AWS::ECS::Service', 'AWS::ECS::Cluster', 'Microsoft.App/containerApps', 'run.googleapis.com/Service'],
  data_rds: ['AWS::RDS::DBInstance', 'AWS::RDS::DBCluster', 'Microsoft.Sql/servers/databases', 'sqladmin.googleapis.com/Instance'],
  data_s3: ['AWS::S3::Bucket', 'Microsoft.Storage/storageAccounts', 'storage.googleapis.com/Bucket'],
  log_cloudtrail: ['AWS::CloudTrail::Trail', 'microsoft.insights/diagnosticSettings'],
  log_cwl: ['AWS::Logs::LogGroup', 'Microsoft.OperationalInsights/workspaces', 'logging.googleapis.com/LogSink'],
  log_config: ['AWS::Config::ConfigurationRecorder'],
  log_archive: ['AWS::S3::Bucket', 'Microsoft.Storage/storageAccounts', 'storage.googleapis.com/Bucket'],
  mon_sechub: ['AWS::SecurityHub::Hub', 'Microsoft.Security/secureScores', 'securitycenter.googleapis.com/Source'],
  mon_gd: ['AWS::GuardDuty::Detector', 'Microsoft.SecurityInsights'],
  bkp_backup: ['AWS::Backup::BackupVault', 'Microsoft.RecoveryServices/vaults', 'backupdr.googleapis.com/BackupPlan'],
  adm_ssm: ['AWS::SSM::Document', 'Microsoft.Network/bastionHosts', 'iap.googleapis.com/TunnelIamPolicy']
};

export function detectCloudFormat(content: string): CloudReconciliationReport['source'] | 'unknown' {
  try {
    const j = JSON.parse(content) as Record<string, unknown>;
    if (Array.isArray(j['Findings']) || Array.isArray(j['findings'])) return 'aws-security-hub';
    if (Array.isArray(j['resourceIdentifiers'])) return 'aws-config';
    if (Array.isArray(j['data']) && (j as { data?: unknown[] }).data?.[0] && typeof (j as { data?: { type?: string }[] }).data?.[0]?.type === 'string') return 'azure-resource-graph';
    if (Array.isArray(j['assets'])) return 'gcp-cloud-asset-inventory';
  } catch { /* ignore */ }
  return 'unknown';
}

export function reconcileCloud(content: string, arch: Architecture): CloudReconciliationReport {
  const source = detectCloudFormat(content) === 'unknown' ? 'aws-config' : detectCloudFormat(content) as CloudReconciliationReport['source'];
  let observed: Resource[] = [];
  let findings: Finding[] = [];
  try {
    const j = JSON.parse(content) as Record<string, unknown>;
    if (source === 'aws-config') {
      const list = (j['resourceIdentifiers'] as { resourceType: string; resourceId: string; region?: string }[]) ?? [];
      observed = list.map(r => ({ type: r.resourceType, id: r.resourceId, region: r.region }));
    } else if (source === 'aws-security-hub') {
      const list = ((j['Findings'] ?? j['findings']) as { Id?: string; Title?: string; Severity?: { Label?: string }; Resources?: { Id?: string }[] }[]) ?? [];
      findings = list.map(f => ({ id: f.Id ?? '', title: f.Title ?? '', severity: f.Severity?.Label ?? 'INFORMATIONAL', resource: f.Resources?.[0]?.Id }));
      // Findings imply observed resources — extract distinct resource ids
      const seen = new Set<string>();
      for (const f of list) {
        for (const r of f.Resources ?? []) {
          const id = r.Id ?? '';
          if (id && !seen.has(id)) { seen.add(id); observed.push({ type: id.split(':')[2] || 'unknown', id }); }
        }
      }
    } else if (source === 'azure-resource-graph') {
      const data = (j['data'] as { type: string; id: string; location?: string }[]) ?? [];
      observed = data.map(d => ({ type: d.type, id: d.id, region: d.location }));
    } else if (source === 'gcp-cloud-asset-inventory') {
      const list = (j['assets'] as { assetType: string; name: string }[]) ?? [];
      observed = list.map(a => ({ type: a.assetType, id: a.name }));
    }
  } catch { /* tolerate */ }

  const matched: CloudReconciliationReport['matched'] = [];
  const missing: CloudReconciliationReport['missing'] = [];
  for (const c of arch.components) {
    const hints = COMPONENT_HINTS[c.id];
    if (!hints) continue;
    const m = observed.find(o => hints.some(h => o.type === h || o.id.includes(h)));
    if (m) matched.push({ expectedId: c.id, observedType: m.type, observedId: m.id });
    else missing.push({ expectedId: c.id, expectedName: c.name });
  }

  const summary = `${observed.length} observed resources; ${matched.length} components matched; ${missing.length} described but not observed; ${findings.length} live findings.`;
  return { source, observedResources: observed, findings, matched, missing, summary };
}
