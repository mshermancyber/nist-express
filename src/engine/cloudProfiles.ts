// Cloud profiles abstract the cloud-specific service names from the
// architecture builder. Each profile maps an architectural role
// (e.g. "edge_waf", "data_relational") to a concrete service name in
// that cloud. The architecture engine renders a uniform component
// graph by looking up names from the active profile.

export type Role =
  | 'idp'
  | 'sso'
  | 'kms'
  | 'secrets'
  | 'dns'
  | 'waf'
  | 'cdn'
  | 'alb'
  | 'apigw'
  | 'app_serverless'
  | 'app_containers'
  | 'data_relational'
  | 'data_object'
  | 'log_audit'
  | 'log_app'
  | 'log_config'
  | 'log_archive'
  | 'mon_posture'
  | 'mon_threat'
  | 'backup'
  | 'admin_ops';

export interface CloudProfile {
  cloudName: 'AWS' | 'Azure' | 'GCP';
  services: Partial<Record<Role, string>>;
  // Components describe how role names map onto presentational labels.
  componentLabels: Partial<Record<Role, string>>;
}

export const AWS_PROFILE: CloudProfile = {
  cloudName: 'AWS',
  services: {
    sso: 'AWS IAM Identity Center',
    kms: 'AWS KMS',
    secrets: 'AWS Secrets Manager',
    dns: 'Amazon Route 53',
    waf: 'AWS WAF',
    cdn: 'Amazon CloudFront',
    alb: 'Elastic Load Balancing (ALB)',
    apigw: 'Amazon API Gateway',
    app_serverless: 'AWS Lambda',
    app_containers: 'Amazon ECS (Fargate)',
    data_relational: 'Amazon Aurora',
    data_object: 'Amazon S3',
    log_audit: 'AWS CloudTrail',
    log_app: 'Amazon CloudWatch Logs',
    log_config: 'AWS Config',
    log_archive: 'Amazon S3 (Log Archive)',
    mon_posture: 'AWS Security Hub',
    mon_threat: 'Amazon GuardDuty',
    backup: 'AWS Backup',
    admin_ops: 'AWS Systems Manager'
  },
  componentLabels: {
    sso: 'AWS IAM Identity Center',
    kms: 'AWS KMS (Customer-Managed Keys)',
    secrets: 'AWS Secrets Manager',
    dns: 'Amazon Route 53',
    waf: 'AWS WAF + Shield',
    cdn: 'Amazon CloudFront',
    alb: 'Application Load Balancer',
    apigw: 'Amazon API Gateway',
    app_serverless: 'Application (AWS Lambda)',
    app_containers: 'Application (ECS Fargate)',
    data_relational: 'Primary Database (Amazon Aurora PostgreSQL)',
    data_object: 'Object Storage (Amazon S3)',
    log_audit: 'AWS CloudTrail (Org Trail)',
    log_app: 'Amazon CloudWatch Logs',
    log_config: 'AWS Config',
    log_archive: 'Log Archive (Amazon S3 with Object Lock)',
    mon_posture: 'AWS Security Hub',
    mon_threat: 'Amazon GuardDuty',
    backup: 'AWS Backup (Vault Lock)',
    admin_ops: 'AWS Systems Manager'
  }
};

export const AZURE_PROFILE: CloudProfile = {
  cloudName: 'Azure',
  services: {
    sso: 'Microsoft Entra ID (Azure AD)',
    kms: 'Azure Key Vault',
    secrets: 'Azure Key Vault',
    dns: 'Azure DNS',
    waf: 'Azure Front Door',
    cdn: 'Azure Front Door',
    alb: 'Azure Application Gateway',
    apigw: 'Azure API Management',
    app_serverless: 'Azure Functions',
    app_containers: 'Azure Container Apps',
    data_relational: 'Azure SQL Database',
    data_object: 'Azure Blob Storage',
    log_audit: 'Azure Activity Log',
    log_app: 'Azure Monitor Logs',
    log_config: 'Azure Monitor Logs',
    log_archive: 'Azure Blob Storage (Immutable)',
    mon_posture: 'Microsoft Defender for Cloud',
    mon_threat: 'Microsoft Sentinel',
    backup: 'Azure Backup',
    admin_ops: 'Azure Bastion'
  },
  componentLabels: {
    sso: 'Microsoft Entra ID',
    kms: 'Azure Key Vault (HSM-backed CMK)',
    secrets: 'Azure Key Vault Secrets',
    dns: 'Azure DNS',
    waf: 'Azure Front Door + WAF',
    cdn: 'Azure Front Door (Premium)',
    alb: 'Azure Application Gateway',
    apigw: 'Azure API Management',
    app_serverless: 'Application (Azure Functions)',
    app_containers: 'Application (Container Apps)',
    data_relational: 'Primary Database (Azure SQL DB)',
    data_object: 'Object Storage (Blob Storage)',
    log_audit: 'Azure Activity Log',
    log_app: 'Azure Monitor Logs',
    log_config: 'Azure Policy & Resource Graph',
    log_archive: 'Immutable Blob Container',
    mon_posture: 'Microsoft Defender for Cloud',
    mon_threat: 'Microsoft Sentinel',
    backup: 'Azure Backup (Vault)',
    admin_ops: 'Azure Bastion + Update Mgr'
  }
};

export const GCP_PROFILE: CloudProfile = {
  cloudName: 'GCP',
  services: {
    sso: 'Google Identity (Cloud Identity)',
    kms: 'Cloud KMS',
    secrets: 'Secret Manager',
    dns: 'Cloud DNS',
    waf: 'Google Cloud Armor',
    cdn: 'Cloud CDN',
    alb: 'External HTTPS LB',
    apigw: 'API Gateway',
    app_serverless: 'Cloud Functions',
    app_containers: 'Cloud Run',
    data_relational: 'Cloud SQL (PostgreSQL)',
    data_object: 'Cloud Storage',
    log_audit: 'Cloud Audit Logs',
    log_app: 'Cloud Logging',
    log_config: 'Cloud Asset Inventory',
    log_archive: 'Cloud Storage (Bucket Lock)',
    mon_posture: 'Security Command Center',
    mon_threat: 'Chronicle SecOps',
    backup: 'Backup and DR Service',
    admin_ops: 'OS Login / IAP TCP Tunnel'
  },
  componentLabels: {
    sso: 'Google Cloud Identity',
    kms: 'Cloud KMS (HSM-backed)',
    secrets: 'Secret Manager',
    dns: 'Cloud DNS',
    waf: 'Cloud Armor',
    cdn: 'Cloud CDN',
    alb: 'External HTTPS Load Balancer',
    apigw: 'API Gateway',
    app_serverless: 'Application (Cloud Functions)',
    app_containers: 'Application (Cloud Run)',
    data_relational: 'Primary Database (Cloud SQL PostgreSQL)',
    data_object: 'Object Storage (Cloud Storage)',
    log_audit: 'Cloud Audit Logs',
    log_app: 'Cloud Logging',
    log_config: 'Cloud Asset Inventory',
    log_archive: 'Bucket-Locked GCS Archive',
    mon_posture: 'Security Command Center',
    mon_threat: 'Chronicle SecOps',
    backup: 'Backup and DR Service',
    admin_ops: 'IAP TCP Tunnel'
  }
};

export function profileFor(model: string): CloudProfile {
  if (model === 'Azure') return AZURE_PROFILE;
  if (model === 'GCP') return GCP_PROFILE;
  return AWS_PROFILE;
}
