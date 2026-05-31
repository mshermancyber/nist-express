// Curated AWS service catalog used by the architecture engine. Each
// service is tagged with the architecture layer it normally occupies
// and the inherited NIST controls AWS commonly attests for that
// service through the shared responsibility model.

export interface AwsServiceDef {
  name: string;
  layer:
    | 'edge'
    | 'identity'
    | 'app'
    | 'data'
    | 'integration'
    | 'logging'
    | 'monitoring'
    | 'backup'
    | 'admin';
  category: string;
  inheritedControls: string[];     // NIST 800-53 ids AWS attests
  notes: string;
}

export const AWS_SERVICES: AwsServiceDef[] = [
  // Edge / Network
  { name: 'Amazon CloudFront', layer: 'edge', category: 'CDN', inheritedControls: ['PE-3', 'MA-2', 'SC-7'], notes: 'TLS termination, global PoPs, integrates with WAF/Shield.' },
  { name: 'AWS WAF', layer: 'edge', category: 'Web App Firewall', inheritedControls: ['PE-3'], notes: 'OWASP Top 10 managed rule groups; rate-based rules.' },
  { name: 'AWS Shield Standard', layer: 'edge', category: 'DDoS', inheritedControls: ['PE-3'], notes: 'Automatic L3/L4 DDoS mitigation; Advanced for higher tiers.' },
  { name: 'Amazon Route 53', layer: 'edge', category: 'DNS', inheritedControls: ['PE-3'], notes: 'Health-checked, multi-region failover routing.' },
  { name: 'Elastic Load Balancing (ALB)', layer: 'edge', category: 'Load Balancer', inheritedControls: ['PE-3', 'MA-2'], notes: 'TLS 1.2+ policies; integrates with WAF and Cognito.' },
  // Identity
  { name: 'AWS IAM Identity Center', layer: 'identity', category: 'SSO', inheritedControls: ['PE-3', 'MA-2'], notes: 'SAML/OIDC SSO entry point; pair with external IdP (Okta).' },
  { name: 'AWS IAM', layer: 'identity', category: 'Identity', inheritedControls: ['PE-3', 'MA-2'], notes: 'Identity-based and resource-based policies.' },
  { name: 'Amazon Cognito', layer: 'identity', category: 'Customer Identity', inheritedControls: ['PE-3', 'MA-2'], notes: 'User pools and identity pools for customer apps.' },
  { name: 'AWS Secrets Manager', layer: 'identity', category: 'Secrets', inheritedControls: ['PE-3', 'MA-2', 'SC-12'], notes: 'Automatic rotation; integration with RDS and Lambda.' },
  { name: 'AWS KMS', layer: 'identity', category: 'Key Management', inheritedControls: ['PE-3', 'MA-2', 'SC-12', 'SC-13'], notes: 'CMKs with rotation; FIPS 140-validated.' },
  // App
  { name: 'Amazon ECS (Fargate)', layer: 'app', category: 'Containers', inheritedControls: ['PE-3', 'MA-2'], notes: 'Serverless containers; task IAM roles per service.' },
  { name: 'Amazon EKS', layer: 'app', category: 'Kubernetes', inheritedControls: ['PE-3', 'MA-2'], notes: 'Pod identity via IRSA; control plane logs to CloudWatch.' },
  { name: 'AWS Lambda', layer: 'app', category: 'Serverless', inheritedControls: ['PE-3', 'MA-2'], notes: 'Function-level IAM, short-lived execution.' },
  { name: 'Amazon API Gateway', layer: 'app', category: 'API', inheritedControls: ['PE-3', 'MA-2', 'SC-7'], notes: 'Throttling, IAM/Cognito authorizers; mutual TLS optional.' },
  { name: 'Amazon EC2', layer: 'app', category: 'Compute', inheritedControls: ['PE-3'], notes: 'Customer manages OS hardening and patching (SSM).' },
  // Data
  { name: 'Amazon RDS (PostgreSQL)', layer: 'data', category: 'Relational DB', inheritedControls: ['PE-3', 'MA-2'], notes: 'SSE-KMS at rest; TLS in transit; automated backups.' },
  { name: 'Amazon Aurora', layer: 'data', category: 'Relational DB', inheritedControls: ['PE-3', 'MA-2'], notes: 'Storage auto-grow; cross-region replicas.' },
  { name: 'Amazon DynamoDB', layer: 'data', category: 'NoSQL', inheritedControls: ['PE-3', 'MA-2'], notes: 'Encryption-by-default; PITR; global tables.' },
  { name: 'Amazon S3', layer: 'data', category: 'Object Storage', inheritedControls: ['PE-3', 'MA-2'], notes: 'SSE-KMS, bucket policies, object lock for immutability.' },
  { name: 'Amazon ElastiCache (Redis)', layer: 'data', category: 'Cache', inheritedControls: ['PE-3', 'MA-2'], notes: 'In-transit and at-rest encryption; AUTH tokens.' },
  // Integration
  { name: 'Amazon EventBridge', layer: 'integration', category: 'Event Bus', inheritedControls: ['PE-3', 'MA-2'], notes: 'Schema registry, cross-account event delivery.' },
  { name: 'Amazon SQS', layer: 'integration', category: 'Queue', inheritedControls: ['PE-3', 'MA-2'], notes: 'SSE-KMS, FIFO, DLQ.' },
  { name: 'Amazon MSK', layer: 'integration', category: 'Streaming', inheritedControls: ['PE-3', 'MA-2'], notes: 'Kafka with TLS, IAM auth, audit to CloudWatch.' },
  { name: 'AWS Transfer Family', layer: 'integration', category: 'File Transfer', inheritedControls: ['PE-3', 'MA-2'], notes: 'SFTP/FTPS to S3 with IAM-bound users.' },
  // Logging
  { name: 'AWS CloudTrail', layer: 'logging', category: 'API Audit', inheritedControls: ['PE-3', 'MA-2'], notes: 'Org-wide trail to dedicated log archive account.' },
  { name: 'Amazon CloudWatch Logs', layer: 'logging', category: 'Application Logs', inheritedControls: ['PE-3', 'MA-2'], notes: 'Retention, metric filters, subscription filters.' },
  { name: 'AWS Config', layer: 'logging', category: 'Configuration', inheritedControls: ['PE-3', 'MA-2', 'CM-8'], notes: 'Resource configuration history; conformance packs.' },
  { name: 'Amazon S3 (Log Archive)', layer: 'logging', category: 'Log Storage', inheritedControls: ['PE-3', 'MA-2'], notes: 'Object lock + cross-region replication.' },
  // Monitoring
  { name: 'AWS Security Hub', layer: 'monitoring', category: 'Posture Management', inheritedControls: ['PE-3', 'MA-2'], notes: 'CIS AWS Foundations, FSBP, PCI standards.' },
  { name: 'Amazon GuardDuty', layer: 'monitoring', category: 'Threat Detection', inheritedControls: ['PE-3', 'MA-2'], notes: 'ML-based threat detection from CloudTrail/VPC/DNS.' },
  { name: 'Amazon Inspector', layer: 'monitoring', category: 'Vulnerability', inheritedControls: ['PE-3', 'MA-2'], notes: 'Continuous EC2/ECR/Lambda vulnerability assessment.' },
  { name: 'Amazon Detective', layer: 'monitoring', category: 'Investigation', inheritedControls: ['PE-3', 'MA-2'], notes: 'Graph-based investigation from VPC/CloudTrail/GuardDuty.' },
  // Backup
  { name: 'AWS Backup', layer: 'backup', category: 'Backup', inheritedControls: ['PE-3', 'MA-2'], notes: 'Cross-account, cross-region vault with vault lock.' },
  { name: 'Amazon S3 (Backup)', layer: 'backup', category: 'Object Backup', inheritedControls: ['PE-3', 'MA-2'], notes: 'Versioning, MFA delete, replication to secondary region.' },
  // Admin
  { name: 'AWS Systems Manager', layer: 'admin', category: 'Operations', inheritedControls: ['PE-3', 'MA-2'], notes: 'Patching, parameter store, session manager.' },
  { name: 'AWS Organizations', layer: 'admin', category: 'Governance', inheritedControls: ['PE-3', 'MA-2'], notes: 'SCP guardrails; OU structure.' }
];

export function findService(name: string): AwsServiceDef | undefined {
  return AWS_SERVICES.find(s => s.name === name);
}
