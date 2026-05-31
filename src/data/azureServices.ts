// Azure service catalog — the parallel of awsServices.ts for the
// Azure architecture renderer. Each entry tags the architectural
// layer and the Azure-shared-responsibility controls it commonly
// attests.

export interface AzureServiceDef {
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
  inheritedControls: string[];
  notes: string;
}

export const AZURE_SERVICES: AzureServiceDef[] = [
  { name: 'Azure Front Door', layer: 'edge', category: 'CDN/WAF', inheritedControls: ['PE-3', 'MA-2', 'SC-7'], notes: 'Global edge with WAF and DDoS protection.' },
  { name: 'Azure Application Gateway', layer: 'edge', category: 'L7 LB', inheritedControls: ['PE-3', 'MA-2'], notes: 'Regional L7 load balancer with WAF.' },
  { name: 'Azure DNS', layer: 'edge', category: 'DNS', inheritedControls: ['PE-3'], notes: 'Authoritative DNS.' },
  { name: 'Microsoft Entra ID (Azure AD)', layer: 'identity', category: 'IdP', inheritedControls: ['PE-3', 'MA-2'], notes: 'Enterprise IdP; Conditional Access and PIM.' },
  { name: 'Azure Key Vault', layer: 'identity', category: 'KMS', inheritedControls: ['PE-3', 'MA-2', 'SC-12', 'SC-13'], notes: 'Keys, secrets, certs with HSM-backed option.' },
  { name: 'Azure Container Apps', layer: 'app', category: 'Containers', inheritedControls: ['PE-3', 'MA-2'], notes: 'Serverless containers with managed identity.' },
  { name: 'Azure Kubernetes Service', layer: 'app', category: 'Kubernetes', inheritedControls: ['PE-3', 'MA-2'], notes: 'AKS with workload identity.' },
  { name: 'Azure Functions', layer: 'app', category: 'Serverless', inheritedControls: ['PE-3', 'MA-2'], notes: 'Event-driven functions.' },
  { name: 'Azure API Management', layer: 'app', category: 'API', inheritedControls: ['PE-3', 'MA-2', 'SC-7'], notes: 'API gateway with policies, OAuth/AAD authorisers.' },
  { name: 'Azure SQL Database', layer: 'data', category: 'Relational DB', inheritedControls: ['PE-3', 'MA-2'], notes: 'Managed SQL with TDE + Always Encrypted.' },
  { name: 'Azure Cosmos DB', layer: 'data', category: 'NoSQL', inheritedControls: ['PE-3', 'MA-2'], notes: 'Multi-model with global distribution.' },
  { name: 'Azure Blob Storage', layer: 'data', category: 'Object Storage', inheritedControls: ['PE-3', 'MA-2'], notes: 'SSE with CMK and immutability.' },
  { name: 'Azure Cache for Redis', layer: 'data', category: 'Cache', inheritedControls: ['PE-3', 'MA-2'], notes: 'In-transit / at-rest encryption.' },
  { name: 'Azure Event Grid', layer: 'integration', category: 'Event Bus', inheritedControls: ['PE-3', 'MA-2'], notes: 'Event routing across services.' },
  { name: 'Azure Service Bus', layer: 'integration', category: 'Queue', inheritedControls: ['PE-3', 'MA-2'], notes: 'Enterprise messaging.' },
  { name: 'Azure Monitor Logs', layer: 'logging', category: 'Application Logs', inheritedControls: ['PE-3', 'MA-2'], notes: 'Log Analytics workspace.' },
  { name: 'Azure Activity Log', layer: 'logging', category: 'API Audit', inheritedControls: ['PE-3', 'MA-2'], notes: 'Subscription-level audit.' },
  { name: 'Microsoft Defender for Cloud', layer: 'monitoring', category: 'Posture / Threat', inheritedControls: ['PE-3', 'MA-2'], notes: 'CSPM + workload protection.' },
  { name: 'Microsoft Sentinel', layer: 'monitoring', category: 'SIEM', inheritedControls: ['PE-3', 'MA-2'], notes: 'Cloud-native SIEM/SOAR.' },
  { name: 'Azure Backup', layer: 'backup', category: 'Backup', inheritedControls: ['PE-3', 'MA-2'], notes: 'Recovery Services vault with soft-delete.' },
  { name: 'Azure Bastion', layer: 'admin', category: 'Operations', inheritedControls: ['PE-3', 'MA-2'], notes: 'Browser-based RDP/SSH to private VMs.' }
];
