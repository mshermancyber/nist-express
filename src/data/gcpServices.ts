// GCP service catalog — parallel of awsServices.ts.

export interface GcpServiceDef {
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

export const GCP_SERVICES: GcpServiceDef[] = [
  { name: 'Cloud CDN', layer: 'edge', category: 'CDN', inheritedControls: ['PE-3', 'MA-2', 'SC-7'], notes: 'Global edge cache.' },
  { name: 'Google Cloud Armor', layer: 'edge', category: 'WAF', inheritedControls: ['PE-3'], notes: 'WAF + DDoS.' },
  { name: 'Cloud DNS', layer: 'edge', category: 'DNS', inheritedControls: ['PE-3'], notes: 'Authoritative DNS.' },
  { name: 'External HTTPS LB', layer: 'edge', category: 'L7 LB', inheritedControls: ['PE-3', 'MA-2'], notes: 'Global L7 load balancer.' },
  { name: 'Google Identity (Cloud Identity)', layer: 'identity', category: 'IdP', inheritedControls: ['PE-3', 'MA-2'], notes: 'Org-wide identity.' },
  { name: 'Cloud IAM', layer: 'identity', category: 'IAM', inheritedControls: ['PE-3', 'MA-2'], notes: 'Resource-based policies.' },
  { name: 'Cloud KMS', layer: 'identity', category: 'KMS', inheritedControls: ['PE-3', 'MA-2', 'SC-12', 'SC-13'], notes: 'CMEK with HSM option (Cloud HSM).' },
  { name: 'Secret Manager', layer: 'identity', category: 'Secrets', inheritedControls: ['PE-3', 'MA-2', 'SC-12'], notes: 'Versioned secret storage.' },
  { name: 'Cloud Run', layer: 'app', category: 'Containers', inheritedControls: ['PE-3', 'MA-2'], notes: 'Serverless containers.' },
  { name: 'GKE Autopilot', layer: 'app', category: 'Kubernetes', inheritedControls: ['PE-3', 'MA-2'], notes: 'Managed Kubernetes.' },
  { name: 'Cloud Functions', layer: 'app', category: 'Serverless', inheritedControls: ['PE-3', 'MA-2'], notes: 'Event-driven functions.' },
  { name: 'API Gateway', layer: 'app', category: 'API', inheritedControls: ['PE-3', 'MA-2', 'SC-7'], notes: 'Managed API endpoints.' },
  { name: 'Cloud SQL (PostgreSQL)', layer: 'data', category: 'Relational DB', inheritedControls: ['PE-3', 'MA-2'], notes: 'Managed PostgreSQL with CMEK.' },
  { name: 'AlloyDB', layer: 'data', category: 'Relational DB', inheritedControls: ['PE-3', 'MA-2'], notes: 'PostgreSQL-compatible HA database.' },
  { name: 'Firestore', layer: 'data', category: 'NoSQL', inheritedControls: ['PE-3', 'MA-2'], notes: 'Document database.' },
  { name: 'Cloud Storage', layer: 'data', category: 'Object Storage', inheritedControls: ['PE-3', 'MA-2'], notes: 'GCS with CMEK and Bucket Lock.' },
  { name: 'Memorystore (Redis)', layer: 'data', category: 'Cache', inheritedControls: ['PE-3', 'MA-2'], notes: 'Managed Redis.' },
  { name: 'Pub/Sub', layer: 'integration', category: 'Event Bus', inheritedControls: ['PE-3', 'MA-2'], notes: 'Async messaging.' },
  { name: 'Eventarc', layer: 'integration', category: 'Event Router', inheritedControls: ['PE-3', 'MA-2'], notes: 'Cross-service event routing.' },
  { name: 'Cloud Logging', layer: 'logging', category: 'Application Logs', inheritedControls: ['PE-3', 'MA-2'], notes: 'Aggregated logs with sinks.' },
  { name: 'Cloud Audit Logs', layer: 'logging', category: 'API Audit', inheritedControls: ['PE-3', 'MA-2'], notes: 'Admin, data, and system event logs.' },
  { name: 'Security Command Center', layer: 'monitoring', category: 'Posture / Threat', inheritedControls: ['PE-3', 'MA-2'], notes: 'CSPM + Event Threat Detection.' },
  { name: 'Chronicle SecOps', layer: 'monitoring', category: 'SIEM', inheritedControls: ['PE-3', 'MA-2'], notes: 'Google-native SIEM.' },
  { name: 'Backup and DR Service', layer: 'backup', category: 'Backup', inheritedControls: ['PE-3', 'MA-2'], notes: 'Application-consistent backups.' },
  { name: 'OS Login / IAP TCP Tunnel', layer: 'admin', category: 'Operations', inheritedControls: ['PE-3', 'MA-2'], notes: 'SSH/RDP via Identity-Aware Proxy.' }
];
