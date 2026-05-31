// Core domain types for the Security Architecture Assessment Platform.
// These shapes are the single source of truth — every engine module
// consumes Assessment and produces typed artifacts. Mirrors the
// questionnaire sections defined in the product brief.

export type UserPopulation =
  | 'Under 100'
  | '100-1000'
  | '1000-10000'
  | '10000+';

export type UserType =
  | 'Employees'
  | 'Customers'
  | 'Vendors'
  | 'Partners'
  | 'Public Users'
  | 'Contractors'
  | 'System-to-System';

export type DataCategory =
  | 'Customer Information'
  | 'Employee Information'
  | 'Financial Data'
  | 'Source Code'
  | 'Intellectual Property'
  | 'Operational Data'
  | 'Public Information';

export type SensitiveDataTag =
  | 'PII'
  | 'PCI'
  | 'PHI'
  | 'Trade Secrets'
  | 'Regulated Data'
  | 'Export Controlled Data';

export type ImpactLevel = 'Low' | 'Moderate' | 'High';

export type RecoveryTime =
  | '15 Minutes'
  | '1 Hour'
  | '4 Hours'
  | '24 Hours'
  | '72 Hours';

export type RecoveryPoint =
  | 'No Data Loss'
  | '15 Minutes'
  | '1 Hour'
  | '24 Hours';

export type Compliance =
  | 'NIST 800-53'
  | 'NIST 800-171'
  | 'CMMC'
  | 'NIST CSF 2.0'
  | 'NIST AI RMF'
  | 'EU AI Act'
  | 'SOC2'
  | 'ISO 27001'
  | 'PCI DSS'
  | 'HIPAA'
  | 'HITRUST CSF'
  | 'FedRAMP'
  | 'GDPR'
  | 'CCPA'
  | 'DORA'
  | 'FFIEC'
  | 'IRS Pub 1075'
  | 'Internal Policy Only';

export type Hosting = 'AWS' | 'Azure' | 'GCP' | 'Hybrid' | 'On-Prem';

export type Protocol =
  | 'HTTPS'
  | 'TLS'
  | 'SFTP'
  | 'gRPC'
  | 'JDBC/ODBC'
  | 'AMQP'
  | 'Kafka'
  | 'Other';

export type AuthMethod =
  | 'OAuth2'
  | 'SAML'
  | 'API Key'
  | 'mTLS'
  | 'Service Account'
  | 'Basic Auth'
  | 'None';

export interface Integration {
  source: string;
  destination: string;
  protocol: Protocol;
  authentication: AuthMethod;
  dataDirection: 'inbound' | 'outbound' | 'bidirectional';
  description?: string;
}

export interface BusinessOverview {
  applicationName: string;
  businessArea?: string;          // e.g. "Finance", "HR", "Customer Operations"
  businessProblem: string;        // the [use case]
  userTypes: UserType[];
  userInteractionDescription: string;
}

export interface DataClassification {
  dataCategories: DataCategory[];
  confidentialToCompany: boolean;
  sensitiveDataTags: SensitiveDataTag[];
}

export interface BusinessImpact {
  confidentialityWorstCase: string;
  integrityWorstCase: string;
  availabilityWorstCase: string;
}

export interface RecoveryRequirements {
  rto: RecoveryTime;
  rpo: RecoveryPoint;
}

export interface UserPopulationSection {
  userCount: UserPopulation;
  expectedGrowth: string;
}

export interface ComplianceSection {
  frameworks: Compliance[];
}

export interface HostingSection {
  model: Hosting;
}

// Optional advanced inputs technical users can override
export interface AdvancedOverrides {
  forceMfa?: boolean;
  forceOkta?: boolean;
  preferredAwsRegion?: string;
  multiRegion?: boolean;
  customControlIds?: string[];      // e.g. add SC-12 manually
  excludeControlIds?: string[];     // e.g. exclude SI-7 with justification
  loggingRetentionDays?: number;
  customAwsServices?: string[];     // names of additional AWS services
}

export interface Assessment {
  id: string;
  createdAt: string;
  updatedAt: string;
  status: 'draft' | 'generated' | 'reviewed' | 'approved' | 'rejected';
  business: BusinessOverview;
  data: DataClassification;
  impact: BusinessImpact;
  recovery: RecoveryRequirements;
  population: UserPopulationSection;
  integrations: Integration[];
  compliance: ComplianceSection;
  hosting: HostingSection;
  advanced?: AdvancedOverrides;
  ownerId?: string;
  team?: string;
  approvalRequest?: ApprovalRequest;
  iacAttachment?: IacAttachment;
}

export interface ApprovalRequest {
  requestedAt: string;
  requestedBy: string;
  requiredRoles: ApproverRole[];
  approvals: ApprovalSignature[];
  status: 'open' | 'approved' | 'rejected' | 'cancelled';
  packageHash: string;          // SHA-256 of the package that was signed
}

export type ApproverRole = 'security' | 'risk' | 'architecture' | 'compliance';

export interface ApprovalSignature {
  role: ApproverRole;
  userId: string;
  displayName: string;
  decision: 'approve' | 'reject';
  comment?: string;
  signedAt: string;
}

export interface IacAttachment {
  filename: string;
  format: 'terraform-plan' | 'cloudformation' | 'cdk-synth' | 'unknown';
  uploadedAt: string;
  uploadedBy?: string;
  resourceCount: number;
}

// -------- Generated artifact types --------

export interface Categorization {
  // FIPS 199 — high water mark of CIA impacts
  confidentialityImpact: ImpactLevel;
  integrityImpact: ImpactLevel;
  availabilityImpact: ImpactLevel;
  overallCategorization: ImpactLevel;
  // NIST 800-60 derived information types
  informationTypes: InformationType[];
  rationale: string[];
}

export interface InformationType {
  code: string;            // e.g. C.3.5.1
  name: string;            // e.g. Personal Identity and Authentication
  confidentiality: ImpactLevel;
  integrity: ImpactLevel;
  availability: ImpactLevel;
  basisInAssessment: string; // which input drove this selection
}

export interface ArchitectureComponent {
  id: string;
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
  awsService?: string;
  description: string;
  trustZone: string;             // e.g. "Public", "DMZ", "Private App", "Restricted Data"
  encryptionAtRest: boolean;
  encryptionInTransit: boolean;
  containsSensitiveData: boolean;
  authentication?: AuthMethod;
  rationale: string;             // why this component is here
}

export interface DataFlow {
  id: string;
  fromComponentId: string;
  toComponentId: string;
  label: string;
  protocol: Protocol;
  encrypted: boolean;
  crossesTrustBoundary: boolean;
  carriesSensitiveData: boolean;
}

export interface Architecture {
  components: ArchitectureComponent[];
  flows: DataFlow[];
  trustBoundaries: { name: string; componentIds: string[]; description: string }[];
  rationale: string[];
}

export interface StrideFinding {
  componentId: string;
  componentName: string;
  category: 'Spoofing' | 'Tampering' | 'Repudiation' | 'Information Disclosure' | 'Denial of Service' | 'Elevation of Privilege';
  description: string;
  attackPath: string;
  likelihood: 'Low' | 'Medium' | 'High';
  impact: 'Low' | 'Medium' | 'High';
  inherentRisk: 'Low' | 'Medium' | 'High' | 'Critical';
  mitigations: string[];     // control IDs
  residualRisk: 'Low' | 'Medium' | 'High' | 'Critical';
}

export interface OperationalThreat {
  category:
    | 'Single Point of Failure'
    | 'Misconfiguration'
    | 'Capacity'
    | 'Backup'
    | 'Monitoring Gap'
    | 'Vendor Dependency'
    | 'Identity'
    | 'Disaster Recovery';
  description: string;
  affectedComponents: string[];
  likelihood: 'Low' | 'Medium' | 'High';
  impact: 'Low' | 'Medium' | 'High';
  recommendation: string;
  controlReferences: string[];
}

export type ControlInheritance =
  | 'Customer'
  | 'AWS (Provider)'
  | 'Hybrid'
  | 'Common Control'
  | 'Not Applicable';

export type ControlStatus =
  | 'Implemented'
  | 'Partially Implemented'
  | 'Planned'
  | 'Not Applicable';

export interface SspControl {
  id: string;                    // e.g. AC-2
  name: string;
  family: string;                // e.g. AC
  baseline: ImpactLevel[];       // baselines this control applies to
  implementationStatement: string;
  responsibleParty: string;
  evidence: string[];            // architecture references
  inheritance: ControlInheritance;
  assessmentGuidance: string;
  implementationStatus: ControlStatus;
  rationale: string;             // why this control was selected
  cisMappings: string[];         // CIS v8 safeguard IDs
}

export interface AuditableEvent {
  name: string;
  source: string;
  ciaMapping: ('C' | 'I' | 'A')[];
  rationale: string;
  retentionDays: number;
  alerting: 'Real-time' | 'Hourly' | 'Daily' | 'On Demand';
  severityOnAlert: 'Info' | 'Warning' | 'High' | 'Critical';
  controlReferences: string[];
}

export interface RecoveryAssessment {
  rto: RecoveryTime;
  rpo: RecoveryPoint;
  availabilityTier: 'Tier 1' | 'Tier 2' | 'Tier 3' | 'Tier 4';
  multiRegion: boolean;
  multiAz: boolean;
  backupStrategy: string;
  restoreTestingCadence: string;
  failoverApproach: string;
  gaps: string[];
  recommendations: string[];
}

export interface DataClassificationAssessment {
  primaryClassification: 'Public' | 'Internal' | 'Confidential' | 'Restricted';
  handlingRequirements: string[];
  retentionGuidance: string;
  dispositionGuidance: string;
  rationale: string[];
}

export interface ResidualRisk {
  id: string;
  description: string;
  source: 'STRIDE' | 'Operational' | 'Compliance' | 'Recovery';
  inherentRisk: 'Low' | 'Medium' | 'High' | 'Critical';
  residualRisk: 'Low' | 'Medium' | 'High' | 'Critical';
  rationale: string;
  treatment: 'Mitigate' | 'Transfer' | 'Avoid' | 'Accept';
  owner: string;
}

export interface SecurityAssumption {
  text: string;
  basis: string;
}

export interface ComplianceMapping {
  framework: Compliance;
  controlId: string;             // framework-native id
  description: string;
  satisfiedByControlIds: string[]; // mapped NIST 800-53 control IDs
  coverage: 'Full' | 'Partial' | 'Gap';
}

export interface WellArchitectedScore {
  pillar: 'Security' | 'Reliability' | 'Operational Excellence' | 'Performance Efficiency' | 'Cost Optimization';
  score: number;                 // 0-100
  findings: string[];
  recommendations: string[];
}

export interface EvidenceRequest {
  controlId: string;
  artifact: string;
  collectionMethod: string;
  responsibleParty: string;
  acceptanceCriteria: string;
}

export interface ExecutiveSummary {
  oneLiner: string;
  businessContext: string;
  riskPosture: 'Low' | 'Moderate' | 'Elevated' | 'High';
  topRisks: string[];
  keyRecommendations: string[];
  goNoGoAdvice: 'Proceed' | 'Proceed With Conditions' | 'Do Not Proceed';
  conditions: string[];
}

export interface ClarificationQuestion {
  field: string;
  question: string;
  reason: string;
}

export interface ArbPackage {
  assessmentId: string;
  generatedAt: string;
  packageVersion: number;       // Incrementing version for diff support
  packageHash: string;          // SHA-256 of the deterministic-ordered package body
  categorization: Categorization;
  dataClassification: DataClassificationAssessment;
  architecture: Architecture;
  architectureDiagramMermaid: string;
  securityOverlayDiagramMermaid: string;
  dataFlowDiagramMermaid: string;
  threatModel: StrideFinding[];
  flowThreatModel: FlowStrideFinding[];
  operationalThreatModel: OperationalThreat[];
  ssp: SspControl[];
  auditableEvents: AuditableEvent[];
  recovery: RecoveryAssessment;
  residualRisks: ResidualRisk[];
  assumptions: SecurityAssumption[];
  complianceMappings: ComplianceMapping[];
  wellArchitected: WellArchitectedScore[];
  evidenceRequests: EvidenceRequest[];
  executiveSummary: ExecutiveSummary;
  clarifications: ClarificationQuestion[];
  validationReport: ValidationReport;

  // Added artifacts (M15-M22):
  oscalSsp: OscalSsp;
  mitreMappings: MitreMapping[];
  capecReferences: CapecReference[];
  linddunFindings: LinddunFinding[];
  dpia: Dpia | null;            // null when GDPR not in scope
  costEstimate: CostEstimate;
  iacReconciliation: IacReconciliationReport | null;
  diff: PackageDiff | null;     // null on first generation

  // M25-M44 additions
  sbomAnalysis: SbomAnalysis | null;
  cloudReconciliation: CloudReconciliationReport | null;
  fair: FairAnalysis;
  attackTrees: AttackTree[];
  killChainMappings: KillChainMapping[];

  // FedRAMP / federal package additions (M68-M73)
  fedramp: FedrampPackage | null;       // null when FedRAMP not in scope
}

// -------- FedRAMP Package --------
export interface FedrampPackage {
  baseline: 'LOW' | 'MODERATE' | 'HIGH' | 'LI-SaaS';
  baselineControlCount: number;
  parameterValues: { controlId: string; paramId: string; value: string }[];
  controlsInBaseline: string[];
  controlsNotImplemented: string[];     // selected but missing from SSP
  authorizationBoundary: AuthorizationBoundary;
  poam: PoamItem[];
  pta: PrivacyThresholdAnalysis;
  pia: PrivacyImpactAssessment | null;  // null if PTA says PIA not required
  iscp: ContingencyPlanSummary;
  irp: IncidentResponsePlanSummary;
  rulesOfBehavior: string[];
  cmp: ConfigurationManagementPlanSummary;
  conmon: ContinuousMonitoringStrategy;
  eAuthWorksheet: EAuthWorksheet;
  agencyOverlays: AgencyOverlay[];      // DoD IL, IRS 1075, CMS ARS, CJIS as applicable
  fipsAttestation: { fipsEnabled: boolean; mode: string; verifiedAt: string };
}

export interface AuthorizationBoundary {
  description: string;
  inScopeComponents: { id: string; name: string; trustZone: string }[];
  externalConnections: { source: string; destination: string; purpose: string; protocol: string; safeguards: string }[];
  outOfScopeAssertions: string[];
}

export interface PoamItem {
  poamId: string;
  weakness: string;
  source: 'STRIDE' | 'Operational' | 'Compliance' | 'Recovery' | 'SBOM/KEV' | 'Vulnerability Scan';
  severity: 'Low' | 'Medium' | 'High' | 'Critical';
  identifiedAt: string;
  scheduledCompletion: string;          // ISO date
  status: 'Open' | 'Ongoing' | 'Risk Accepted' | 'Completed';
  pointOfContact: string;
  resourcesRequired: string;
  milestones: { description: string; date: string; completed: boolean }[];
  controlsImpacted: string[];
}

export interface PrivacyThresholdAnalysis {
  collectsPii: boolean;
  piiCategoriesPresent: string[];
  containsSensitiveCategories: boolean;
  piaRequired: boolean;
  rationale: string;
  systemOfRecordsApplicable: boolean;
}

export interface PrivacyImpactAssessment {
  introduction: string;
  informationCollected: string;
  lawfulBasis: string[];
  retentionAndDisposition: string;
  individualParticipation: string;
  dataSharing: { partner: string; purpose: string; safeguards: string }[];
  privacyRisks: { description: string; mitigation: string }[];
  approval: { drafter: string; reviewer: string };
}

export interface ContingencyPlanSummary {
  systemName: string;
  rto: string;
  rpo: string;
  recoveryPriorities: string[];
  alternateProcessing: string;
  alternateStorage: string;
  notificationProcedures: string[];
  testingCadence: string;
  recoveryProcedures: string[];
}

export interface IncidentResponsePlanSummary {
  scope: string;
  categories: string[];
  declarationCriteria: string;
  rolesAndResponsibilities: { role: string; responsibility: string }[];
  reportingTimeline: string;
  notificationContacts: string[];
  containmentSteps: string[];
  eradicationSteps: string[];
  recoverySteps: string[];
  lessonsLearned: string;
}

export interface ConfigurationManagementPlanSummary {
  baselineSource: string;
  changeControlProcess: string;
  approvalAuthority: string;
  driftDetection: string;
  reviewCadence: string;
}

export interface ContinuousMonitoringStrategy {
  vulnScans: { scope: string; cadence: string };
  pentest: { cadence: string; scope: string };
  configCompliance: { scope: string; cadence: string };
  controlSubsetReviews: { quarterly: string[]; annual: string[] };
  reportingCadence: string;
  metrics: string[];
}

export interface EAuthWorksheet {
  assuranceLevel: 'IAL1' | 'IAL2' | 'IAL3';
  authenticatorAssuranceLevel: 'AAL1' | 'AAL2' | 'AAL3';
  federationAssuranceLevel: 'FAL1' | 'FAL2' | 'FAL3';
  rationale: string;
  mfaRequired: boolean;
  phishingResistantRequired: boolean;
}

export interface AgencyOverlay {
  name: string;             // "DoD IL5", "IRS Pub 1075", "CMS ARS 5.1", "CJIS"
  additionalControls: string[];
  parameterOverrides: { controlId: string; value: string }[];
  citizenshipRequirement?: 'US Citizen Only' | 'US Persons Only' | 'No Restriction';
  dataLocation?: string;    // "CONUS only", "GovCloud only"
}

// -------- SBOM (CycloneDX / SPDX) + VEX + KEV --------
export interface SbomAnalysis {
  format: 'cyclonedx' | 'spdx' | 'unknown';
  documentName: string;
  componentCount: number;
  components: SbomComponent[];
  vulnerabilities: SbomVulnerability[];
  vexStatements: VexStatement[];
  kevHits: SbomVulnerability[];   // intersect vulns with CISA KEV list
  affectedArchitectureComponents: string[];
  summary: string;
}
export interface SbomComponent {
  name: string;
  version: string;
  type?: string;
  purl?: string;
  licenses?: string[];
}
export interface SbomVulnerability {
  id: string;                    // CVE-... or GHSA-...
  cvssScore?: number;
  severity: 'Critical' | 'High' | 'Medium' | 'Low' | 'Unknown';
  affectsComponents: string[];   // names from the SBOM
  description?: string;
  kev: boolean;
}
export interface VexStatement {
  id: string;                    // CVE-...
  status: 'not_affected' | 'affected' | 'fixed' | 'under_investigation';
  justification?: string;
  detail?: string;
}

// -------- Cloud snapshot reconciliation (M35) --------
export interface CloudReconciliationReport {
  source: 'aws-config' | 'aws-security-hub' | 'azure-resource-graph' | 'gcp-cloud-asset-inventory';
  observedResources: { type: string; id: string; region?: string }[];
  findings: { id: string; title: string; severity: string; resource?: string }[];
  matched: { expectedId: string; observedType: string; observedId: string }[];
  missing: { expectedId: string; expectedName: string }[];
  summary: string;
}

// -------- FAIR + Monte Carlo --------
export interface FairFinding {
  riskId: string;
  description: string;
  tefLow: number;       // threat events / year (low)
  tefHigh: number;      // threat events / year (high)
  vulnLow: number;      // 0..1
  vulnHigh: number;     // 0..1
  lmLow: number;        // USD per event
  lmHigh: number;       // USD per event
  aleP10: number;
  aleP50: number;
  aleP90: number;
  aleMean: number;
  rationale: string;
}
export interface FairAnalysis {
  perRisk: FairFinding[];
  portfolio: { aleP10: number; aleP50: number; aleP90: number; aleMean: number };
  iterations: number;
  notes: string[];
}

// -------- Attack tree + Kill chain --------
export interface AttackTreeNode {
  id: string;
  label: string;
  type: 'goal' | 'tactic' | 'technique' | 'precondition';
  children: AttackTreeNode[];
}
export interface AttackTree {
  riskId: string;
  goal: string;
  root: AttackTreeNode;
}
export interface KillChainMapping {
  strideFindingIndex: number;
  stage: 'Reconnaissance' | 'Weaponization' | 'Delivery' | 'Exploitation' | 'Installation' | 'Command & Control' | 'Actions on Objectives';
  rationale: string;
}

// -------- Comments (M26) --------
export type CommentTarget = 'ssp-control' | 'residual-risk' | 'threat' | 'package' | 'flow-threat';
export interface Comment {
  id: string;
  assessmentId: string;
  targetType: CommentTarget;
  targetId: string;              // e.g. SSP control id "AC-2", residual id "RR-003"
  author: string;
  authorDisplay: string;
  body: string;
  createdAt: string;
  replyToId?: string;
  edited?: boolean;
}
export interface Watcher {
  userId: string;
  assessmentId: string;
  targetType?: CommentTarget;
  targetId?: string;
}
export interface Notification {
  id: string;
  userId: string;
  ts: string;
  kind: 'comment' | 'approval' | 'generation' | 'risk-expiry' | 'webhook';
  assessmentId?: string;
  message: string;
  read: boolean;
}

// -------- Risk acceptance (M33) --------
export interface RiskAcceptance {
  riskId: string;
  acceptedBy: string;
  acceptedAt: string;
  expiresAt: string;
  rationale: string;
  status: 'active' | 'expired' | 'released';
}

// -------- Webhooks (M31) --------
export interface WebhookSubscription {
  id: string;
  name: string;
  url: string;
  secret: string;                // HMAC signing key
  events: ('package.generated' | 'approval.requested' | 'approval.signed' | 'residual.critical' | 'comment.created' | 'risk.expiring')[];
  adapter?: 'generic' | 'slack' | 'teams';
  enabled: boolean;
  createdBy: string;
  createdAt: string;
}

// -------- External ticketing (M32) --------
export interface ExternalTicket {
  riskId: string;
  system: 'jira' | 'servicenow';
  externalId: string;
  url?: string;
  status?: string;
  createdAt: string;
}

// -------- 2FA + API keys (M34) --------
export interface UserSecurity {
  userId: string;
  totpSecret?: string;
  totpEnabled?: boolean;
  apiKeys: ApiKey[];
}
export interface ApiKey {
  id: string;
  name: string;
  hash: string;                  // sha256 of the raw secret
  prefix: string;                // first 8 chars for display
  createdAt: string;
  lastUsedAt?: string;
  revokedAt?: string;
}

// -------- Jobs (M37) --------
export interface JobRecord {
  id: string;
  kind: 'package.generate' | 'webhook.deliver' | 'ai.chat' | 'cloud.reconcile';
  assessmentId?: string;
  payload: Record<string, unknown>;
  state: 'queued' | 'running' | 'succeeded' | 'failed';
  enqueuedAt: string;
  startedAt?: string;
  finishedAt?: string;
  error?: string;
  result?: unknown;
}

// -------- Flow-level STRIDE --------
export interface FlowStrideFinding {
  flowId: string;
  flowLabel: string;
  fromComponentName: string;
  toComponentName: string;
  category: StrideFinding['category'];
  description: string;
  likelihood: 'Low' | 'Medium' | 'High';
  impact: 'Low' | 'Medium' | 'High';
  inherentRisk: 'Low' | 'Medium' | 'High' | 'Critical';
  mitigations: string[];
  residualRisk: 'Low' | 'Medium' | 'High' | 'Critical';
}

// -------- MITRE ATT&CK and CAPEC --------
export interface MitreMapping {
  strideFindingIndex: number;   // index into ArbPackage.threatModel
  attackTacticId: string;       // e.g. TA0001
  attackTacticName: string;
  attackTechniqueId: string;    // e.g. T1078
  attackTechniqueName: string;
  rationale: string;
}

export interface CapecReference {
  capecId: string;              // e.g. CAPEC-115
  name: string;
  appliesToComponentIds: string[];
  strideCategories: StrideFinding['category'][];
  description: string;
}

// -------- LINDDUN (privacy threat model) --------
export type LinddunCategory =
  | 'Linkability'
  | 'Identifiability'
  | 'Non-repudiation'
  | 'Detectability'
  | 'Disclosure of information'
  | 'Unawareness'
  | 'Non-compliance';

export interface LinddunFinding {
  componentId: string;
  componentName: string;
  category: LinddunCategory;
  description: string;
  affectedData: string[];        // PII / PHI / PCI / etc.
  recommendation: string;
  mitigationControls: string[];  // NIST control IDs
  severity: 'Low' | 'Medium' | 'High';
}

// -------- DPIA (GDPR Article 35) --------
export interface Dpia {
  lawfulBases: string[];         // Art. 6 selections
  specialCategoryBases: string[]; // Art. 9 selections (if PHI/PII)
  dataSubjectCategories: string[];
  processingActivities: { activity: string; purpose: string; lawfulBasis: string }[];
  dataTransfers: { destination: string; mechanism: string; safeguards: string }[];
  risks: { description: string; likelihood: string; severity: string; mitigation: string }[];
  rightsHandling: { right: string; mechanism: string }[];
  consultations: { stakeholder: string; concern: string }[];
  conclusion: 'Acceptable' | 'Acceptable with mitigations' | 'High residual risk — consult DPA';
}

// -------- Cost estimate --------
export interface CostEstimate {
  currency: 'USD';
  monthlyLowUsd: number;
  monthlyHighUsd: number;
  tier: 'XS' | 'S' | 'M' | 'L' | 'XL';
  drivers: { item: string; lowUsd: number; highUsd: number; rationale: string }[];
  notes: string[];
}

// -------- OSCAL SSP (NIST 800-53 control implementation) --------
// We emit a structural subset of OSCAL v1.1.2 sufficient for FedRAMP
// ingestion; not every optional field is populated.
export interface OscalSsp {
  uuid: string;
  metadata: {
    title: string;
    'last-modified': string;
    version: string;
    'oscal-version': string;
    parties: { uuid: string; type: 'organization' | 'person'; name: string }[];
    'responsible-parties'?: { 'role-id': string; 'party-uuids': string[] }[];
  };
  'import-profile': { href: string };
  'system-characteristics': {
    'system-name': string;
    description: string;
    'security-sensitivity-level': string;
    'system-information': {
      'information-types': {
        uuid: string;
        title: string;
        categorizations: { system: string; 'information-type-ids': string[] }[];
        'confidentiality-impact': { base: string };
        'integrity-impact': { base: string };
        'availability-impact': { base: string };
      }[];
    };
    'security-impact-level': {
      'security-objective-confidentiality': string;
      'security-objective-integrity': string;
      'security-objective-availability': string;
    };
    status: { state: 'operational' | 'under-development' | 'under-major-modification' };
    'authorization-boundary': { description: string };
  };
  'system-implementation': {
    users: { uuid: string; title: string; 'role-ids': string[] }[];
    components: {
      uuid: string;
      type: string;
      title: string;
      description: string;
      status: { state: 'operational' | 'under-development' };
    }[];
  };
  'control-implementation': {
    description: string;
    'implemented-requirements': {
      uuid: string;
      'control-id': string;
      statements: { 'statement-id': string; uuid: string; 'by-components': { 'component-uuid': string; uuid: string; description: string }[] }[];
      'responsible-roles'?: { 'role-id': string }[];
      remarks?: string;
    }[];
  };
}

// -------- IaC reconciliation --------
export interface IacReconciliationReport {
  format: 'terraform-plan' | 'cloudformation' | 'cdk-synth' | 'unknown';
  observedResources: { type: string; name: string; layer: string; encryptionAtRest?: boolean; encryptionInTransit?: boolean }[];
  expectedComponents: { id: string; name: string; layer: string }[];
  matched: { expectedId: string; observedType: string; observedName: string }[];
  missing: { expectedId: string; expectedName: string; layer: string }[];      // described but not in IaC
  unexpected: { observedType: string; observedName: string }[];                // in IaC but not described
  encryptionMismatches: { component: string; expected: string; observed: string }[];
  summary: string;
}

// -------- Diff between regenerations --------
export interface PackageDiff {
  fromVersion: number;
  toVersion: number;
  fromGeneratedAt: string;
  toGeneratedAt: string;
  postureChange: { from: ExecutiveSummary['riskPosture']; to: ExecutiveSummary['riskPosture'] } | null;
  goNoGoChange: { from: ExecutiveSummary['goNoGoAdvice']; to: ExecutiveSummary['goNoGoAdvice'] } | null;
  categoryChange: { from: ImpactLevel; to: ImpactLevel } | null;
  recoveryTierChange: { from: RecoveryAssessment['availabilityTier']; to: RecoveryAssessment['availabilityTier'] } | null;
  controlsAdded: string[];
  controlsRemoved: string[];
  componentsAdded: string[];
  componentsRemoved: string[];
  threatCountDelta: { inherent: number; residual: number };
  complianceCoverageDelta: { full: number; partial: number; gap: number };
  highlights: string[];
}

// -------- Audit log & users --------
export interface AuditLogEntry {
  id: string;
  ts: string;
  actor: string;                // user id or "anonymous"
  action: string;               // verb (e.g. "assessment.create")
  target: string;               // resource id
  details?: Record<string, unknown>;
  ip?: string;
}

export type UserRole = 'admin' | 'architect' | 'analyst' | 'product-owner' | 'approver-security' | 'approver-risk' | 'approver-architecture' | 'approver-compliance';

export interface User {
  id: string;
  username: string;
  displayName: string;
  passwordHash: string;         // bcrypt
  roles: UserRole[];
  createdAt: string;
  team?: string;
  disabled?: boolean;           // when true, login is refused (M62)
  disabledReason?: string;
  disabledAt?: string;
  // Profile (all optional — pre-existing users have these blank)
  email?: string;
  firstName?: string;
  lastName?: string;
  department?: string;
  jobTitle?: string;
  phone?: string;
  timezone?: string;
  notes?: string;
  // Lifecycle / security
  updatedAt?: string;
  lastLoginAt?: string;
  forcePasswordChange?: boolean;  // user must set a new password before any other action
  deletedAt?: string;             // soft delete tombstone — hidden from listings but row preserved for audit
}

export interface SessionInfo {
  userId: string;
  username: string;
  displayName: string;
  roles: UserRole[];
}

export interface ValidationReport {
  passed: boolean;
  issues: { severity: 'info' | 'warn' | 'error'; field: string; message: string }[];
}
