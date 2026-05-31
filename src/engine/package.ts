// Assembles the full ARB package from an Assessment. AI augmentation
// is best-effort; the deterministic engine outputs are always present.

import crypto from 'crypto';
import {
  Assessment, ArbPackage
} from '../types/assessment';
import { categorize } from './categorization';
import { buildArchitecture } from './architecture';
import { renderArchitectureMermaid, renderDataFlowMermaid, renderSecurityOverlayMermaid } from './diagrams';
import { buildThreatModel, buildFlowThreatModel } from './threatModel';
import { buildOperationalThreats } from './operationalThreats';
import { buildSsp } from './ssp';
import { buildAuditableEvents } from './auditEvents';
import { buildRecovery } from './recovery';
import { buildComplianceMappings } from './compliance';
import { buildWellArchitected } from './wellArchitected';
import { buildEvidenceRequests } from './evidence';
import { buildResidualRisk } from './residualRisk';
import { buildAssumptions } from './assumptions';
import { buildExecutiveSummary } from './executiveSummary';
import { validate } from './validation';
import { buildDataClassification } from './dataClassification';
import { aiStatus, enrichClarificationQuestions, enrichExecutiveNarrative } from './ai';
import { buildMitreMappings, buildCapecReferences } from './mitre';
import { buildLinddun } from './linddun';
import { buildDpia } from './dpia';
import { estimateCost } from './cost';
import { buildOscalSsp } from './oscal';
import { diffPackages } from './diff';
import { reconcileIac } from './iac';
import { analyzeSbom } from './sbom';
import { reconcileCloud } from './cloudReconcile';
import { quantifyFair } from './fair';
import { buildAttackTrees } from './attackTree';
import { buildKillChainMappings } from './killChain';
import { buildFedrampPackage } from './fedrampPackage';

// Deterministic hash of the package body (excluding fields that change
// on every regeneration like generatedAt and packageVersion/diff).
function hashPackage(pkg: Omit<ArbPackage, 'packageHash' | 'packageVersion' | 'generatedAt' | 'diff'>): string {
  const ordered = JSON.stringify(pkg, Object.keys(pkg).sort());
  return crypto.createHash('sha256').update(ordered).digest('hex');
}

export async function generatePackage(
  a: Assessment,
  options: { previousPackage?: ArbPackage | null; iacContent?: string | null; sbomContent?: string | null; cloudSnapshot?: string | null } = {}
): Promise<ArbPackage> {
  const validation = validate(a);

  const categorization = categorize(a);
  const dataClassification = buildDataClassification(a, categorization);
  const arch = buildArchitecture(a, categorization);
  const archDiagram = renderArchitectureMermaid(arch);
  const overlayDiagram = renderSecurityOverlayMermaid(arch);
  const dfdDiagram = renderDataFlowMermaid(arch);
  const threats = buildThreatModel(a, arch, categorization);
  const flowThreats = buildFlowThreatModel(arch, categorization);
  const ops = buildOperationalThreats(a, arch, categorization);
  const ssp = buildSsp(a, categorization, arch);
  const audits = buildAuditableEvents(a, categorization, arch);
  const recovery = buildRecovery(a, categorization);
  const mappings = buildComplianceMappings(a, ssp);
  const pillars = buildWellArchitected(a, arch, ssp, recovery, threats);
  const evidence = buildEvidenceRequests(ssp);
  const residualRisks = buildResidualRisk(threats, ops, mappings, recovery);
  const assumptions = buildAssumptions(a, categorization);
  const execSummary = buildExecutiveSummary(a, categorization, residualRisks, recovery, mappings, pillars);
  const mitreMappings = buildMitreMappings(threats, arch);
  const capecReferences = buildCapecReferences(threats, arch);
  const linddunFindings = buildLinddun(a, arch);
  const dpia = buildDpia(a, categorization);
  const costEstimate = estimateCost(a, arch, recovery);
  const iacReconciliation = options.iacContent ? reconcileIac(options.iacContent, arch) : null;
  const sbomAnalysis = options.sbomContent ? analyzeSbom(options.sbomContent, arch) : null;
  const cloudReconciliation = options.cloudSnapshot ? reconcileCloud(options.cloudSnapshot, arch) : null;
  const fair = quantifyFair(a, residualRisks);
  const attackTrees = buildAttackTrees(threats, residualRisks);
  const killChainMappings = buildKillChainMappings(threats);

  const nextVersion = (options.previousPackage?.packageVersion ?? 0) + 1;

  // Build the body once without the volatile fields, then hash and assemble.
  const body = {
    assessmentId: a.id,
    categorization,
    dataClassification,
    architecture: arch,
    architectureDiagramMermaid: archDiagram,
    securityOverlayDiagramMermaid: overlayDiagram,
    dataFlowDiagramMermaid: dfdDiagram,
    threatModel: threats,
    flowThreatModel: flowThreats,
    operationalThreatModel: ops,
    ssp,
    auditableEvents: audits,
    recovery,
    residualRisks,
    assumptions,
    complianceMappings: mappings,
    wellArchitected: pillars,
    evidenceRequests: evidence,
    executiveSummary: execSummary,
    clarifications: validation.clarifications,
    validationReport: validation.report,
    mitreMappings,
    capecReferences,
    linddunFindings,
    dpia,
    costEstimate,
    iacReconciliation,
    sbomAnalysis,
    cloudReconciliation,
    fair,
    attackTrees,
    killChainMappings,
    fedramp: null as unknown as ArbPackage['fedramp'],
    // OSCAL is computed last because it references the package version.
    oscalSsp: null as unknown as ArbPackage['oscalSsp']
  };

  const generatedAt = new Date().toISOString();
  const packageHash = hashPackage({ ...body });

  const pkg: ArbPackage = {
    ...body,
    generatedAt,
    packageVersion: nextVersion,
    packageHash,
    diff: null,
    oscalSsp: body.oscalSsp
  };

  // OSCAL needs the assembled package (it references the version).
  pkg.oscalSsp = buildOscalSsp(a, pkg);
  // FedRAMP package is computed last because it consumes the assembled ArbPackage.
  pkg.fedramp = buildFedrampPackage(a, pkg);

  // Diff against the previous version if any.
  if (options.previousPackage) {
    pkg.diff = diffPackages(options.previousPackage, pkg);
  }

  // ---- AI augmentation (best-effort) ----
  if (aiStatus().configured) {
    const [narrative, extraQuestions] = await Promise.all([
      enrichExecutiveNarrative(a, pkg),
      enrichClarificationQuestions(a, validation.clarifications.map(c => c.question))
    ]);
    if (narrative) pkg.executiveSummary.businessContext = narrative;
    for (const q of extraQuestions) {
      pkg.clarifications.push({
        field: 'ai-suggested',
        question: q,
        reason: 'Generated by AI augmentation; verify before treating as authoritative.'
      });
    }
  }

  return pkg;
}
