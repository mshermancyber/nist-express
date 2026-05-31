// Builds the small, AI-shaped "digest" that gets shipped to the
// Python handler service. The point is that the network payload —
// and any subsequent LLM prompt — stays under a few KB even for
// HIGH-impact packages. The TypeScript side does the heavy lifting
// of summarising; Python does the deterministic-first routing.

import { Assessment, ArbPackage } from '../types/assessment';

export interface PackageDigest {
  package_hash: string;
  app_name: string;
  one_liner: string;
  category: string;
  confidentiality: string;
  integrity: string;
  availability: string;
  posture: string;
  advice: string;
  hosting: string;
  rto: string;
  rpo: string;
  availability_tier: string;
  failover: string;
  multi_region: boolean;
  cost_tier: string;
  cost_low: number;
  cost_high: number;
  cost_top_drivers: string[];
  ssp_count: number;
  ssp_families: string[];
  component_count: number;
  layers: string[];
  integration_count: number;
  sensitive_tags: string[];
  confidential: boolean;
  frameworks: string[];
  ai_related_frameworks: string[];
  compliance_full: number;
  compliance_partial: number;
  compliance_gap: number;
  top_risks: string[];
  diff_highlights: string[];
  linddun_findings: number;
  dpia_emitted: boolean;
  dpia_conclusion: string;
  sbom_components: number;
  sbom_vulns: number;
  sbom_kev: number;
  fair_p50: number;
  fair_p90: number;
  fair_mean: number;
  mitre_count: number;
  capec_count: number;
  kill_chain_stages: string[];
  fedramp_baseline: string;
  fedramp_baseline_count: number;
  fedramp_poam_count: number;
  approval_status: string;
}

export function buildDigest(a: Assessment, p: ArbPackage): PackageDigest {
  const layers = Array.from(new Set(p.architecture.components.map(c => c.layer)));
  const topRisks = p.residualRisks
    .filter(r => r.residualRisk === 'Critical' || r.residualRisk === 'High')
    .slice(0, 4)
    .map(r => r.description.slice(0, 160));
  const stages = Array.from(new Set(p.killChainMappings.map(k => k.stage)));
  const aiFrameworks = a.compliance.frameworks.filter(f => f === 'EU AI Act' || f === 'NIST AI RMF');
  const approval = a.approvalRequest;
  return {
    package_hash: p.packageHash,
    app_name: a.business.applicationName,
    one_liner: p.executiveSummary.oneLiner,
    category: p.categorization.overallCategorization,
    confidentiality: p.categorization.confidentialityImpact,
    integrity: p.categorization.integrityImpact,
    availability: p.categorization.availabilityImpact,
    posture: p.executiveSummary.riskPosture,
    advice: p.executiveSummary.goNoGoAdvice,
    hosting: a.hosting.model,
    rto: a.recovery.rto,
    rpo: a.recovery.rpo,
    availability_tier: p.recovery.availabilityTier,
    failover: p.recovery.failoverApproach,
    multi_region: !!p.recovery.multiRegion,
    cost_tier: p.costEstimate.tier,
    cost_low: p.costEstimate.monthlyLowUsd,
    cost_high: p.costEstimate.monthlyHighUsd,
    cost_top_drivers: p.costEstimate.drivers.slice(0, 3).map(d => d.item),
    ssp_count: p.ssp.length,
    ssp_families: Array.from(new Set(p.ssp.map(c => c.family))),
    component_count: p.architecture.components.length,
    layers,
    integration_count: a.integrations.length,
    sensitive_tags: a.data.sensitiveDataTags,
    confidential: a.data.confidentialToCompany,
    frameworks: a.compliance.frameworks,
    ai_related_frameworks: aiFrameworks,
    compliance_full: p.complianceMappings.filter(m => m.coverage === 'Full').length,
    compliance_partial: p.complianceMappings.filter(m => m.coverage === 'Partial').length,
    compliance_gap: p.complianceMappings.filter(m => m.coverage === 'Gap').length,
    top_risks: topRisks,
    diff_highlights: p.diff?.highlights ?? [],
    linddun_findings: p.linddunFindings.length,
    dpia_emitted: !!p.dpia,
    dpia_conclusion: p.dpia?.conclusion ?? 'not emitted',
    sbom_components: p.sbomAnalysis?.componentCount ?? 0,
    sbom_vulns: p.sbomAnalysis?.vulnerabilities.length ?? 0,
    sbom_kev: p.sbomAnalysis?.kevHits.length ?? 0,
    fair_p50: p.fair.portfolio.aleP50,
    fair_p90: p.fair.portfolio.aleP90,
    fair_mean: p.fair.portfolio.aleMean,
    mitre_count: p.mitreMappings.length,
    capec_count: p.capecReferences.length,
    kill_chain_stages: stages,
    fedramp_baseline: p.fedramp?.baseline ?? 'not in scope',
    fedramp_baseline_count: p.fedramp?.baselineControlCount ?? 0,
    fedramp_poam_count: p.fedramp?.poam.length ?? 0,
    approval_status: approval ? `${approval.status} (${approval.approvals.length}/${approval.requiredRoles.length} signatures)` : 'No approval request open.'
  };
}
