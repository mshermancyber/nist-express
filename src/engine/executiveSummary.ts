// Executive summary for the ARB package. Distils the artifact set
// into a one-page narrative the system owner / risk officer can sign.

import {
  Assessment, Categorization, ResidualRisk, RecoveryAssessment, ComplianceMapping, ExecutiveSummary, WellArchitectedScore
} from '../types/assessment';

export function buildExecutiveSummary(
  a: Assessment,
  cat: Categorization,
  risks: ResidualRisk[],
  recovery: RecoveryAssessment,
  mappings: ComplianceMapping[],
  pillars: WellArchitectedScore[]
): ExecutiveSummary {
  const criticals = risks.filter(r => r.residualRisk === 'Critical').length;
  const highs = risks.filter(r => r.residualRisk === 'High').length;
  const gaps = mappings.filter(m => m.coverage === 'Gap').length;
  const secScore = pillars.find(p => p.pillar === 'Security')?.score ?? 0;
  const relScore = pillars.find(p => p.pillar === 'Reliability')?.score ?? 0;

  let posture: ExecutiveSummary['riskPosture'] = 'Low';
  if (criticals > 0) posture = 'High';
  else if (highs >= 3 || gaps >= 3) posture = 'Elevated';
  else if (highs > 0 || gaps > 0) posture = 'Moderate';

  let go: ExecutiveSummary['goNoGoAdvice'] = 'Proceed';
  const conditions: string[] = [];
  if (criticals > 0) {
    go = 'Do Not Proceed';
    conditions.push(`Resolve ${criticals} Critical residual risk(s) before authorisation.`);
  } else if (highs > 0 || gaps > 0 || recovery.gaps.length > 0) {
    go = 'Proceed With Conditions';
    if (highs > 0) conditions.push(`Track ${highs} High residual risk(s) to closure within ARB-defined window.`);
    if (gaps > 0) conditions.push(`Close ${gaps} compliance coverage gap(s).`);
    if (recovery.gaps.length > 0) conditions.push(`Close recovery gap(s): ${recovery.gaps.join('; ')}`);
  }

  const topRisks = risks
    .filter(r => r.residualRisk === 'Critical' || r.residualRisk === 'High')
    .slice(0, 5)
    .map(r => r.description);

  return {
    oneLiner: `${a.business.applicationName}${a.business.businessArea ? ' (' + a.business.businessArea + ')' : ''} is a ${cat.overallCategorization}-impact ${a.hosting.model} workload serving ${a.business.userTypes.join(', ')} with a ${posture.toLowerCase()} residual risk posture.`,
    businessContext: a.business.businessProblem,
    riskPosture: posture,
    topRisks,
    keyRecommendations: [
      `Maintain ${recovery.availabilityTier} availability posture; ${recovery.failoverApproach.toLowerCase()}`,
      secScore < 70 ? 'Invest in Security pillar gaps before authorisation.' : 'Continue to operate the security baseline.',
      relScore < 70 ? 'Invest in Reliability pillar gaps before authorisation.' : 'Continue to operate the reliability baseline.',
      'Establish a quarterly control-effectiveness review.'
    ],
    goNoGoAdvice: go,
    conditions
  };
}
