// FIPS 199 + NIST 800-60 categorization engine.
// Maps questionnaire inputs to information types, then takes the
// high-water mark across all selected types to produce the overall
// security category. Rationale is preserved so downstream artifacts
// can cite *why* a category was chosen.

import {
  Assessment,
  Categorization,
  InformationType,
  ImpactLevel
} from '../types/assessment';
import { INFORMATION_TYPES, impactRank, maxImpact } from '../data/informationTypes';

function rationaleForType(itype: typeof INFORMATION_TYPES[number], a: Assessment): string {
  const reasons: string[] = [];
  if (itype.triggers.dataCategories?.some(d => a.data.dataCategories.includes(d))) {
    const overlap = itype.triggers.dataCategories.filter(d => a.data.dataCategories.includes(d));
    reasons.push(`Data category selected: ${overlap.join(', ')}`);
  }
  if (itype.triggers.sensitiveTags?.some(t => a.data.sensitiveDataTags.includes(t))) {
    const overlap = itype.triggers.sensitiveTags.filter(t => a.data.sensitiveDataTags.includes(t));
    reasons.push(`Sensitive data present: ${overlap.join(', ')}`);
  }
  if (itype.triggers.userTypes?.some(u => a.business.userTypes.includes(u))) {
    const overlap = itype.triggers.userTypes.filter(u => a.business.userTypes.includes(u));
    reasons.push(`User population includes: ${overlap.join(', ')}`);
  }
  if (itype.triggers.requiresConfidential && a.data.confidentialToCompany) {
    reasons.push('Information must remain confidential to the company');
  }
  return reasons.join(' — ') || 'Always-applicable cross-cutting type';
}

function matches(itype: typeof INFORMATION_TYPES[number], a: Assessment): boolean {
  const t = itype.triggers;
  // A type matches if any of its declared triggers fires; if no triggers are
  // declared, it is treated as always-applicable.
  const hasAnyTrigger =
    !!t.dataCategories?.length ||
    !!t.sensitiveTags?.length ||
    !!t.userTypes?.length ||
    !!t.requiresConfidential;
  if (!hasAnyTrigger) return true;

  if (t.dataCategories?.some(d => a.data.dataCategories.includes(d))) return true;
  if (t.sensitiveTags?.some(s => a.data.sensitiveDataTags.includes(s))) return true;
  if (t.userTypes?.some(u => a.business.userTypes.includes(u))) return true;
  if (t.requiresConfidential && a.data.confidentialToCompany) return true;
  return false;
}

// Worst-case CIA descriptions can push the *minimum* category we
// will accept above whatever the information types alone would imply.
// Severe language (legal action, regulatory fines, large financial
// loss) bumps the minimum to High; moderate language to Moderate.
function impactFromWorstCase(text: string): ImpactLevel {
  const t = text.toLowerCase();
  // High-impact language must name a concrete consequence; bare
  // "regulator(y)" is too ambiguous (e.g. "no regulatory impact").
  const highPatterns = [
    /regulatory (fine|action|notification|sanction|exposure|breach|investigation|penalt)/,
    /\bfines\b/,
    /\blawsuit\b/,
    /\blegal action\b/,
    /class[- ]?action/,
    /breach notification/,
    /\bcriminal (exposure|liabilit|charge|penalt)/,
    /material (financial|loss)/,
    /\bhipaa\b/,
    /\bpci\b/,
    /\bsafety (event|risk|harm)/
  ];
  if (highPatterns.some(re => re.test(t))) return 'High';
  if (/competitive|financial loss|disadvantage|reputation|customer trust|outage|trust loss/.test(t)) return 'Moderate';
  if (/minor|embarrassment|inconvenien|no (impact|regulatory)/.test(t)) return 'Low';
  return 'Moderate';
}

export function categorize(a: Assessment): Categorization {
  const matched: InformationType[] = [];
  for (const itype of INFORMATION_TYPES) {
    if (!matches(itype, a)) continue;
    matched.push({
      code: itype.code,
      name: itype.name,
      confidentiality: itype.confidentiality,
      integrity: itype.integrity,
      availability: itype.availability,
      basisInAssessment: rationaleForType(itype, a)
    });
  }

  // High-water mark across all matched information types
  let c: ImpactLevel = 'Low';
  let i: ImpactLevel = 'Low';
  let av: ImpactLevel = 'Low';
  for (const m of matched) {
    c = maxImpact(c, m.confidentiality);
    i = maxImpact(i, m.integrity);
    av = maxImpact(av, m.availability);
  }

  // Worst-case narratives may further raise the floor
  const wcC = impactFromWorstCase(a.impact.confidentialityWorstCase);
  const wcI = impactFromWorstCase(a.impact.integrityWorstCase);
  const wcA = impactFromWorstCase(a.impact.availabilityWorstCase);
  c = maxImpact(c, wcC);
  i = maxImpact(i, wcI);
  av = maxImpact(av, wcA);

  // RTO tightens availability floor
  if (a.recovery.rto === '15 Minutes' || a.recovery.rto === '1 Hour') av = maxImpact(av, 'High');
  else if (a.recovery.rto === '4 Hours') av = maxImpact(av, 'Moderate');

  // Compliance frameworks raise floors
  const frameworks = a.compliance.frameworks;
  if (frameworks.includes('PCI DSS') || frameworks.includes('HIPAA') || frameworks.includes('FedRAMP')) {
    c = maxImpact(c, 'Moderate');
    i = maxImpact(i, 'Moderate');
  }

  const overall: ImpactLevel = [c, i, av].reduce(maxImpact, 'Low');

  const rationale: string[] = [
    `${matched.length} NIST 800-60 information types matched the inputs.`,
    `Confidentiality high-water mark: ${c} (worst-case narrative read as ${wcC}).`,
    `Integrity high-water mark: ${i} (worst-case narrative read as ${wcI}).`,
    `Availability high-water mark: ${av} (RTO=${a.recovery.rto}; narrative read as ${wcA}).`,
    `Overall FIPS 199 categorization is ${overall} via high-water-mark across CIA.`
  ];
  if (frameworks.length) {
    rationale.push(`Compliance scope (${frameworks.join(', ')}) influenced the floor.`);
  }

  return {
    confidentialityImpact: c,
    integrityImpact: i,
    availabilityImpact: av,
    overallCategorization: overall,
    informationTypes: matched,
    rationale
  };
}

export function baselineFromCategory(level: ImpactLevel): ImpactLevel[] {
  // Controls applicable for any baseline up to the system's level.
  if (level === 'High') return ['Low', 'Moderate', 'High'];
  if (level === 'Moderate') return ['Low', 'Moderate'];
  return ['Low'];
}

export function rankCategory(level: ImpactLevel): number {
  return impactRank(level);
}
