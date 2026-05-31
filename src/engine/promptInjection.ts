// Heuristic detector for prompt-injection patterns in user-supplied
// free-text fields. Used at two points:
//   1. Validation pass — if the assessment contains injection-shaped
//      text, the package emits a clarification warning so a human
//      reviewer can look at it before approval.
//   2. AI handler — every user field is wrapped in unambiguous
//      delimiters AND the system prompt explicitly instructs the
//      model to refuse instructions that appear inside the data.

const PATTERNS: { re: RegExp; label: string }[] = [
  { re: /\bignore (all |previous |prior |above )?instructions?\b/i, label: 'ignore-instructions' },
  { re: /\bdisregard (all |previous |prior )?(instructions?|rules?|system)\b/i, label: 'disregard' },
  { re: /\boverride (system|previous|prior) (prompt|instructions?)\b/i, label: 'override-prompt' },
  { re: /\bact as (?:a|an) (?:different|new|other)\b/i, label: 'role-switch' },
  { re: /\byou are now (?:a |an )?[a-z]+/i, label: 'role-injection' },
  { re: /\b(?:respond|reply|answer) (?:only )?with\b.*?(?:approved|denied|low|high|critical)/i, label: 'forced-verdict' },
  { re: /\bsystem prompt(?:: |:)/i, label: 'system-prompt-leak' },
  { re: /(?:```|<\|)\s*(?:system|developer|assistant)\s*[:>|]/i, label: 'role-marker' },
  { re: /\bprint (?:the )?(?:secret|password|api[_ ]?key|token)\b/i, label: 'secret-exfil' },
  { re: /\bjailbreak\b/i, label: 'jailbreak' },
  { re: /\bdeveloper mode\b/i, label: 'developer-mode' },
  { re: /\bsay (?:only )?["']?(approved|denied|categori[sz]ation is)/i, label: 'forced-output' },
  { re: /\$\{[^}]+\}|\{\{[^}]+\}\}/, label: 'template-syntax' },
  // Detect attempts to add instructions in worst-case narratives
  { re: /(?:please )?(?:respond|return|output) (?:in|as) (?:json|xml|html)/i, label: 'format-override' }
];

export interface InjectionFinding {
  field: string;
  label: string;
  excerpt: string;
}

export function scanForInjection(field: string, text: string): InjectionFinding[] {
  if (!text) return [];
  const findings: InjectionFinding[] = [];
  for (const p of PATTERNS) {
    const m = p.re.exec(text);
    if (m) {
      const start = Math.max(0, m.index - 20);
      const end = Math.min(text.length, m.index + m[0].length + 40);
      findings.push({ field, label: p.label, excerpt: text.slice(start, end).replace(/\s+/g, ' ').trim() });
    }
  }
  return findings;
}

export function scanAssessmentForInjection(a: {
  business: { businessProblem?: string; userInteractionDescription?: string; applicationName?: string; businessArea?: string };
  impact: { confidentialityWorstCase?: string; integrityWorstCase?: string; availabilityWorstCase?: string };
  population?: { expectedGrowth?: string };
  integrations?: { source?: string; destination?: string; description?: string }[];
}): InjectionFinding[] {
  const out: InjectionFinding[] = [];
  out.push(...scanForInjection('business.applicationName', a.business?.applicationName || ''));
  out.push(...scanForInjection('business.businessArea', a.business?.businessArea || ''));
  out.push(...scanForInjection('business.businessProblem', a.business?.businessProblem || ''));
  out.push(...scanForInjection('business.userInteractionDescription', a.business?.userInteractionDescription || ''));
  out.push(...scanForInjection('impact.confidentialityWorstCase', a.impact?.confidentialityWorstCase || ''));
  out.push(...scanForInjection('impact.integrityWorstCase', a.impact?.integrityWorstCase || ''));
  out.push(...scanForInjection('impact.availabilityWorstCase', a.impact?.availabilityWorstCase || ''));
  out.push(...scanForInjection('population.expectedGrowth', a.population?.expectedGrowth || ''));
  for (let i = 0; i < (a.integrations || []).length; i++) {
    const ig = a.integrations![i] ?? {};
    out.push(...scanForInjection(`integrations[${i}].source`, ig.source || ''));
    out.push(...scanForInjection(`integrations[${i}].destination`, ig.destination || ''));
    out.push(...scanForInjection(`integrations[${i}].description`, ig.description || ''));
  }
  return out;
}

// Sentinel delimiters wrapped around user data in AI prompts. The
// system prompt tells the model to ignore any instructions inside.
// Random-prefixed so a malicious user can't guess and emit the close
// delimiter inside their own field to break out.
import crypto from 'crypto';
export function delimit(text: string): { open: string; close: string; wrapped: string } {
  const tag = crypto.randomBytes(8).toString('hex');
  const open  = `<<<USER_DATA_${tag}>>>`;
  const close = `<<<END_USER_DATA_${tag}>>>`;
  // Strip anything that already looks like our delimiter from user input.
  const clean = String(text || '').replace(/<<<(?:END_)?USER_DATA_[0-9a-f]{16}>>>/g, '');
  return { open, close, wrapped: `${open}\n${clean}\n${close}` };
}

// Reference-grounding guard: verify every control-id-shaped token
// (e.g. AC-2, SC-7) the model emits ACTUALLY exists in the package's
// SSP, and every component name it mentions exists in the
// architecture. Hallucinated identifiers are the most-common failure
// mode and are catchable mechanically.
export interface GroundingContext {
  controlIds: Set<string>;       // every package.ssp[].id
  componentNames: Set<string>;   // every package.architecture.components[].name
  componentTokens: Set<string>;  // word tokens drawn from component names (lowercase)
}

export function buildGroundingContext(pkg: { ssp: { id: string }[]; architecture: { components: { name: string }[] } }): GroundingContext {
  const controlIds = new Set<string>(pkg.ssp.map(c => c.id));
  const componentNames = new Set<string>(pkg.architecture.components.map(c => c.name));
  const componentTokens = new Set<string>();
  for (const c of pkg.architecture.components) {
    for (const tok of c.name.toLowerCase().split(/[^a-z0-9]+/)) {
      if (tok.length >= 4) componentTokens.add(tok);
    }
  }
  return { controlIds, componentNames, componentTokens };
}

export function validateAiOutputGrounding(text: string, ctx: GroundingContext): { ok: boolean; hallucinated: string[]; reason?: string } {
  const hallucinated: string[] = [];

  // 1) Every NIST 800-53 / 800-171-shaped identifier must exist
  const idPattern = /\b([A-Z]{2}|3)-\d+(?:\(\d+\))?\b/g;
  let m: RegExpExecArray | null;
  const seenIds = new Set<string>();
  while ((m = idPattern.exec(text)) !== null) {
    const raw = m[0];
    // Strip any enhancement suffix to compare against base ids
    const base = raw.replace(/\(\d+\)$/, '');
    if (seenIds.has(base)) continue;
    seenIds.add(base);
    // Accept 800-171 ids (3.x.y.z) only when they look like the catalog format
    if (base.startsWith('3-')) continue;
    if (!ctx.controlIds.has(base)) hallucinated.push(`unknown control ${raw}`);
  }

  if (hallucinated.length > 0) {
    return { ok: false, hallucinated, reason: `model referenced ${hallucinated.length} unknown identifier(s): ${hallucinated.slice(0, 3).join(', ')}` };
  }
  return { ok: true, hallucinated: [] };
}

// Numeric fact validator. Looks for "N controls" / "N components" /
// "N residual risks" / "N findings" patterns and verifies the
// reported count matches the package.
export function validateAiOutputNumerics(text: string, facts: { ssp: number; components: number; threats: number; residuals: number }): { ok: boolean; mismatches: string[] } {
  const mismatches: string[] = [];
  const check = (label: string, expected: number, ...keywords: string[]) => {
    for (const kw of keywords) {
      const re = new RegExp(`\\b(\\d+)\\s+${kw.replace(/\s+/g, '\\s+')}\\b`, 'gi');
      let m: RegExpExecArray | null;
      while ((m = re.exec(text)) !== null) {
        const claimed = Number(m[1]);
        if (claimed !== expected) mismatches.push(`${label}: model said ${claimed}, actual ${expected}`);
      }
    }
  };
  check('SSP controls', facts.ssp, 'controls', 'NIST controls', 'SSP controls');
  check('components', facts.components, 'components', 'architecture components');
  check('STRIDE findings', facts.threats, 'STRIDE findings', 'threats', 'threat findings');
  check('residual risks', facts.residuals, 'residual risks', 'residuals');
  return { ok: mismatches.length === 0, mismatches };
}

// Output guard: refuse model responses that claim authority over the
// engine's deterministic outputs.
export function validateAiOutput(s: string): { ok: boolean; reason?: string } {
  const t = (s || '').toLowerCase();
  const forbidden: { re: RegExp; reason: string }[] = [
    { re: /\bcategori[sz]ation (?:is|should be) (low|moderate|high)\b/i, reason: 'AI tried to change FIPS 199 categorization' },
    { re: /\b(?:i (?:hereby )?)?approve(?:d)? (?:this|the) (?:system|package|arb)\b/i, reason: 'AI emitted approval language' },
    { re: /\b(?:i (?:hereby )?)?(?:deny|reject)(?:ed)? (?:this|the) (?:system|package|arb)\b/i, reason: 'AI emitted denial language' },
    { re: /\bsignature[s]? (?:are |is |have been )?(?:complete|valid|authorised)/i, reason: 'AI tried to assert signatures' },
    { re: /\bauthorisation to operate\b|\bATO is granted\b/i, reason: 'AI tried to assert ATO' }
  ];
  for (const f of forbidden) {
    if (f.re.test(t)) return { ok: false, reason: f.reason };
  }
  return { ok: true };
}
