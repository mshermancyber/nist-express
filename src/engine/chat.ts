// "Chat with the package" — given an ArbPackage and a question,
// answers from the package contents. When AI is configured we hand
// the package summary + question to the LLM with strict grounding
// instructions; otherwise we fall back to a deterministic FAQ that
// recognises common questions ("which controls", "what changed",
// "cost", "compliance gaps", "residual risks").

import { aiStatus, chat, hardenedSystemPrompt, dispatchToPython } from './ai';
import { ArbPackage } from '../types/assessment';
import { buildGroundingContext, validateAiOutput, validateAiOutputGrounding, validateAiOutputNumerics, delimit } from './promptInjection';

interface FaqMatcher {
  match: RegExp;
  answer: (p: ArbPackage) => string;
}

const FAQ: FaqMatcher[] = [
  {
    match: /which controls|what controls|ssp|nist 800-53/i,
    answer: p => `${p.ssp.length} controls in the SSP, spanning families ${Array.from(new Set(p.ssp.map(c => c.family))).join(', ')}. Sample: ${p.ssp.slice(0, 6).map(c => c.id).join(', ')}.`
  },
  {
    match: /cost|budget|how much/i,
    answer: p => `Tier ${p.costEstimate.tier} — $${p.costEstimate.monthlyLowUsd.toLocaleString()} to $${p.costEstimate.monthlyHighUsd.toLocaleString()} USD/month. Top drivers: ${p.costEstimate.drivers.slice(0, 3).map(d => d.item).join(', ')}.`
  },
  {
    match: /compliance|gap|coverage/i,
    answer: p => {
      const full = p.complianceMappings.filter(m => m.coverage === 'Full').length;
      const partial = p.complianceMappings.filter(m => m.coverage === 'Partial').length;
      const gap = p.complianceMappings.filter(m => m.coverage === 'Gap').length;
      return `Compliance coverage: ${full} Full / ${partial} Partial / ${gap} Gap across ${new Set(p.complianceMappings.map(m => m.framework)).size} frameworks.`;
    }
  },
  {
    match: /residual|top risk|critical risk|risk register/i,
    answer: p => {
      const top = p.residualRisks.filter(r => r.residualRisk === 'Critical' || r.residualRisk === 'High').slice(0, 5);
      if (!top.length) return 'No High/Critical residual risks.';
      return 'Top residual risks: ' + top.map(r => `${r.id} (${r.residualRisk}) — ${r.description.slice(0, 120)}`).join(' | ');
    }
  },
  {
    match: /what changed|diff|version/i,
    answer: p => p.diff ? p.diff.highlights.join('; ') : 'This is the first version; nothing to compare against.'
  },
  {
    match: /architecture|component|service/i,
    answer: p => `Architecture: ${p.architecture.components.length} components across ${new Set(p.architecture.components.map(c => c.layer)).size} layers. Edge: ${p.architecture.components.filter(c => c.layer === 'edge').map(c => c.name).join(', ') || '—'}.`
  },
  {
    match: /availability|recovery|rto|rpo/i,
    answer: p => `Availability tier ${p.recovery.availabilityTier}; RTO ${p.recovery.rto}, RPO ${p.recovery.rpo}. ${p.recovery.failoverApproach}`
  },
  {
    match: /privacy|pii|gdpr|linddun|dpia/i,
    answer: p => `${p.linddunFindings.length} LINDDUN findings. DPIA: ${p.dpia ? p.dpia.conclusion : 'not emitted (no GDPR/CCPA and no personal data)'}.`
  }
];

function deterministicAnswer(p: ArbPackage, question: string): string {
  for (const f of FAQ) if (f.match.test(question)) return f.answer(p);
  return `Question received; the deterministic FAQ has no answer for: "${question.slice(0, 200)}". Enable AI augmentation for free-form Q&A.`;
}

// Use the hardened SYSTEM_PRIMER from engine/ai.ts so the chat path
// gets the same anti-hallucination rules, delimiter contract, and
// "Not stated in the package." sentinel as narrative + clarifications.
const SYSTEM = hardenedSystemPrompt();

function condense(p: ArbPackage): string {
  return JSON.stringify({
    category: p.categorization.overallCategorization,
    posture: p.executiveSummary.riskPosture,
    advice: p.executiveSummary.goNoGoAdvice,
    cost: p.costEstimate,
    sspCount: p.ssp.length,
    sspFamilies: Array.from(new Set(p.ssp.map(c => c.family))),
    components: p.architecture.components.map(c => ({ id: c.id, name: c.name, layer: c.layer, svc: c.awsService })),
    threatTopFive: p.threatModel.slice(0, 5).map(t => ({ c: t.componentName, k: t.category, r: t.residualRisk })),
    compliance: p.complianceMappings.map(m => ({ f: m.framework, c: m.controlId, cov: m.coverage })),
    residuals: p.residualRisks.map(r => ({ id: r.id, severity: r.residualRisk, t: r.treatment, d: r.description })),
    fairPortfolio: p.fair?.portfolio,
    diff: p.diff?.highlights
  }, null, 0).slice(0, 25000);
}

export async function answerQuestion(p: ArbPackage, question: string): Promise<{ answer: string; source: 'ai' | 'faq' | 'python' | 'ai-rejected' }> {
  // 1) Python sidecar dispatch when PY_AI_URL is configured.
  const py = await dispatchToPython('/chat', { package_digest: pythonDigest(p), question });
  if (py) return { answer: String(py.answer ?? ''), source: 'python' };

  // 2) Deterministic fallback when AI is unavailable.
  if (!aiStatus().configured) {
    return { answer: deterministicAnswer(p, question), source: 'faq' };
  }

  // 3) Direct TS-side AI call with the full hardened guard stack.
  try {
    const wrappedQuestion = delimit(question).wrapped;
    const r = await chat({
      messages: [
        { role: 'system', content: SYSTEM },
        { role: 'user', content: `PACKAGE:\n${condense(p)}\n\nQUESTION:\n${wrappedQuestion}` }
      ],
      temperature: 0,         // Maximally deterministic
      max_tokens: 600
    });
    const trimmed = r.content.trim();
    const auth = validateAiOutput(trimmed);
    if (!auth.ok) return { answer: 'Not stated in the package.', source: 'ai-rejected' };
    const ctx = buildGroundingContext(p);
    if (!validateAiOutputGrounding(trimmed, ctx).ok) return { answer: 'Not stated in the package.', source: 'ai-rejected' };
    if (!validateAiOutputNumerics(trimmed, {
      ssp: p.ssp.length, components: p.architecture.components.length,
      threats: p.threatModel.length, residuals: p.residualRisks.length
    }).ok) return { answer: 'Not stated in the package.', source: 'ai-rejected' };
    return { answer: trimmed, source: 'ai' };
  } catch {
    return { answer: deterministicAnswer(p, question), source: 'faq' };
  }
}

// Compact digest shape that the Python sidecar expects.
function pythonDigest(p: ArbPackage): Record<string, unknown> {
  return {
    package_hash: p.packageHash,
    category: p.categorization.overallCategorization,
    posture: p.executiveSummary.riskPosture,
    advice: p.executiveSummary.goNoGoAdvice,
    ssp_count: p.ssp.length,
    ssp_families: Array.from(new Set(p.ssp.map(c => c.family))),
    component_count: p.architecture.components.length,
    cost_tier: p.costEstimate.tier,
    cost_low: p.costEstimate.monthlyLowUsd,
    cost_high: p.costEstimate.monthlyHighUsd,
    frameworks: p.complianceMappings.map(m => m.framework).filter((v, i, a) => a.indexOf(v) === i),
    top_risks: p.residualRisks.filter(r => r.residualRisk === 'High' || r.residualRisk === 'Critical').slice(0, 5).map(r => r.description)
  };
}
