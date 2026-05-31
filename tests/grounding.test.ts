import { buildGroundingContext, validateAiOutputGrounding, validateAiOutputNumerics } from '../src/engine/promptInjection';

const ctx = buildGroundingContext({
  ssp: [{ id: 'AC-2' }, { id: 'AC-3' }, { id: 'SC-7' }, { id: 'SI-4' }],
  architecture: { components: [{ name: 'Amazon S3' }, { name: 'AWS WAF' }] }
});

describe('reference grounding', () => {
  test('accepts answers that only cite real controls', () => {
    const r = validateAiOutputGrounding('Mitigations include AC-2 and SC-7.', ctx);
    expect(r.ok).toBe(true);
  });
  test('rejects hallucinated control AC-99', () => {
    const r = validateAiOutputGrounding('Use AC-99 to mitigate this risk.', ctx);
    expect(r.ok).toBe(false);
    expect(r.hallucinated[0]).toContain('AC-99');
  });
  test('accepts known control with an enhancement suffix', () => {
    // AC-2(7) — we strip the (7) and check the base AC-2 is in the set
    const r = validateAiOutputGrounding('Apply AC-2(7) for privileged accounts.', ctx);
    expect(r.ok).toBe(true);
  });
  test('ignores NIST 800-171 IDs (3.x.y.z) — they use dotted format and never match the dashed regex', () => {
    // Real 800-171 IDs use dots: 3.1.1, 3.5.3, etc. The grounding
    // regex deliberately only matches dashed 800-53 identifiers
    // (AC-2, SC-7), so 800-171 text is structurally invisible.
    const r = validateAiOutputGrounding('See 3.1.1 in NIST 800-171 r2.', ctx);
    expect(r.ok).toBe(true);
  });
});

describe('numeric fact validation', () => {
  const facts = { ssp: 186, components: 22, threats: 60, residuals: 18 };
  test('passes correct counts', () => {
    const r = validateAiOutputNumerics('There are 186 controls and 22 components.', facts);
    expect(r.ok).toBe(true);
  });
  test('rejects fabricated counts', () => {
    const r = validateAiOutputNumerics('There are 500 controls in this package.', facts);
    expect(r.ok).toBe(false);
    expect(r.mismatches[0]).toContain('500');
    expect(r.mismatches[0]).toContain('186');
  });
  test('catches residual-risk fabrication', () => {
    const r = validateAiOutputNumerics('I count 99 residual risks here.', facts);
    expect(r.ok).toBe(false);
    expect(r.mismatches.length).toBeGreaterThan(0);
  });
});
