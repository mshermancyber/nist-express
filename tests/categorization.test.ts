import { categorize, baselineFromCategory } from '../src/engine/categorization';
import { sampleAssessment } from './fixtures';

describe('categorization (FIPS 199 + NIST 800-60)', () => {
  test('PCI + PII + regulatory worst case yields HIGH confidentiality', () => {
    const cat = categorize(sampleAssessment());
    expect(cat.confidentialityImpact).toBe('High');
    expect(cat.overallCategorization).toBe('High');
    expect(cat.informationTypes.length).toBeGreaterThan(0);
    expect(cat.rationale.join(' ')).toMatch(/high-water/i);
  });

  test('Pure operational data with no sensitivity stays Low/Moderate', () => {
    const a = sampleAssessment({
      data: { dataCategories: ['Operational Data'], confidentialToCompany: false, sensitiveDataTags: [] },
      impact: { confidentialityWorstCase: 'minor', integrityWorstCase: 'minor', availabilityWorstCase: 'minor' },
      compliance: { frameworks: [] },
      recovery: { rto: '72 Hours', rpo: '24 Hours' }
    });
    const cat = categorize(a);
    expect(['Low', 'Moderate']).toContain(cat.overallCategorization);
  });

  test('15-minute RTO forces availability impact to High', () => {
    const a = sampleAssessment({
      recovery: { rto: '15 Minutes', rpo: '15 Minutes' },
      impact: { confidentialityWorstCase: 'minor', integrityWorstCase: 'minor', availabilityWorstCase: 'minor' },
      compliance: { frameworks: [] }
    });
    const cat = categorize(a);
    expect(cat.availabilityImpact).toBe('High');
  });

  test('baselineFromCategory aggregates lower baselines', () => {
    expect(baselineFromCategory('High')).toEqual(['Low', 'Moderate', 'High']);
    expect(baselineFromCategory('Moderate')).toEqual(['Low', 'Moderate']);
    expect(baselineFromCategory('Low')).toEqual(['Low']);
  });
});
