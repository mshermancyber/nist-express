import { categorize } from '../src/engine/categorization';
import { buildArchitecture } from '../src/engine/architecture';
import { buildSsp } from '../src/engine/ssp';
import { buildComplianceMappings } from '../src/engine/compliance';
import { sampleAssessment } from './fixtures';

describe('SSP and compliance mapping', () => {
  test('HIGH category selects controls from every required family', () => {
    const a = sampleAssessment();
    const cat = categorize(a);
    expect(cat.overallCategorization).toBe('High');
    const ssp = buildSsp(a, cat, buildArchitecture(a, cat));
    const families = new Set(ssp.map(c => c.family));
    for (const f of ['AC', 'AT', 'AU', 'CA', 'CM', 'CP', 'IA', 'IR', 'MA', 'MP', 'PE', 'PL', 'PM', 'PS', 'PT', 'RA', 'SA', 'SC', 'SI', 'SR']) {
      expect(families.has(f)).toBe(true);
    }
  });

  test('every SSP control has implementation statement, evidence, rationale', () => {
    const a = sampleAssessment();
    const cat = categorize(a);
    const ssp = buildSsp(a, cat, buildArchitecture(a, cat));
    for (const c of ssp) {
      expect(c.implementationStatement.length).toBeGreaterThan(20);
      expect(c.evidence.length).toBeGreaterThan(0);
      expect(c.rationale.length).toBeGreaterThan(5);
    }
  });

  test('excluded controls are removed; custom controls are added', () => {
    const a = sampleAssessment({
      advanced: { excludeControlIds: ['SI-7'], customControlIds: ['MA-2'] }
    } as any);
    const cat = categorize(a);
    const ssp = buildSsp(a, cat, buildArchitecture(a, cat));
    expect(ssp.find(c => c.id === 'SI-7')).toBeUndefined();
    expect(ssp.find(c => c.id === 'MA-2')).toBeDefined();
  });

  test('PCI DSS in compliance scope produces full or partial coverage', () => {
    const a = sampleAssessment();
    const cat = categorize(a);
    const ssp = buildSsp(a, cat, buildArchitecture(a, cat));
    const mappings = buildComplianceMappings(a, ssp);
    const pci = mappings.filter(m => m.framework === 'PCI DSS');
    expect(pci.length).toBeGreaterThan(0);
    expect(pci.every(m => m.coverage !== 'Gap')).toBe(true);
  });
});
