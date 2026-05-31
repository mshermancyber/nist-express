import { generatePackage } from '../src/engine/package';
import { sampleAssessment } from './fixtures';

describe('expanded compliance frameworks', () => {
  test('NIST CSF 2.0 emits mappings when selected', async () => {
    const pkg = await generatePackage(sampleAssessment({ compliance: { frameworks: ['NIST CSF 2.0'] } }));
    expect(pkg.complianceMappings.some(m => m.framework === 'NIST CSF 2.0')).toBe(true);
  });
  test('EU AI Act + AI RMF emit mappings together', async () => {
    const pkg = await generatePackage(sampleAssessment({ compliance: { frameworks: ['EU AI Act', 'NIST AI RMF'] } }));
    const frameworks = new Set(pkg.complianceMappings.map(m => m.framework));
    expect(frameworks.has('EU AI Act')).toBe(true);
    expect(frameworks.has('NIST AI RMF')).toBe(true);
  });
  test('DORA + FFIEC + HITRUST + IRS Pub 1075 all wired', async () => {
    const pkg = await generatePackage(sampleAssessment({ compliance: { frameworks: ['DORA', 'FFIEC', 'HITRUST CSF', 'IRS Pub 1075'] } }));
    for (const f of ['DORA', 'FFIEC', 'HITRUST CSF', 'IRS Pub 1075']) {
      expect(pkg.complianceMappings.some(m => m.framework === f)).toBe(true);
    }
  });
});
