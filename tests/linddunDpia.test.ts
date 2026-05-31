import { generatePackage } from '../src/engine/package';
import { sampleAssessment } from './fixtures';

describe('LINDDUN + DPIA', () => {
  test('LINDDUN is empty when no personal data is declared', async () => {
    const a = sampleAssessment({
      data: { dataCategories: ['Operational Data'], confidentialToCompany: false, sensitiveDataTags: [] }
    });
    const pkg = await generatePackage(a);
    expect(pkg.linddunFindings.length).toBe(0);
  });
  test('LINDDUN emits findings when PII is declared', async () => {
    const pkg = await generatePackage(sampleAssessment());
    const cats = new Set(pkg.linddunFindings.map(l => l.category));
    expect(cats.has('Disclosure of information')).toBe(true);
    expect(cats.has('Unawareness')).toBe(true);
  });
  test('DPIA is emitted when GDPR is in scope', async () => {
    const a = sampleAssessment({ compliance: { frameworks: ['GDPR', 'SOC2'] } });
    const pkg = await generatePackage(a);
    expect(pkg.dpia).not.toBeNull();
    expect(pkg.dpia!.lawfulBases.length).toBeGreaterThan(0);
  });
  test('DPIA is null with no privacy mandate and no personal data', async () => {
    const a = sampleAssessment({
      data: { dataCategories: ['Public Information'], confidentialToCompany: false, sensitiveDataTags: [] },
      compliance: { frameworks: ['Internal Policy Only'] }
    });
    const pkg = await generatePackage(a);
    expect(pkg.dpia).toBeNull();
  });
});
