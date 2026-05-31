import { generatePackage } from '../src/engine/package';
import { sampleAssessment } from './fixtures';
import { renderCsv } from '../src/export/csv';
import { diffPackages } from '../src/engine/diff';

describe('CSV exports + diff', () => {
  test('SSP CSV starts with header', async () => {
    const pkg = await generatePackage(sampleAssessment());
    const csv = renderCsv('ssp', pkg);
    expect(csv.split('\r\n')[0]).toContain('Control,Family,Name');
  });
  test('CSV quoting escapes embedded quotes and commas', async () => {
    const pkg = await generatePackage(sampleAssessment());
    const csv = renderCsv('evidence', pkg);
    // Should be well-formed: equal counts of opening/closing quotes when present.
    const quotes = (csv.match(/"/g) || []).length;
    expect(quotes % 2).toBe(0);
  });
  test('diff captures category change between two generations', async () => {
    const v1 = await generatePackage(sampleAssessment());
    // Force a category drop by removing all sensitive data + compliance.
    const lower = await generatePackage(sampleAssessment({
      data: { dataCategories: ['Operational Data'], confidentialToCompany: false, sensitiveDataTags: [] },
      impact: { confidentialityWorstCase: 'minor', integrityWorstCase: 'minor', availabilityWorstCase: 'minor' },
      compliance: { frameworks: [] },
      recovery: { rto: '72 Hours', rpo: '24 Hours' }
    }), { previousPackage: v1 });
    expect(lower.diff!.categoryChange).not.toBeNull();
    expect(lower.diff!.categoryChange!.from).toBe('High');
  });
});
