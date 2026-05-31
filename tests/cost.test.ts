import { generatePackage } from '../src/engine/package';
import { sampleAssessment } from './fixtures';

describe('cost estimate', () => {
  test('larger user population produces higher band', async () => {
    const small = await generatePackage(sampleAssessment({ population: { userCount: 'Under 100', expectedGrowth: '' } }));
    const big   = await generatePackage(sampleAssessment({ population: { userCount: '10000+', expectedGrowth: '' } }));
    expect(big.costEstimate.monthlyHighUsd).toBeGreaterThan(small.costEstimate.monthlyHighUsd);
  });
  test('multi-region inflates cost vs. an otherwise-comparable single-region system', async () => {
    // Use a moderate-availability sample so the recovery engine does
    // not automatically force multi-region from the categorisation.
    const base = sampleAssessment({
      recovery: { rto: '4 Hours', rpo: '1 Hour' },
      impact: {
        confidentialityWorstCase: 'competitive disadvantage',
        integrityWorstCase: 'competitive disadvantage',
        availabilityWorstCase: 'competitive disadvantage'
      },
      compliance: { frameworks: ['SOC2'] },
      data: { dataCategories: ['Customer Information'], confidentialToCompany: false, sensitiveDataTags: [] }
    });
    const single = await generatePackage({ ...base, advanced: { multiRegion: false } });
    const multi  = await generatePackage({ ...base, advanced: { multiRegion: true } });
    expect(multi.costEstimate.monthlyHighUsd).toBeGreaterThan(single.costEstimate.monthlyHighUsd);
  });
});
