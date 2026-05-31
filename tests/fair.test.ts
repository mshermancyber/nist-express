import { generatePackage } from '../src/engine/package';
import { sampleAssessment } from './fixtures';

describe('FAIR Monte Carlo', () => {
  test('produces ALE bands consistent with percentile ordering', async () => {
    const pkg = await generatePackage(sampleAssessment());
    expect(pkg.fair.iterations).toBeGreaterThan(1000);
    for (const r of pkg.fair.perRisk) {
      expect(r.aleP10).toBeLessThanOrEqual(r.aleP50);
      expect(r.aleP50).toBeLessThanOrEqual(r.aleP90);
      expect(r.aleP90).toBeGreaterThan(0);
    }
  });
  test('portfolio rollup sums per-risk percentiles', async () => {
    const pkg = await generatePackage(sampleAssessment());
    const p50sum = pkg.fair.perRisk.reduce((s, r) => s + r.aleP50, 0);
    expect(pkg.fair.portfolio.aleP50).toBe(p50sum);
  });
});
