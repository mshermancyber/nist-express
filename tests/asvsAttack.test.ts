import { generatePackage } from '../src/engine/package';
import { sampleAssessment } from './fixtures';
import { selfAttestAsvs } from '../src/engine/asvs';

describe('ASVS self-attestation + attack trees + kill chain', () => {
  test('ASVS report includes items across all key categories', () => {
    const r = selfAttestAsvs();
    expect(r.items.length).toBeGreaterThan(15);
    const cats = new Set(r.items.map(i => i.category));
    expect(cats.has('Authentication')).toBe(true);
    expect(cats.has('Session Management')).toBe(true);
    expect(cats.has('Access Control')).toBe(true);
    expect(r.totals.pass + r.totals.partial + r.totals.gap).toBe(r.items.length);
  });
  test('Attack trees are emitted for HIGH/CRITICAL residual risks', async () => {
    const pkg = await generatePackage(sampleAssessment());
    const highs = pkg.residualRisks.filter(r => r.residualRisk === 'High' || r.residualRisk === 'Critical');
    expect(pkg.attackTrees.length).toBe(highs.length);
    if (highs.length) {
      expect(pkg.attackTrees[0]!.root.children.length).toBeGreaterThan(0);
    }
  });
  test('Kill chain mappings cover every STRIDE finding', async () => {
    const pkg = await generatePackage(sampleAssessment());
    expect(pkg.killChainMappings.length).toBe(pkg.threatModel.length);
  });
});
