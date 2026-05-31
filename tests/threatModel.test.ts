import { categorize } from '../src/engine/categorization';
import { buildArchitecture } from '../src/engine/architecture';
import { buildThreatModel, summarizeRiskCounts } from '../src/engine/threatModel';
import { sampleAssessment } from './fixtures';

describe('STRIDE threat model', () => {
  test('every component yields at least one STRIDE finding', () => {
    const a = sampleAssessment();
    const cat = categorize(a);
    const arch = buildArchitecture(a, cat);
    const tm = buildThreatModel(a, arch, cat);
    const componentsWithFindings = new Set(tm.map(t => t.componentId));
    // Edge/app/data/identity/integration/admin/logging components should all appear
    const expected = arch.components.filter(c => c.layer !== 'monitoring' && c.layer !== 'backup');
    for (const c of expected) {
      expect(componentsWithFindings.has(c.id)).toBe(true);
    }
  });

  test('residual risk is never higher than inherent risk', () => {
    const a = sampleAssessment();
    const cat = categorize(a);
    const arch = buildArchitecture(a, cat);
    const tm = buildThreatModel(a, arch, cat);
    const order = { Low: 0, Medium: 1, High: 2, Critical: 3 };
    for (const f of tm) {
      expect(order[f.residualRisk]).toBeLessThanOrEqual(order[f.inherentRisk]);
    }
  });

  test('summarizeRiskCounts returns all categories', () => {
    const a = sampleAssessment();
    const cat = categorize(a);
    const arch = buildArchitecture(a, cat);
    const counts = summarizeRiskCounts(buildThreatModel(a, arch, cat));
    expect(counts.inherent).toHaveProperty('Low');
    expect(counts.residual).toHaveProperty('Critical');
  });
});
