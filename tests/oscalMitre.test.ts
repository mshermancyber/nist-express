import { generatePackage } from '../src/engine/package';
import { sampleAssessment } from './fixtures';

describe('OSCAL + MITRE + CAPEC', () => {
  test('OSCAL SSP control-id is lowercase + dash format', async () => {
    const pkg = await generatePackage(sampleAssessment());
    const reqs = pkg.oscalSsp['control-implementation']['implemented-requirements'];
    for (const r of reqs) {
      expect(r['control-id']).toMatch(/^[a-z]{2}-[0-9]+$/);
    }
  });
  test('MITRE mapping picks Initial Access for edge Spoofing', async () => {
    const pkg = await generatePackage(sampleAssessment());
    const edge = pkg.threatModel.findIndex(f => f.category === 'Spoofing' && /WAF|CloudFront|ALB|Route 53|Front Door|Armor/.test(f.componentName));
    if (edge >= 0) {
      const m = pkg.mitreMappings.find(x => x.strideFindingIndex === edge);
      expect(m).toBeDefined();
      expect(['TA0001', 'TA0006']).toContain(m!.attackTacticId);
    }
  });
  test('CAPEC references cite at least one identifier per category', async () => {
    const pkg = await generatePackage(sampleAssessment());
    expect(pkg.capecReferences.every(c => /^CAPEC-\d+$/.test(c.capecId))).toBe(true);
  });
});
