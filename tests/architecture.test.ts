import { categorize } from '../src/engine/categorization';
import { buildArchitecture } from '../src/engine/architecture';
import { renderArchitectureMermaid, renderDataFlowMermaid, renderSecurityOverlayMermaid } from '../src/engine/diagrams';
import { sampleAssessment } from './fixtures';

describe('architecture engine', () => {
  test('produces components from every required layer', () => {
    const a = sampleAssessment();
    const arch = buildArchitecture(a, categorize(a));
    const layers = new Set(arch.components.map(c => c.layer));
    for (const l of ['edge', 'identity', 'app', 'data', 'logging', 'monitoring', 'backup', 'admin']) {
      expect(layers.has(l as any)).toBe(true);
    }
  });

  test('every flow has a sender and receiver that exists in components', () => {
    const a = sampleAssessment();
    const arch = buildArchitecture(a, categorize(a));
    const ids = new Set(arch.components.map(c => c.id));
    for (const f of arch.flows) {
      expect(ids.has(f.fromComponentId)).toBe(true);
      expect(ids.has(f.toComponentId)).toBe(true);
    }
  });

  test('confidentiality requirement forces MFA / Okta inclusion', () => {
    const a = sampleAssessment();
    const arch = buildArchitecture(a, categorize(a));
    const okta = arch.components.find(c => c.name.toLowerCase().includes('okta'));
    expect(okta).toBeDefined();
    expect(okta!.rationale.toLowerCase()).toMatch(/mfa|saml|confidential/);
  });

  test('mermaid renderers produce non-empty diagrams', () => {
    const a = sampleAssessment();
    const arch = buildArchitecture(a, categorize(a));
    expect(renderArchitectureMermaid(arch)).toMatch(/flowchart LR/);
    expect(renderSecurityOverlayMermaid(arch)).toMatch(/TRUST BOUNDARY/);
    expect(renderDataFlowMermaid(arch)).toMatch(/flowchart LR/);
  });
});
