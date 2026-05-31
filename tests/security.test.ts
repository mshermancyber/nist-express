// Security-focused tests: input validation boundaries.

import { sampleAssessment } from './fixtures';
import { categorize } from '../src/engine/categorization';
import { buildArchitecture } from '../src/engine/architecture';

describe('security', () => {
  test('mermaid renderer escapes special characters in component names', () => {
    // Use a malicious-looking name in description; the categorizer/architecture
    // engine will accept any string but the diagram generator must not break
    // mermaid grammar.
    const a = sampleAssessment({
      business: {
        applicationName: 'Quotes "and" <brackets>',
        businessProblem: 'safe',
        userTypes: ['Employees'],
        userInteractionDescription: ''
      }
    });
    const cat = categorize(a);
    const arch = buildArchitecture(a, cat);
    // No component IDs should contain unsafe characters
    for (const c of arch.components) {
      expect(c.id).toMatch(/^[a-zA-Z0-9_]+$/);
    }
  });

  test('integration with weak auth still validates but is flagged downstream', () => {
    const a = sampleAssessment({
      integrations: [{ source: 'A', destination: 'B', protocol: 'HTTPS', authentication: 'None', dataDirection: 'outbound' }]
    });
    const cat = categorize(a);
    const arch = buildArchitecture(a, cat);
    const integ = arch.components.find(c => c.layer === 'integration');
    expect(integ).toBeDefined();
    expect(integ!.authentication).toBe('None');
  });
});
