import { TEMPLATES, getTemplate } from '../src/data/templates';
import { generatePackage } from '../src/engine/package';
import { sampleAssessment } from './fixtures';
import { answerQuestion } from '../src/engine/chat';

describe('templates + chat fallback', () => {
  test('all 5 templates exist with non-empty bodies', () => {
    expect(TEMPLATES.length).toBe(5);
    for (const t of TEMPLATES) {
      expect(t.body.business.applicationName.length).toBeGreaterThan(0);
      expect(t.body.compliance.frameworks.length).toBeGreaterThan(0);
    }
    expect(getTemplate('ai-enabled')).toBeDefined();
  });
  test('chat falls back to deterministic FAQ when AI unavailable', async () => {
    delete process.env.AI_API_KEY;
    delete process.env.AI_BASE_URL;
    const pkg = await generatePackage(sampleAssessment());
    const r = await answerQuestion(pkg, 'which controls are in the SSP?');
    expect(r.source).toBe('faq');
    expect(r.answer.toLowerCase()).toContain('controls');
  });
});
