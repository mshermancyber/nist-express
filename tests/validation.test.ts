import { validate } from '../src/engine/validation';
import { sampleAssessment } from './fixtures';

describe('validation', () => {
  test('valid sample passes', () => {
    const r = validate(sampleAssessment());
    expect(r.report.passed).toBe(true);
  });

  test('missing application name fails', () => {
    const r = validate(sampleAssessment({ business: { applicationName: '', businessProblem: '', userTypes: [], userInteractionDescription: '' } } as any));
    expect(r.report.passed).toBe(false);
    expect(r.report.issues.some(i => i.field.includes('applicationName'))).toBe(true);
  });

  test('PCI declared without PCI DSS scope yields a warning', () => {
    const r = validate(sampleAssessment({ compliance: { frameworks: ['SOC2'] } }));
    expect(r.report.issues.some(i => i.message.includes('PCI'))).toBe(true);
  });

  test('No Data Loss + 72h RTO produces a clarification question', () => {
    const r = validate(sampleAssessment({ recovery: { rto: '72 Hours', rpo: 'No Data Loss' } }));
    expect(r.clarifications.some(c => c.field === 'recovery')).toBe(true);
  });

  test('Basic Auth integration produces a warning', () => {
    const r = validate(sampleAssessment({
      integrations: [{ source: 'A', destination: 'B', protocol: 'HTTPS', authentication: 'Basic Auth', dataDirection: 'inbound' }]
    }));
    expect(r.report.issues.some(i => i.message.includes('Basic Auth'))).toBe(true);
  });
});
