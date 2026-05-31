import { encryptString, decryptString } from '../src/auth/crypto';
import { buildFedrampPackage } from '../src/engine/fedrampPackage';
import { generatePackage } from '../src/engine/package';
import { sampleAssessment } from './fixtures';

describe('field encryption', () => {
  test('round-trips a value', () => {
    const ct = encryptString('hello-secret');
    expect(ct.startsWith('enc:v1:')).toBe(true);
    expect(decryptString(ct)).toBe('hello-secret');
  });
  test('plaintext passes through unchanged', () => {
    expect(decryptString('legacy-plaintext')).toBe('legacy-plaintext');
  });
  test('two encryptions of the same value differ (random IV)', () => {
    const a = encryptString('same');
    const b = encryptString('same');
    expect(a).not.toBe(b);
  });
});

describe('FedRAMP package', () => {
  test('emits baseline + supporting docs when FedRAMP in scope', async () => {
    const pkg = await generatePackage(sampleAssessment({ compliance: { frameworks: ['FedRAMP', 'NIST 800-53'] } }));
    expect(pkg.fedramp).not.toBeNull();
    const fr = pkg.fedramp!;
    expect(['LOW', 'MODERATE', 'HIGH', 'LI-SaaS']).toContain(fr.baseline);
    expect(fr.baselineControlCount).toBeGreaterThan(50);
    expect(fr.parameterValues.length).toBeGreaterThan(0);
    expect(fr.authorizationBoundary.inScopeComponents.length).toBeGreaterThan(0);
    expect(fr.iscp.systemName).toBeTruthy();
    expect(fr.irp.declarationCriteria).toBeTruthy();
    expect(fr.rulesOfBehavior.length).toBeGreaterThan(5);
    expect(fr.conmon.metrics.length).toBeGreaterThan(0);
    expect(fr.eAuthWorksheet.assuranceLevel).toMatch(/IAL[1-3]/);
  });
  test('POA&M includes critical residuals', async () => {
    const pkg = await generatePackage(sampleAssessment({ compliance: { frameworks: ['FedRAMP'] } }));
    expect(pkg.fedramp?.poam).toBeDefined();
    for (const it of pkg.fedramp!.poam) {
      expect(it.poamId).toMatch(/^V-\d{4}$/);
      expect(['Open', 'Ongoing', 'Risk Accepted', 'Completed']).toContain(it.status);
      expect(it.scheduledCompletion).toMatch(/^\d{4}-\d{2}-\d{2}$/);
    }
  });
  test('null when FedRAMP not in scope', async () => {
    const pkg = await generatePackage(sampleAssessment({ compliance: { frameworks: ['SOC2'] } }));
    expect(pkg.fedramp).toBeNull();
  });
  test('NIST 800-171 emits 110 requirement mappings', async () => {
    const pkg = await generatePackage(sampleAssessment({ compliance: { frameworks: ['NIST 800-171'] } }));
    const mapped = pkg.complianceMappings.filter(m => m.framework === 'NIST 800-171');
    expect(mapped.length).toBe(110);
  });
});
