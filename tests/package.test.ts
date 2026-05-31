import { generatePackage } from '../src/engine/package';
import { sampleAssessment } from './fixtures';

describe('full ARB package generation', () => {
  test('produces every required section', async () => {
    const pkg = await generatePackage(sampleAssessment());
    expect(pkg.categorization).toBeDefined();
    expect(pkg.dataClassification).toBeDefined();
    expect(pkg.architecture.components.length).toBeGreaterThan(5);
    expect(pkg.architectureDiagramMermaid).toMatch(/flowchart/);
    expect(pkg.securityOverlayDiagramMermaid).toMatch(/TRUST BOUNDARY/);
    expect(pkg.dataFlowDiagramMermaid).toMatch(/flowchart/);
    expect(pkg.threatModel.length).toBeGreaterThan(10);
    expect(pkg.flowThreatModel.length).toBeGreaterThan(5);
    expect(pkg.operationalThreatModel.length).toBeGreaterThan(3);
    expect(pkg.ssp.length).toBeGreaterThan(15);
    expect(pkg.auditableEvents.length).toBeGreaterThan(10);
    expect(pkg.recovery.availabilityTier).toMatch(/Tier/);
    expect(pkg.residualRisks).toBeDefined();
    expect(pkg.assumptions.length).toBeGreaterThan(0);
    expect(pkg.complianceMappings.length).toBeGreaterThan(0);
    expect(pkg.wellArchitected.length).toBe(3);
    expect(pkg.evidenceRequests.length).toBe(pkg.ssp.length);
    expect(pkg.executiveSummary.oneLiner.length).toBeGreaterThan(20);
    expect(pkg.validationReport.passed).toBe(true);
    // New (M15-M22) sections
    expect(pkg.packageVersion).toBe(1);
    expect(pkg.packageHash).toMatch(/^[a-f0-9]{64}$/);
    expect(pkg.mitreMappings.length).toBe(pkg.threatModel.length);
    expect(pkg.capecReferences.length).toBeGreaterThan(0);
    expect(pkg.costEstimate.tier).toMatch(/^(XS|S|M|L|XL)$/);
    expect(pkg.costEstimate.monthlyHighUsd).toBeGreaterThan(pkg.costEstimate.monthlyLowUsd);
    expect(pkg.oscalSsp.metadata['oscal-version']).toBe('1.1.2');
    expect(pkg.oscalSsp['control-implementation']['implemented-requirements'].length).toBe(pkg.ssp.length);
    expect(pkg.linddunFindings.length).toBeGreaterThan(0); // PII+PCI present in sample
    expect(pkg.dpia).not.toBeNull();                       // PII / PCI in sample triggers DPIA
    expect(pkg.diff).toBeNull();                           // first version
  });

  test('second generation includes a diff against the first', async () => {
    const a = sampleAssessment();
    const v1 = await generatePackage(a);
    const v2 = await generatePackage({ ...a, recovery: { rto: '24 Hours', rpo: '24 Hours' } }, { previousPackage: v1 });
    expect(v2.packageVersion).toBe(2);
    expect(v2.diff).not.toBeNull();
    expect(v2.diff!.recoveryTierChange).not.toBeNull();
  });
});
