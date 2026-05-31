import { analyzeSbom, detectSbomFormat } from '../src/engine/sbom';
import { buildArchitecture } from '../src/engine/architecture';
import { categorize } from '../src/engine/categorization';
import { sampleAssessment } from './fixtures';

describe('SBOM ingestion', () => {
  test('detects CycloneDX', () => {
    const cdx = JSON.stringify({ bomFormat: 'CycloneDX', specVersion: '1.5', components: [{ name: 'log4j-core', version: '2.14.1', purl: 'pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1' }], vulnerabilities: [{ id: 'CVE-2021-44228', ratings: [{ score: 10, severity: 'critical' }], affects: [{ ref: 'log4j-core' }], description: 'Log4Shell' }] });
    expect(detectSbomFormat(cdx)).toBe('cyclonedx');
  });
  test('intersects with CISA KEV', () => {
    const a = sampleAssessment();
    const arch = buildArchitecture(a, categorize(a));
    const cdx = JSON.stringify({ bomFormat: 'CycloneDX', components: [{ name: 'log4j-core', version: '2.14.1' }], vulnerabilities: [{ id: 'CVE-2021-44228', ratings: [{ score: 10 }], affects: [{ ref: 'log4j-core' }] }] });
    const analysis = analyzeSbom(cdx, arch);
    expect(analysis.format).toBe('cyclonedx');
    expect(analysis.kevHits.length).toBe(1);
    expect(analysis.kevHits[0]!.id).toBe('CVE-2021-44228');
  });
  test('SPDX parses package list', () => {
    const spdx = JSON.stringify({ spdxVersion: 'SPDX-2.3', name: 'sample', packages: [{ name: 'lodash', versionInfo: '4.17.21' }] });
    const a = sampleAssessment();
    const arch = buildArchitecture(a, categorize(a));
    const analysis = analyzeSbom(spdx, arch);
    expect(analysis.format).toBe('spdx');
    expect(analysis.components.length).toBe(1);
  });
});
