import { reconcileCloud, detectCloudFormat } from '../src/engine/cloudReconcile';
import { buildArchitecture } from '../src/engine/architecture';
import { categorize } from '../src/engine/categorization';
import { sampleAssessment } from './fixtures';

describe('Cloud snapshot reconciliation', () => {
  test('detects AWS Config snapshot', () => {
    const snap = JSON.stringify({ resourceIdentifiers: [{ resourceType: 'AWS::S3::Bucket', resourceId: 'b' }] });
    expect(detectCloudFormat(snap)).toBe('aws-config');
  });
  test('detects Security Hub findings', () => {
    const snap = JSON.stringify({ Findings: [{ Id: 'x', Title: 't', Severity: { Label: 'HIGH' }, Resources: [{ Id: 'arn:aws:s3:::b' }] }] });
    expect(detectCloudFormat(snap)).toBe('aws-security-hub');
  });
  test('matches components from a Config snapshot', () => {
    const a = sampleAssessment();
    const arch = buildArchitecture(a, categorize(a));
    const snap = JSON.stringify({
      resourceIdentifiers: [
        { resourceType: 'AWS::S3::Bucket', resourceId: 'b1' },
        { resourceType: 'AWS::CloudTrail::Trail', resourceId: 'tr' },
        { resourceType: 'AWS::WAFv2::WebACL', resourceId: 'w' }
      ]
    });
    const report = reconcileCloud(snap, arch);
    expect(report.matched.length).toBeGreaterThan(0);
  });
});
