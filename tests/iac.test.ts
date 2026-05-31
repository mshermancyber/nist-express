import { reconcileIac, detectFormat, parseIac } from '../src/engine/iac';
import { buildArchitecture } from '../src/engine/architecture';
import { categorize } from '../src/engine/categorization';
import { sampleAssessment } from './fixtures';

describe('IaC reconciliation', () => {
  test('detects Terraform plan format', () => {
    const tf = JSON.stringify({
      planned_values: { root_module: { resources: [{ type: 'aws_s3_bucket', name: 'logs', values: { server_side_encryption_configuration: {} } }] } }
    });
    expect(detectFormat(tf)).toBe('terraform-plan');
  });

  test('detects CloudFormation JSON', () => {
    const cfn = JSON.stringify({
      AWSTemplateFormatVersion: '2010-09-09',
      Resources: { Bucket: { Type: 'AWS::S3::Bucket', Properties: { BucketEncryption: {} } } }
    });
    expect(['cloudformation', 'cdk-synth']).toContain(detectFormat(cfn));
  });

  test('CloudFormation YAML parses', () => {
    const yaml = `AWSTemplateFormatVersion: '2010-09-09'
Resources:
  Logs:
    Type: AWS::S3::Bucket
    Properties: { BucketEncryption: {} }
  DB:
    Type: AWS::RDS::DBInstance
    Properties: { StorageEncrypted: true }`;
    expect(detectFormat(yaml)).toBe('cloudformation');
    const { observed } = parseIac(yaml);
    expect(observed.map(o => o.type)).toEqual(expect.arrayContaining(['AWS::S3::Bucket', 'AWS::RDS::DBInstance']));
  });

  test('reconciles a partial CFN template against the expected architecture', () => {
    const a = sampleAssessment();
    const arch = buildArchitecture(a, categorize(a));
    const cfn = JSON.stringify({
      AWSTemplateFormatVersion: '2010-09-09',
      Resources: {
        Bucket:  { Type: 'AWS::S3::Bucket', Properties: { BucketEncryption: {} } },
        DB:      { Type: 'AWS::RDS::DBCluster', Properties: { StorageEncrypted: true } },
        Trail:   { Type: 'AWS::CloudTrail::Trail' },
        WAF:     { Type: 'AWS::WAFv2::WebACL' },
        Random:  { Type: 'AWS::SQS::Queue' }  // unexpected — not in described arch
      }
    });
    const report = reconcileIac(cfn, arch);
    expect(report.format).toBe('cloudformation');
    expect(report.matched.length).toBeGreaterThan(0);
    expect(report.unexpected.find(u => u.observedType === 'AWS::SQS::Queue')).toBeDefined();
    expect(report.missing.length).toBeGreaterThan(0);   // many described components not in this stub
  });
});
