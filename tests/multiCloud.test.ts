import { buildArchitecture } from '../src/engine/architecture';
import { categorize } from '../src/engine/categorization';
import { sampleAssessment } from './fixtures';

describe('multi-cloud architecture renderers', () => {
  test('Azure profile substitutes Azure service names', () => {
    const a = sampleAssessment({ hosting: { model: 'Azure' } });
    const arch = buildArchitecture(a, categorize(a));
    const kms = arch.components.find(c => c.id === 'aws_kms');
    expect(kms?.awsService).toBe('Azure Key Vault');
    expect(kms?.name).toMatch(/Key Vault/);
    const sso = arch.components.find(c => c.id === 'aws_idc');
    expect(sso?.awsService).toMatch(/Entra ID/);
  });
  test('GCP profile substitutes GCP service names', () => {
    const a = sampleAssessment({ hosting: { model: 'GCP' } });
    const arch = buildArchitecture(a, categorize(a));
    const db = arch.components.find(c => c.id === 'data_rds');
    expect(db?.awsService).toMatch(/Cloud SQL/);
  });
  test('AWS profile remains the default unchanged', () => {
    const a = sampleAssessment(); // hosting AWS in fixture
    const arch = buildArchitecture(a, categorize(a));
    const db = arch.components.find(c => c.id === 'data_rds');
    expect(db?.awsService).toMatch(/Aurora/);
  });
});
