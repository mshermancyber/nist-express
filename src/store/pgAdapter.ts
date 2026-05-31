// Postgres adapter. Stores assessments and packages as JSONB blobs
// keyed by id. Versioned package history is in a separate table. On
// first connection we ensure the schema exists (idempotent DDL).

import { Pool } from 'pg';
import { Assessment, ArbPackage } from '../types/assessment';
import { StoreAdapter } from './adapter';

export class PgAdapter implements StoreAdapter {
  private constructor(private pool: Pool) {}

  static async create(databaseUrl: string): Promise<PgAdapter> {
    const pool = new Pool({ connectionString: databaseUrl, max: 8 });
    const a = new PgAdapter(pool);
    await a.bootstrap();
    return a;
  }

  kind(): 'pg' { return 'pg'; }

  private async bootstrap(): Promise<void> {
    await this.pool.query(`
      CREATE TABLE IF NOT EXISTS arb_assessments (
        id TEXT PRIMARY KEY,
        updated_at TIMESTAMPTZ NOT NULL,
        body JSONB NOT NULL
      );
      CREATE TABLE IF NOT EXISTS arb_packages (
        assessment_id TEXT NOT NULL,
        version INT NOT NULL,
        generated_at TIMESTAMPTZ NOT NULL,
        package_hash TEXT NOT NULL,
        body JSONB NOT NULL,
        PRIMARY KEY (assessment_id, version)
      );
      CREATE INDEX IF NOT EXISTS arb_packages_latest ON arb_packages (assessment_id, version DESC);
    `);
  }

  async listAssessments() {
    const r = await this.pool.query<{ body: Assessment }>('SELECT body FROM arb_assessments ORDER BY updated_at DESC');
    return r.rows.map(x => x.body);
  }
  async getAssessment(id: string) {
    const r = await this.pool.query<{ body: Assessment }>('SELECT body FROM arb_assessments WHERE id = $1', [id]);
    return r.rows[0]?.body;
  }
  async saveAssessment(a: Assessment) {
    await this.pool.query(
      'INSERT INTO arb_assessments (id, updated_at, body) VALUES ($1, $2, $3) ON CONFLICT (id) DO UPDATE SET updated_at = EXCLUDED.updated_at, body = EXCLUDED.body',
      [a.id, a.updatedAt, a]
    );
    return a;
  }
  async deleteAssessment(id: string) {
    const r = await this.pool.query('DELETE FROM arb_assessments WHERE id = $1', [id]);
    await this.pool.query('DELETE FROM arb_packages WHERE assessment_id = $1', [id]);
    return (r.rowCount ?? 0) > 0;
  }
  async savePackage(p: ArbPackage) {
    await this.pool.query(
      'INSERT INTO arb_packages (assessment_id, version, generated_at, package_hash, body) VALUES ($1, $2, $3, $4, $5) ON CONFLICT (assessment_id, version) DO UPDATE SET body = EXCLUDED.body',
      [p.assessmentId, p.packageVersion, p.generatedAt, p.packageHash, p]
    );
    return p;
  }
  async getPackage(id: string) {
    const r = await this.pool.query<{ body: ArbPackage }>(
      'SELECT body FROM arb_packages WHERE assessment_id = $1 ORDER BY version DESC LIMIT 1', [id]);
    return r.rows[0]?.body;
  }
  async listPackages() {
    const r = await this.pool.query<{ body: ArbPackage }>(
      'SELECT body FROM arb_packages WHERE (assessment_id, version) IN (SELECT assessment_id, MAX(version) FROM arb_packages GROUP BY assessment_id)');
    return r.rows.map(x => x.body);
  }
  async listPackageVersions(id: string) {
    const r = await this.pool.query<{ version: number; generated_at: string; package_hash: string }>(
      'SELECT version, generated_at, package_hash FROM arb_packages WHERE assessment_id = $1 ORDER BY version DESC', [id]);
    return r.rows.map(x => ({ version: x.version, generatedAt: x.generated_at, packageHash: x.package_hash }));
  }
  async getPackageVersion(id: string, version: number) {
    const r = await this.pool.query<{ body: ArbPackage }>(
      'SELECT body FROM arb_packages WHERE assessment_id = $1 AND version = $2', [id, version]);
    return r.rows[0]?.body;
  }
}
