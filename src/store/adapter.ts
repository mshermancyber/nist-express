// Storage adapter interface — chosen at startup based on env. The
// existing JSON-file behaviour is wrapped by FsAdapter (default).
// Setting DATABASE_URL selects PgAdapter, which persists the same
// shapes into Postgres. Both adapters expose the same minimal CRUD
// surface; routes never see the underlying medium.
//
// We deliberately keep the surface narrow (key/value blob storage)
// because the workload is read-heavy and the per-record shapes are
// already typed. Promoting to first-class columns is a later concern.

import { Assessment, ArbPackage } from '../types/assessment';

export interface StoreAdapter {
  kind(): 'fs' | 'pg';

  // Assessments
  listAssessments(): Promise<Assessment[]>;
  getAssessment(id: string): Promise<Assessment | undefined>;
  saveAssessment(a: Assessment): Promise<Assessment>;
  deleteAssessment(id: string): Promise<boolean>;

  // Packages + history
  savePackage(p: ArbPackage): Promise<ArbPackage>;
  getPackage(assessmentId: string): Promise<ArbPackage | undefined>;
  listPackages(): Promise<ArbPackage[]>;
  listPackageVersions(assessmentId: string): Promise<{ version: number; generatedAt: string; packageHash: string }[]>;
  getPackageVersion(assessmentId: string, version: number): Promise<ArbPackage | undefined>;
}

let active: StoreAdapter | null = null;

export async function getAdapter(): Promise<StoreAdapter> {
  if (active) return active;
  if (process.env.DATABASE_URL) {
    const { PgAdapter } = await import('./pgAdapter');
    active = await PgAdapter.create(process.env.DATABASE_URL);
  } else {
    const { FsAdapter } = await import('./fsAdapter');
    active = new FsAdapter();
  }
  return active;
}

export function adapterKind(): string {
  return active?.kind() ?? 'fs';
}
