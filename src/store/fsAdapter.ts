// FS adapter — wraps the existing JSON-file store so the sync
// functions in assessmentStore become async at the adapter layer
// without changing the on-disk layout.

import { Assessment, ArbPackage } from '../types/assessment';
import { StoreAdapter } from './adapter';
import {
  listAssessments as _list,
  getAssessment as _get,
  saveAssessment as _save,
  deleteAssessment as _del,
  savePackage as _savePkg,
  getPackage as _getPkg,
  listPackages as _listPkgs,
  listPackageVersions as _listVers,
  getPackageVersion as _getVer
} from './assessmentStore';

export class FsAdapter implements StoreAdapter {
  kind(): 'fs' { return 'fs'; }
  async listAssessments() { return _list(); }
  async getAssessment(id: string) { return _get(id); }
  async saveAssessment(a: Assessment) { return _save(a); }
  async deleteAssessment(id: string) { return _del(id); }
  async savePackage(p: ArbPackage) { return _savePkg(p); }
  async getPackage(id: string) { return _getPkg(id); }
  async listPackages() { return _listPkgs(); }
  async listPackageVersions(id: string) { return _listVers(id); }
  async getPackageVersion(id: string, v: number) { return _getVer(id, v); }
}
