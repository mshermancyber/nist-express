// Assessment storage — in-memory cache backed by JSON files under
// /data/nist-express/.data/. Suitable for a single-node deployment;
// swap for Postgres/Dynamo if multi-node persistence is required.
//
// Package history: each generated package is kept under
// .data/package-history/<assessment-id>/<version>.json so the diff
// engine can compare against the previous version. The "current"
// package lives in .data/packages/<id>.json.

import fs from 'fs';
import path from 'path';
import { Assessment, ArbPackage } from '../types/assessment';

const DATA_DIR = path.join(__dirname, '..', '..', '.data');
const ASSESS_DIR = path.join(DATA_DIR, 'assessments');
const PKG_DIR = path.join(DATA_DIR, 'packages');
const HISTORY_DIR = path.join(DATA_DIR, 'package-history');

function ensureDirs() {
  for (const d of [DATA_DIR, ASSESS_DIR, PKG_DIR, HISTORY_DIR]) {
    if (!fs.existsSync(d)) fs.mkdirSync(d, { recursive: true });
  }
}
ensureDirs();

const assessmentCache = new Map<string, Assessment>();
const packageCache = new Map<string, ArbPackage>();

function loadFromDisk(): void {
  for (const f of fs.readdirSync(ASSESS_DIR)) {
    if (!f.endsWith('.json')) continue;
    try {
      const data = JSON.parse(fs.readFileSync(path.join(ASSESS_DIR, f), 'utf-8')) as Assessment;
      assessmentCache.set(data.id, data);
    } catch { /* ignore corrupt file */ }
  }
  for (const f of fs.readdirSync(PKG_DIR)) {
    if (!f.endsWith('.json')) continue;
    try {
      const data = JSON.parse(fs.readFileSync(path.join(PKG_DIR, f), 'utf-8')) as ArbPackage;
      packageCache.set(data.assessmentId, data);
    } catch { /* ignore */ }
  }
}
loadFromDisk();

export function listAssessments(filter?: { userId?: string; team?: string; isAdmin?: boolean }): Assessment[] {
  let xs = Array.from(assessmentCache.values());
  if (filter && !filter.isAdmin) {
    xs = xs.filter(a => {
      // Visibility rule:
      //   - owner sees their own
      //   - any user on the same team sees the assessment
      //   - admins see everything (already filtered above)
      if (filter.userId && a.ownerId === filter.userId) return true;
      if (filter.team && a.team && a.team === filter.team) return true;
      return !a.ownerId && !a.team;   // legacy untaged rows visible to everyone
    });
  }
  return xs.sort((a, b) => b.updatedAt.localeCompare(a.updatedAt));
}

// Per-assessment authorization helper consumed by every route.
export function canAccessAssessment(a: Assessment, session: { userId: string; roles: string[]; team?: string } | undefined): boolean {
  if (!session) return false;
  if (session.roles.includes('admin')) return true;
  if (a.ownerId && a.ownerId === session.userId) return true;
  if (a.team && session.team && a.team === session.team) return true;
  if (!a.ownerId && !a.team) return true;   // legacy untaged rows
  return false;
}

export function getAssessment(id: string): Assessment | undefined {
  return assessmentCache.get(id);
}

export function saveAssessment(a: Assessment): Assessment {
  assessmentCache.set(a.id, a);
  fs.writeFileSync(path.join(ASSESS_DIR, `${a.id}.json`), JSON.stringify(a, null, 2));
  return a;
}

export function deleteAssessment(id: string): boolean {
  const had = assessmentCache.delete(id);
  packageCache.delete(id);
  const ap = path.join(ASSESS_DIR, `${id}.json`);
  const pp = path.join(PKG_DIR, `${id}.json`);
  if (fs.existsSync(ap)) fs.unlinkSync(ap);
  if (fs.existsSync(pp)) fs.unlinkSync(pp);
  // Clean history
  const hd = path.join(HISTORY_DIR, id);
  if (fs.existsSync(hd)) fs.rmSync(hd, { recursive: true, force: true });
  return had;
}

export function savePackage(pkg: ArbPackage): ArbPackage {
  packageCache.set(pkg.assessmentId, pkg);
  fs.writeFileSync(path.join(PKG_DIR, `${pkg.assessmentId}.json`), JSON.stringify(pkg, null, 2));
  // Versioned history file
  const hd = path.join(HISTORY_DIR, pkg.assessmentId);
  if (!fs.existsSync(hd)) fs.mkdirSync(hd, { recursive: true });
  fs.writeFileSync(path.join(hd, `v${String(pkg.packageVersion).padStart(4, '0')}.json`), JSON.stringify(pkg, null, 2));
  return pkg;
}

export function getPackage(assessmentId: string): ArbPackage | undefined {
  return packageCache.get(assessmentId);
}

export function listPackages(): ArbPackage[] {
  return Array.from(packageCache.values()).sort((a, b) => b.generatedAt.localeCompare(a.generatedAt));
}

export function listPackageVersions(assessmentId: string): { version: number; generatedAt: string; packageHash: string }[] {
  const hd = path.join(HISTORY_DIR, assessmentId);
  if (!fs.existsSync(hd)) return [];
  return fs.readdirSync(hd).filter(f => f.endsWith('.json')).map(f => {
    try {
      const p = JSON.parse(fs.readFileSync(path.join(hd, f), 'utf-8')) as ArbPackage;
      return { version: p.packageVersion, generatedAt: p.generatedAt, packageHash: p.packageHash };
    } catch {
      return { version: 0, generatedAt: '', packageHash: '' };
    }
  }).filter(x => x.version > 0).sort((a, b) => b.version - a.version);
}

export function getPackageVersion(assessmentId: string, version: number): ArbPackage | undefined {
  const hd = path.join(HISTORY_DIR, assessmentId);
  const f = path.join(hd, `v${String(version).padStart(4, '0')}.json`);
  if (!fs.existsSync(f)) return undefined;
  try {
    return JSON.parse(fs.readFileSync(f, 'utf-8')) as ArbPackage;
  } catch {
    return undefined;
  }
}
