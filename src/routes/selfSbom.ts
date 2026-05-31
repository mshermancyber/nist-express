// The platform emits its own CycloneDX SBOM by reading the local
// package-lock.json. This is the irony-free version of "do we ship
// an SBOM for the security tool" — the answer is yes, and it's a
// real CycloneDX 1.5 document.

import { Router } from 'express';
import fs from 'fs';
import path from 'path';
import { randomUUID } from 'crypto';

export const selfSbomRouter = Router();

interface PkgLock {
  name: string;
  version: string;
  packages?: Record<string, { version?: string; license?: string; resolved?: string; integrity?: string; dev?: boolean }>;
}

function readLock(): PkgLock | null {
  const p = path.join(__dirname, '..', '..', 'package-lock.json');
  if (!fs.existsSync(p)) return null;
  try { return JSON.parse(fs.readFileSync(p, 'utf-8')) as PkgLock; } catch { return null; }
}

selfSbomRouter.get('/', (_req, res) => {
  const lock = readLock();
  if (!lock) { res.status(503).json({ error: 'package-lock.json not present' }); return; }
  const components: { type: string; name: string; version: string; purl?: string; licenses?: { license: { id: string } }[]; scope?: string }[] = [];
  for (const [k, v] of Object.entries(lock.packages ?? {})) {
    if (k === '' || !v?.version) continue;
    // k looks like "node_modules/express" or "node_modules/foo/node_modules/bar"
    const m = /node_modules\/(@[^/]+\/[^/]+|[^/]+)$/.exec(k);
    const name = m?.[1];
    if (!name) continue;
    const purl = `pkg:npm/${name}@${v.version}`;
    components.push({
      type: 'library',
      name,
      version: v.version,
      purl,
      scope: v.dev ? 'optional' : 'required',
      ...(v.license ? { licenses: [{ license: { id: v.license } }] } : {})
    });
  }
  res.json({
    bomFormat: 'CycloneDX',
    specVersion: '1.5',
    serialNumber: 'urn:uuid:' + randomUUID(),
    version: 1,
    metadata: {
      timestamp: new Date().toISOString(),
      component: { type: 'application', name: lock.name, version: lock.version }
    },
    components
  });
});
