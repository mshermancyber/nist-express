// Ordered migrations applied on startup. Each migration has a numeric
// id, runs at most once, and is recorded in .data/migrations.json. A
// migration is a sync function that touches files under .data; this is
// suitable for small, infrequent schema evolutions.

import fs from 'fs';
import path from 'path';
import { logger } from '../obs/logger';

interface Applied { id: number; appliedAt: string; description: string }
interface Migration { id: number; description: string; run(): void | Promise<void> }

const DATA = path.join(__dirname, '..', '..', '.data');
const STATE_FILE = path.join(DATA, 'migrations.json');

function loadState(): Applied[] {
  if (!fs.existsSync(STATE_FILE)) return [];
  try { return JSON.parse(fs.readFileSync(STATE_FILE, 'utf-8')) as Applied[]; } catch { return []; }
}
function saveState(state: Applied[]): void { fs.writeFileSync(STATE_FILE, JSON.stringify(state, null, 2)); }

const MIGRATIONS: Migration[] = [
  {
    id: 1,
    description: 'Ensure .data/{assessments,packages,package-history,iac,sbom,cloud,backups} subdirs exist',
    run() {
      for (const d of ['assessments', 'packages', 'package-history', 'iac', 'sbom', 'cloud']) {
        const p = path.join(DATA, d);
        if (!fs.existsSync(p)) fs.mkdirSync(p, { recursive: true });
      }
    }
  }
];

export async function runMigrations(): Promise<void> {
  if (!fs.existsSync(DATA)) fs.mkdirSync(DATA, { recursive: true });
  const applied = loadState();
  const seen = new Set(applied.map(a => a.id));
  for (const m of MIGRATIONS.sort((a, b) => a.id - b.id)) {
    if (seen.has(m.id)) continue;
    logger.info('migration.run', { id: m.id, description: m.description });
    await m.run();
    applied.push({ id: m.id, appliedAt: new Date().toISOString(), description: m.description });
    saveState(applied);
  }
}
