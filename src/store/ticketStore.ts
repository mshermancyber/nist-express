import fs from 'fs';
import path from 'path';
import { ExternalTicket } from '../types/assessment';

const FILE = path.join(__dirname, '..', '..', '.data', 'tickets.json');

let cache: ExternalTicket[] | null = null;
function load(): ExternalTicket[] {
  if (cache) return cache;
  if (!fs.existsSync(FILE)) { cache = []; return cache; }
  try { cache = JSON.parse(fs.readFileSync(FILE, 'utf-8')) as ExternalTicket[]; } catch { cache = []; }
  return cache;
}
function persist(): void { fs.writeFileSync(FILE, JSON.stringify(cache ?? [], null, 2)); }

export function listTickets(): ExternalTicket[] { return load(); }
export function getTicket(riskId: string): ExternalTicket | undefined { return load().find(t => t.riskId === riskId); }
export function saveTicket(t: ExternalTicket): ExternalTicket {
  const all = load(); const i = all.findIndex(x => x.riskId === t.riskId);
  if (i >= 0) all[i] = t; else all.push(t); persist(); return t;
}
