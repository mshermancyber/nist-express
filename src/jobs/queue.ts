// Single-process persistent job queue. JSONL on-disk record + an
// in-memory worker that picks the next queued record once per tick.
// Jobs run sequentially; this is intentional for a single-node ARB
// platform (fairness and order matter more than throughput).
//
// Job kinds:
//   package.generate  — payload: { assessmentId } — runs the engine
//   webhook.deliver   — payload: { subscriptionId, event, data }
//   ai.chat           — payload: { assessmentId, question, userId }
//   cloud.reconcile   — payload: { assessmentId } — uses stored snapshot

import fs from 'fs';
import path from 'path';
import { randomUUID } from 'crypto';
import { JobRecord } from '../types/assessment';

const DATA = path.join(__dirname, '..', '..', '.data');
const FILE = path.join(DATA, 'jobs.jsonl');
if (!fs.existsSync(DATA)) fs.mkdirSync(DATA, { recursive: true });

let cache: JobRecord[] = [];
function loadFromDisk(): void {
  if (!fs.existsSync(FILE)) { cache = []; return; }
  cache = fs.readFileSync(FILE, 'utf-8').split('\n').filter(Boolean).map(l => JSON.parse(l) as JobRecord);
}
loadFromDisk();

function persistAll(): void {
  fs.writeFileSync(FILE, cache.map(j => JSON.stringify(j)).join('\n') + (cache.length ? '\n' : ''));
}

export function enqueue(kind: JobRecord['kind'], payload: Record<string, unknown>, assessmentId?: string): JobRecord {
  const j: JobRecord = {
    id: randomUUID(),
    kind,
    assessmentId,
    payload,
    state: 'queued',
    enqueuedAt: new Date().toISOString()
  };
  cache.push(j);
  persistAll();
  return j;
}

export function listJobs(): JobRecord[] {
  return cache.slice().reverse().slice(0, 500);
}

export function getJob(id: string): JobRecord | undefined { return cache.find(j => j.id === id); }

type Handler = (j: JobRecord) => Promise<unknown>;
const handlers: Partial<Record<JobRecord['kind'], Handler>> = {};

export function register(kind: JobRecord['kind'], handler: Handler): void {
  handlers[kind] = handler;
}

let running = false;

async function tick(): Promise<void> {
  if (running) return;
  const next = cache.find(j => j.state === 'queued');
  if (!next) return;
  running = true;
  next.state = 'running';
  next.startedAt = new Date().toISOString();
  persistAll();
  try {
    const handler = handlers[next.kind];
    if (!handler) throw new Error(`no handler registered for ${next.kind}`);
    const result = await handler(next);
    next.state = 'succeeded';
    next.result = result;
  } catch (err) {
    next.state = 'failed';
    next.error = (err as Error).message;
  } finally {
    next.finishedAt = new Date().toISOString();
    persistAll();
    running = false;
    setImmediate(tick);
  }
}

export function startWorker(): void {
  // unref() so the timer never blocks graceful shutdown or Jest
  // teardown — the server lifecycle (server.listen) keeps the loop
  // alive on its own.
  setInterval(tick, 500).unref();
}
