// Comments, watchers, and notifications. JSON-file persistence in the
// same style as the other stores. Notifications are append-only and
// indexed by user.

import fs from 'fs';
import path from 'path';
import { randomUUID } from 'crypto';
import { Comment, CommentTarget, Notification, Watcher } from '../types/assessment';

const DATA = path.join(__dirname, '..', '..', '.data');
const COMMENTS = path.join(DATA, 'comments.jsonl');
const WATCHERS = path.join(DATA, 'watchers.json');
const NOTIFY = path.join(DATA, 'notifications.jsonl');
if (!fs.existsSync(DATA)) fs.mkdirSync(DATA, { recursive: true });

function readJsonl<T>(p: string): T[] {
  if (!fs.existsSync(p)) return [];
  return fs.readFileSync(p, 'utf-8').split('\n').filter(Boolean).map(l => JSON.parse(l) as T);
}

export function listComments(assessmentId: string, target?: { type: CommentTarget; id: string }): Comment[] {
  const all = readJsonl<Comment>(COMMENTS).filter(c => c.assessmentId === assessmentId);
  return target ? all.filter(c => c.targetType === target.type && c.targetId === target.id) : all;
}

export function getCommentById(id: string): Comment | undefined {
  return readJsonl<Comment>(COMMENTS).find(c => c.id === id);
}

export function addComment(input: Omit<Comment, 'id' | 'createdAt'>): Comment {
  const c: Comment = { id: randomUUID(), createdAt: new Date().toISOString(), ...input };
  fs.appendFileSync(COMMENTS, JSON.stringify(c) + '\n');
  return c;
}

function atomicRewriteJsonl(file: string, rows: unknown[]): void {
  const tmp = file + '.tmp.' + process.pid + '.' + Date.now();
  fs.writeFileSync(tmp, rows.map(r => JSON.stringify(r)).join('\n') + (rows.length ? '\n' : ''));
  fs.renameSync(tmp, file);
}

export function deleteComment(id: string): boolean {
  const all = readJsonl<Comment>(COMMENTS);
  const remaining = all.filter(c => c.id !== id);
  if (remaining.length === all.length) return false;
  atomicRewriteJsonl(COMMENTS, remaining);
  return true;
}

let watcherCache: Watcher[] | null = null;
function loadWatchers(): Watcher[] {
  if (watcherCache) return watcherCache;
  if (!fs.existsSync(WATCHERS)) { watcherCache = []; return watcherCache; }
  try { watcherCache = JSON.parse(fs.readFileSync(WATCHERS, 'utf-8')) as Watcher[]; } catch { watcherCache = []; }
  return watcherCache;
}
function persistWatchers(): void {
  fs.writeFileSync(WATCHERS, JSON.stringify(watcherCache ?? [], null, 2));
}

export function watch(w: Watcher): void {
  const all = loadWatchers();
  const exists = all.find(x => x.userId === w.userId && x.assessmentId === w.assessmentId && x.targetType === w.targetType && x.targetId === w.targetId);
  if (!exists) { all.push(w); persistWatchers(); }
}
export function unwatch(w: Watcher): boolean {
  const all = loadWatchers();
  const idx = all.findIndex(x => x.userId === w.userId && x.assessmentId === w.assessmentId && x.targetType === w.targetType && x.targetId === w.targetId);
  if (idx < 0) return false;
  all.splice(idx, 1);
  persistWatchers();
  return true;
}
export function watchersFor(assessmentId: string, target?: { type: CommentTarget; id: string }): Watcher[] {
  const all = loadWatchers().filter(w => w.assessmentId === assessmentId);
  if (!target) return all.filter(w => !w.targetType);
  return all.filter(w => !w.targetType || (w.targetType === target.type && w.targetId === target.id));
}
export function listWatchersForUser(userId: string): Watcher[] {
  return loadWatchers().filter(w => w.userId === userId);
}

const NOTIFY_MAX_LINES = Number(process.env.NOTIFY_MAX_LINES ?? 10_000);

// Rotate the notifications file when it crosses the threshold. We
// keep the most recent half as the new active log and move the older
// half to an archive ladder (a.0 -> a.1 -> ...). Bounded archive
// depth prevents unbounded disk growth.
// In-process mutex prevents concurrent rotations. We also snapshot
// the byte length at rotation start and re-append any bytes that
// arrived between snapshot and rename so no append is silently lost.
let rotating = false;
function maybeRotateNotify(): void {
  if (rotating) return;
  if (!fs.existsSync(NOTIFY)) return;
  rotating = true;
  try {
    const stat0 = fs.statSync(NOTIFY);
    if (stat0.size < 256 * 1024) return;
    const data = fs.readFileSync(NOTIFY, 'utf-8');
    const sizeAtRead = stat0.size;
    const lines = data.split('\n').filter(Boolean);
    if (lines.length < NOTIFY_MAX_LINES) return;
    const keepFrom = Math.floor(lines.length / 2);
    const archive = lines.slice(0, keepFrom).join('\n') + '\n';
    const active  = lines.slice(keepFrom).join('\n') + '\n';

    const max = 5;
    for (let i = max - 1; i > 0; i--) {
      const src = `${NOTIFY}.${i - 1}`;
      const dst = `${NOTIFY}.${i}`;
      if (fs.existsSync(src)) fs.renameSync(src, dst);
    }
    fs.writeFileSync(`${NOTIFY}.0`, archive);

    // Read any tail bytes appended via O_APPEND while we were
    // building the archive so they survive the rename.
    const sizeNow = fs.existsSync(NOTIFY) ? fs.statSync(NOTIFY).size : sizeAtRead;
    let tail = '';
    if (sizeNow > sizeAtRead) {
      const fd = fs.openSync(NOTIFY, 'r');
      try {
        const buf = Buffer.alloc(sizeNow - sizeAtRead);
        fs.readSync(fd, buf, 0, buf.length, sizeAtRead);
        tail = buf.toString('utf-8');
      } finally { fs.closeSync(fd); }
    }
    const tmp = `${NOTIFY}.tmp.${process.pid}.${Date.now()}`;
    fs.writeFileSync(tmp, active + (tail && !tail.endsWith('\n') ? tail + '\n' : tail));
    fs.renameSync(tmp, NOTIFY);
  } finally {
    rotating = false;
  }
}

export function notify(n: Omit<Notification, 'id' | 'ts' | 'read'>): Notification {
  const full: Notification = { id: randomUUID(), ts: new Date().toISOString(), read: false, ...n };
  fs.appendFileSync(NOTIFY, JSON.stringify(full) + '\n');
  // Rotate at most once per N notifications by sampling on UUID prefix
  // so we don't pay statSync on every call.
  if (full.id.startsWith('00')) maybeRotateNotify();
  return full;
}

export function inbox(userId: string, unreadOnly = false): Notification[] {
  const all = readJsonl<Notification>(NOTIFY).filter(n => n.userId === userId);
  const filtered = unreadOnly ? all.filter(n => !n.read) : all;
  return filtered.reverse().slice(0, 200);
}

export function markAllRead(userId: string): number {
  const all = readJsonl<Notification>(NOTIFY);
  let touched = 0;
  for (const n of all) if (n.userId === userId && !n.read) { n.read = true; touched++; }
  atomicRewriteJsonl(NOTIFY, all);
  return touched;
}
