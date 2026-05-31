import fs from 'fs';
import path from 'path';
import { WebhookSubscription } from '../types/assessment';
import { encryptString, decryptString } from '../auth/crypto';

const FILE = path.join(__dirname, '..', '..', '.data', 'webhooks.json');

let cache: WebhookSubscription[] | null = null;
function load(): WebhookSubscription[] {
  if (cache) return cache;
  if (!fs.existsSync(FILE)) { cache = []; return cache; }
  try {
    const raw = JSON.parse(fs.readFileSync(FILE, 'utf-8')) as WebhookSubscription[];
    cache = raw.map(w => ({ ...w, secret: w.secret ? decryptString(w.secret) : w.secret }));
  } catch { cache = []; }
  return cache;
}
function persist(): void {
  const out = (cache ?? []).map(w => ({ ...w, secret: w.secret ? encryptString(w.secret) : w.secret }));
  fs.writeFileSync(FILE, JSON.stringify(out, null, 2));
}

export function listWebhooks(): WebhookSubscription[] { return load(); }
export function getWebhook(id: string): WebhookSubscription | undefined { return load().find(w => w.id === id); }
export function saveWebhook(w: WebhookSubscription): WebhookSubscription {
  const all = load(); const i = all.findIndex(x => x.id === w.id);
  if (i >= 0) all[i] = w; else all.push(w); persist(); return w;
}
export function deleteWebhook(id: string): boolean {
  const all = load(); const i = all.findIndex(x => x.id === id);
  if (i < 0) return false; all.splice(i, 1); persist(); return true;
}
