// Webhook dispatcher. Subscriptions select event kinds; the dispatcher
// formats the payload per adapter (generic / slack / teams) and signs
// the body with an HMAC SHA-256 using the subscription's secret.
//
// SMTP / email is intentionally out-of-scope here; we expose the same
// adapter shape so an SMTP adapter could be added without changing
// callers.

import crypto from 'crypto';
import { WebhookSubscription } from '../types/assessment';
import { getWebhook, listWebhooks } from '../store/webhookStore';
import { appendAudit } from '../store/auditStore';
import { safeFetch } from './safeFetch';

export type WebhookEvent = WebhookSubscription['events'][number];

function sign(secret: string, body: string): string {
  return 'sha256=' + crypto.createHmac('sha256', secret).update(body).digest('hex');
}

function adaptPayload(event: WebhookEvent, data: Record<string, unknown>, adapter: WebhookSubscription['adapter']): unknown {
  if (adapter === 'slack') {
    return {
      text: `*${event}* — ${JSON.stringify(data).slice(0, 800)}`
    };
  }
  if (adapter === 'teams') {
    return {
      '@type': 'MessageCard',
      '@context': 'https://schema.org/extensions',
      summary: event,
      themeColor: event === 'residual.critical' ? 'ef4444' : '38bdf8',
      title: event,
      text: '```json\n' + JSON.stringify(data, null, 2).slice(0, 1500) + '\n```'
    };
  }
  // generic
  return { event, data, ts: new Date().toISOString() };
}

export async function deliverWebhook(sub: WebhookSubscription, event: WebhookEvent, data: Record<string, unknown>): Promise<void> {
  if (!sub.enabled || !sub.events.includes(event)) return;
  const payload = adaptPayload(event, data, sub.adapter);
  const body = JSON.stringify(payload);
  const sig = sign(sub.secret, body);
  try {
    const r = await safeFetch(sub.url, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-nistexpress-event': event, 'x-nistexpress-signature': sig },
      body,
      timeoutMs: 8_000
    });
    appendAudit({ actor: 'system', action: 'webhook.deliver', target: sub.id, details: { event, status: r.status } });
  } catch (err) {
    appendAudit({ actor: 'system', action: 'webhook.deliver.fail', target: sub.id, details: { event, error: (err as Error).message } });
  }
}

export async function fanOut(event: WebhookEvent, data: Record<string, unknown>): Promise<void> {
  await Promise.all(listWebhooks().map(s => deliverWebhook(s, event, data)));
}

export function getWebhookById(id: string): WebhookSubscription | undefined { return getWebhook(id); }
